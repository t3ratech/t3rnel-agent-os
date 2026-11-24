//! Image generation across providers, with fallback.
//!
//! Previously this spoke only to OpenAI's `/v1/images/generations`. When that
//! single provider was unavailable — an unset key, a billing limit, or a
//! retired model id — image generation failed outright and callers degraded to
//! script-drawn SVG placeholders instead of real artwork (ISSUE-002). Generation
//! now walks a provider chain and only fails when every provider has failed.

use base64::Engine;
use t3rnel_types::media::{GeneratedImage, ImageGenRequest, ImageGenResult};
use tracing::{info, warn};

/// Cloudflare Workers AI text-to-image models, best first.
///
/// `binary` marks models that return raw image bytes rather than
/// `{"result":{"image":"<base64>"}}` — Workers AI is inconsistent about this.
const CLOUDFLARE_IMAGE_MODELS: &[(&str, bool)] = &[
    ("@cf/black-forest-labs/flux-1-schnell", false),
    ("@cf/bytedance/stable-diffusion-xl-lightning", true),
    ("@cf/stabilityai/stable-diffusion-xl-base-1.0", true),
    ("@cf/leonardo/lucid-origin", true),
    ("@cf/leonardo/phoenix-1.0", true),
    ("@cf/lykon/dreamshaper-8-lcm", true),
];

/// Gemini image-generation models on the AI Studio free tier, best first.
/// These are the "flash image" models returned under `categories.image_generation`
/// in `config/category-templates.toml`; both accept `responseModalities=["IMAGE"]`.
const GEMINI_IMAGE_MODELS: &[&str] = &["gemini-3.1-flash-image", "gemini-2.5-flash-image"];

/// Hugging Face Inference Providers, best first. The deprecated
/// `hf-inference` provider path is gone — each provider now serves an
/// OpenAI-compatible `/{provider}/v1/images/generations` endpoint on the HF
/// router that returns `{data: [{b64_json}]}`. Verified live: `nscale` serves
/// `black-forest-labs/FLUX.1-schnell` on the free tier.
const HUGGINGFACE_IMAGE_PROVIDERS: &[&str] = &["nscale", "fal-ai", "wavespeed"];

/// Models to try per provider — provider availability varies, so every
/// (provider, model) pair is attempted until one returns an image.
const HUGGINGFACE_IMAGE_MODELS: &[&str] = &[
    "black-forest-labs/FLUX.1-schnell",
    "stabilityai/stable-diffusion-xl-base-1.0",
];

/// Max accepted image payload (10 MB), applied to every provider.
const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;

/// Generate images, trying each configured provider in turn.
///
/// Order: Gemini AI Studio free-tier image models (if `GEMINI_API_KEY` or
/// `GOOGLE_API_KEY` is set), then the Hugging Face free Inference Providers
/// tier (if `HUGGING_FACE_API_KEY` or `HF_TOKEN` is set), then Cloudflare
/// Workers AI (if `CLOUDFLARE_API_KEY` and `CLOUDFLARE_ACCOUNT_ID` are set),
/// then OpenAI (if `OPENAI_API_KEY` is set). Free providers run first so paid
/// and quota-metered providers are only consumed when every free option has
/// failed. Returns the first success; on total failure returns every
/// provider's error so the operator can see whether it was auth, billing, or
/// a bad model id.
///
/// `base_url_override` (sourced from `MediaConfig.image_gen_base_url`) lets
/// callers redirect the OpenAI leg to a local OpenAI-compatible image service
/// (e.g. Lemonade/Flux, LM Studio). When `None`, the hardcoded
/// `https://api.openai.com/v1/images/generations` endpoint is used. Closes #1051.
pub async fn generate_image(
    request: &ImageGenRequest,
    base_url_override: Option<&str>,
) -> Result<ImageGenResult, String> {
    request.validate()?;

    let mut errors: Vec<String> = Vec::new();

    match generate_image_gemini(request).await {
        Ok(result) => return Ok(result),
        Err(e) => {
            warn!(error = %e, "Gemini image generation failed — trying next provider");
            errors.push(format!("gemini: {e}"));
        }
    }

    match generate_image_huggingface(request).await {
        Ok(result) => return Ok(result),
        Err(e) => {
            warn!(error = %e, "Hugging Face image generation failed — trying next provider");
            errors.push(format!("huggingface: {e}"));
        }
    }

    match generate_image_cloudflare(request).await {
        Ok(result) => return Ok(result),
        Err(e) => {
            warn!(error = %e, "Cloudflare image generation failed — trying next provider");
            errors.push(format!("cloudflare: {e}"));
        }
    }

    if std::env::var("OPENAI_API_KEY").is_ok() {
        match generate_image_openai(request, base_url_override).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                warn!(error = %e, "OpenAI image generation failed");
                errors.push(format!("openai: {e}"));
            }
        }
    } else {
        errors.push("openai: OPENAI_API_KEY not set".to_string());
    }

    Err(format!(
        "All image generation providers failed. Callers must NOT substitute a \
         script-drawn placeholder — surface this error instead. Details: {}",
        errors.join(" | ")
    ))
}

/// Extract the first image from a Gemini `generateContent` response.
///
/// Image models return `candidates[].content.parts[].inlineData.data` (REST
/// JSON spells the field `inlineData`; accept `inline_data` too so a wire
/// change does not silently produce "no image" errors). Returns the first
/// part whose payload is a non-empty base64 image.
fn parse_gemini_image_b64(body: &serde_json::Value) -> Result<String, String> {
    let mut saw_part = false;
    for candidate in body
        .get("candidates")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default()
    {
        for part in candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default()
        {
            saw_part = true;
            for key in ["inlineData", "inline_data"] {
                if let Some(data) = part
                    .get(key)
                    .and_then(|i| i.get("data"))
                    .and_then(|d| d.as_str())
                {
                    if data.is_empty() {
                        return Err("inlineData.data was empty".to_string());
                    }
                    return Ok(data.to_string());
                }
            }
        }
    }
    // Surface a real reason when Gemini answered with text or a block instead
    // of an image — "no image" alone sends operators chasing the wrong layer.
    let block_reason = body
        .get("promptFeedback")
        .and_then(|f| f.get("blockReason"))
        .and_then(|r| r.as_str())
        .map(|r| format!("prompt blocked: {r}"));
    let finish = body
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str())
        .map(|r| format!("finishReason={r}"));
    let mut detail = if saw_part {
        "no part contained image data".to_string()
    } else {
        "response had no content parts".to_string()
    };
    if let Some(reason) = block_reason.or(finish) {
        detail.push_str(&format!(" ({reason})"));
    }
    Err(detail)
}

/// Generate images via the Gemini `generateContent` API (AI Studio free tier).
///
/// Requires `GEMINI_API_KEY` or `GOOGLE_API_KEY`.
async fn generate_image_gemini(request: &ImageGenRequest) -> Result<ImageGenResult, String> {
    let api_key = std::env::var("GEMINI_API_KEY")
        .or_else(|_| std::env::var("GOOGLE_API_KEY"))
        .map_err(|_| "GEMINI_API_KEY/GOOGLE_API_KEY not set".to_string())?;

    let client = reqwest::Client::new();
    let mut errors = Vec::new();

    for model in GEMINI_IMAGE_MODELS {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        );
        let response = match client
            .post(&url)
            .header("x-goog-api-key", api_key.trim())
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "contents": [{"parts": [{"text": request.prompt}]}],
                "generationConfig": {"responseModalities": ["IMAGE", "TEXT"]}
            }))
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{model}: request failed: {e}"));
                continue;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            errors.push(format!(
                "{model}: HTTP {status}: {}",
                crate::str_utils::safe_truncate_str(&body, 200)
            ));
            continue;
        }

        let body: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("{model}: bad JSON: {e}"));
                continue;
            }
        };

        match parse_gemini_image_b64(&body) {
            Ok(b64) if b64.len() <= MAX_IMAGE_BYTES => {
                info!(provider = "gemini", model, "Generated image");
                return Ok(ImageGenResult {
                    images: vec![GeneratedImage {
                        data_base64: b64,
                        url: None,
                    }],
                    model: (*model).to_string(),
                    revised_prompt: None,
                });
            }
            Ok(_) => errors.push(format!("{model}: image exceeds {MAX_IMAGE_BYTES} bytes")),
            Err(e) => errors.push(format!("{model}: {e}")),
        }
    }

    Err(errors.join("; "))
}

/// Generate images via the Hugging Face free Inference Providers tier.
///
/// Requires `HUGGING_FACE_API_KEY` or `HF_TOKEN`. Each provider exposes an
/// OpenAI-compatible `POST /{provider}/v1/images/generations` on the HF router;
/// the response is `{data: [{b64_json}]}` — the same envelope OpenAI returns.
async fn generate_image_huggingface(request: &ImageGenRequest) -> Result<ImageGenResult, String> {
    let api_key = std::env::var("HUGGING_FACE_API_KEY")
        .or_else(|_| std::env::var("HF_TOKEN"))
        .map_err(|_| "HUGGING_FACE_API_KEY/HF_TOKEN not set".to_string())?;

    let client = reqwest::Client::new();
    let mut errors = Vec::new();

    for provider in HUGGINGFACE_IMAGE_PROVIDERS {
        let url = format!("https://router.huggingface.co/{provider}/v1/images/generations");
        for model in HUGGINGFACE_IMAGE_MODELS {
            let response = match client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key.trim()))
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({
                    "model": model,
                    "prompt": request.prompt,
                    "response_format": "b64_json",
                }))
                .timeout(std::time::Duration::from_secs(180))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    errors.push(format!("{provider}/{model}: request failed: {e}"));
                    continue;
                }
            };

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                errors.push(format!(
                    "{provider}/{model}: HTTP {status}: {}",
                    crate::str_utils::safe_truncate_str(&body, 200)
                ));
                continue;
            }

            let body: serde_json::Value = match response.json().await {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("{provider}/{model}: bad JSON: {e}"));
                    continue;
                }
            };
            let b64 = body
                .get("data")
                .and_then(|d| d.as_array())
                .and_then(|d| d.first())
                .and_then(|d| d.get("b64_json"))
                .and_then(|d| d.as_str())
                .unwrap_or("");
            if b64.is_empty() {
                errors.push(format!(
                    "{provider}/{model}: no image in response: {}",
                    crate::str_utils::safe_truncate_str(&body.to_string(), 200)
                ));
                continue;
            }
            if b64.len() > MAX_IMAGE_BYTES * 4 / 3 {
                errors.push(format!(
                    "{provider}/{model}: image exceeds {MAX_IMAGE_BYTES} bytes"
                ));
                continue;
            }

            info!(
                provider = "huggingface",
                hf_provider = provider,
                model,
                "Generated image"
            );
            return Ok(ImageGenResult {
                images: vec![GeneratedImage {
                    data_base64: b64.to_string(),
                    url: None,
                }],
                model: (*model).to_string(),
                revised_prompt: None,
            });
        }
    }

    Err(errors.join("; "))
}

/// Generate images via Cloudflare Workers AI.
async fn generate_image_cloudflare(request: &ImageGenRequest) -> Result<ImageGenResult, String> {
    let api_key = std::env::var("CLOUDFLARE_API_KEY")
        .map_err(|_| "CLOUDFLARE_API_KEY not set".to_string())?;
    let account_id = std::env::var(t3rnel_types::model_catalog::CLOUDFLARE_ACCOUNT_ID_ENV)
        .map_err(|_| "CLOUDFLARE_ACCOUNT_ID not set".to_string())?;

    let client = reqwest::Client::new();
    let mut errors = Vec::new();

    for (model, returns_binary) in CLOUDFLARE_IMAGE_MODELS {
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/ai/run/{}",
            account_id.trim(),
            model
        );
        let response = match client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "prompt": request.prompt }))
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{model}: request failed: {e}"));
                continue;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            errors.push(format!(
                "{model}: HTTP {status}: {}",
                crate::str_utils::safe_truncate_str(&body, 200)
            ));
            continue;
        }

        let b64 = if *returns_binary {
            let bytes = match response.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("{model}: read failed: {e}"));
                    continue;
                }
            };
            if bytes.len() > MAX_IMAGE_BYTES {
                errors.push(format!("{model}: image exceeds {MAX_IMAGE_BYTES} bytes"));
                continue;
            }
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        } else {
            let body: serde_json::Value = match response.json().await {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("{model}: bad JSON: {e}"));
                    continue;
                }
            };
            match body
                .get("result")
                .and_then(|r| r.get("image"))
                .and_then(|v| v.as_str())
            {
                Some(s) if s.len() <= MAX_IMAGE_BYTES => s.to_string(),
                Some(_) => {
                    errors.push(format!("{model}: image exceeds {MAX_IMAGE_BYTES} bytes"));
                    continue;
                }
                None => {
                    errors.push(format!("{model}: response had no result.image"));
                    continue;
                }
            }
        };

        info!(provider = "cloudflare", model, "Generated image");
        return Ok(ImageGenResult {
            images: vec![GeneratedImage {
                data_base64: b64,
                url: None,
            }],
            model: (*model).to_string(),
            revised_prompt: None,
        });
    }

    Err(errors.join("; "))
}

/// Generate images via OpenAI's image generation API.
///
/// Requires OPENAI_API_KEY to be set.
async fn generate_image_openai(
    request: &ImageGenRequest,
    base_url_override: Option<&str>,
) -> Result<ImageGenResult, String> {
    // Check for API key (presence only — never read the actual value into logs)
    let api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| "OPENAI_API_KEY not set. Image generation requires an OpenAI API key.")?;

    let model_str = request.model.to_string();

    let mut body = serde_json::json!({
        "model": model_str,
        "prompt": request.prompt,
        "n": request.count,
        "size": request.size,
        "response_format": "b64_json",
    });

    // DALL-E 3 specific fields
    if request.model == t3rnel_types::media::ImageGenModel::DallE3 {
        body["quality"] = serde_json::json!(request.quality);
    }

    // `image_gen_base_url` (config.media.image_gen_base_url) overrides the
    // hardcoded provider URL when set, allowing the same OpenAI-compat JSON
    // wire format to be sent to a local image generation service
    // (Lemonade/Flux, LM Studio, etc.) instead of the cloud provider. The
    // Authorization header is still built from `OPENAI_API_KEY`; local
    // services typically accept any non-empty bearer token. Closes #1051.
    let url = base_url_override
        .map(|base| format!("{}/v1/images/generations", base.trim_end_matches('/')))
        .unwrap_or_else(|| "https://api.openai.com/v1/images/generations".to_string());

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .map_err(|e| format!("Image generation API request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        // SECURITY: don't include full error body which might contain key info
        let truncated = crate::str_utils::safe_truncate_str(&error_body, 500);
        return Err(format!(
            "Image generation failed (HTTP {}): {}",
            status, truncated
        ));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse image generation response: {e}"))?;

    let mut images = Vec::new();
    let mut revised_prompt = None;

    if let Some(data) = result.get("data").and_then(|d| d.as_array()) {
        for item in data {
            let b64 = item
                .get("b64_json")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let url = item
                .get("url")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // SECURITY: bound image data size (max 10MB base64)
            if b64.len() > 10 * 1024 * 1024 {
                warn!("Generated image data exceeds 10MB, skipping");
                continue;
            }

            images.push(GeneratedImage {
                data_base64: b64,
                url,
            });

            // Capture revised prompt from first image
            if revised_prompt.is_none() {
                revised_prompt = item
                    .get("revised_prompt")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
    }

    if images.is_empty() {
        return Err("No images returned by the API".into());
    }

    Ok(ImageGenResult {
        images,
        model: model_str,
        revised_prompt,
    })
}

/// Save generated images to workspace output directory.
pub fn save_images_to_workspace(
    result: &ImageGenResult,
    workspace: &std::path::Path,
) -> Result<Vec<String>, String> {
    let output_dir = workspace.join("output");
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create output dir: {e}"))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let mut paths = Vec::new();

    for (i, image) in result.images.iter().enumerate() {
        let filename = if result.images.len() == 1 {
            format!("image_{timestamp}.png")
        } else {
            format!("image_{timestamp}_{i}.png")
        };

        let path = output_dir.join(&filename);

        // Decode base64 and save
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&image.data_base64)
            .map_err(|e| format!("Failed to decode base64 image: {e}"))?;

        // SECURITY: verify decoded size
        if decoded.len() > 10 * 1024 * 1024 {
            return Err("Decoded image exceeds 10MB limit".into());
        }

        std::fs::write(&path, &decoded)
            .map_err(|e| format!("Failed to write image to {}: {e}", path.display()))?;

        paths.push(path.display().to_string());
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use t3rnel_types::media::ImageGenModel;

    #[test]
    fn test_validate_valid_request() {
        let req = ImageGenRequest {
            prompt: "A beautiful sunset".to_string(),
            model: ImageGenModel::DallE3,
            size: "1024x1024".to_string(),
            quality: "hd".to_string(),
            count: 1,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_prompt() {
        let req = ImageGenRequest {
            prompt: String::new(),
            model: ImageGenModel::DallE3,
            size: "1024x1024".to_string(),
            quality: "standard".to_string(),
            count: 1,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_validate_dalle2_sizes() {
        for size in &["256x256", "512x512", "1024x1024"] {
            let req = ImageGenRequest {
                prompt: "test".to_string(),
                model: ImageGenModel::DallE2,
                size: size.to_string(),
                quality: "standard".to_string(),
                count: 1,
            };
            assert!(req.validate().is_ok(), "Failed for size {size}");
        }
    }

    #[test]
    fn test_validate_gpt_image_sizes() {
        for size in &["1024x1024", "1536x1024", "1024x1536"] {
            let req = ImageGenRequest {
                prompt: "test".to_string(),
                model: ImageGenModel::GptImage1,
                size: size.to_string(),
                quality: "auto".to_string(),
                count: 2,
            };
            assert!(req.validate().is_ok(), "Failed for size {size}");
        }
    }

    /// Closes #1051: when `image_gen_base_url` is set, the URL building
    /// logic must use the override (with `/v1/images/generations` appended)
    /// and strip any trailing slash from the user-supplied base. When unset,
    /// the hardcoded provider URL is used.
    #[test]
    fn test_image_gen_base_url_override_logic() {
        // Helper mirroring the URL construction in `generate_image`.
        fn build(base: Option<&str>) -> String {
            base.map(|b| format!("{}/v1/images/generations", b.trim_end_matches('/')))
                .unwrap_or_else(|| "https://api.openai.com/v1/images/generations".to_string())
        }

        // Default: hardcoded URL preserved (backward compatibility).
        assert_eq!(build(None), "https://api.openai.com/v1/images/generations");

        // Override applied.
        assert_eq!(
            build(Some("http://127.0.0.1:7000")),
            "http://127.0.0.1:7000/v1/images/generations"
        );

        // Trailing slash on the user-supplied base is stripped.
        assert_eq!(
            build(Some("http://127.0.0.1:7000/")),
            "http://127.0.0.1:7000/v1/images/generations"
        );
        assert_eq!(
            build(Some("https://images.example.com/")),
            "https://images.example.com/v1/images/generations"
        );
    }

    #[test]
    fn test_save_images_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        let result = ImageGenResult {
            images: vec![GeneratedImage {
                // Minimal valid base64 (8 zero bytes)
                data_base64: base64::engine::general_purpose::STANDARD.encode([0u8; 8]),
                url: None,
            }],
            model: "dall-e-3".to_string(),
            revised_prompt: None,
        };
        let paths = save_images_to_workspace(&result, workspace).unwrap();
        assert_eq!(paths.len(), 1);
        assert!(std::path::Path::new(&paths[0]).exists());
    }

    #[test]
    fn test_parse_gemini_image_b64_extracts_image() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "here is the image"},
                        {"inlineData": {"mimeType": "image/png", "data": "aGVsbG8="}}
                    ]
                }
            }]
        });
        assert_eq!(parse_gemini_image_b64(&body).unwrap(), "aGVsbG8=");
    }

    #[test]
    fn test_parse_gemini_image_b64_accepts_snake_case() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"inline_data": {"data": "aGVsbG8="}}]}
            }]
        });
        assert_eq!(parse_gemini_image_b64(&body).unwrap(), "aGVsbG8=");
    }

    #[test]
    fn test_parse_gemini_image_b64_text_only_response() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"text": "I cannot draw that"}]},
                "finishReason": "STOP"
            }]
        });
        let err = parse_gemini_image_b64(&body).unwrap_err();
        assert!(err.contains("no part contained image data"), "got: {err}");
        assert!(err.contains("finishReason=STOP"), "got: {err}");
    }

    #[test]
    fn test_parse_gemini_image_b64_blocked_prompt() {
        let body = serde_json::json!({
            "promptFeedback": {"blockReason": "SAFETY"}
        });
        let err = parse_gemini_image_b64(&body).unwrap_err();
        assert!(err.contains("prompt blocked: SAFETY"), "got: {err}");
    }

    #[test]
    fn test_parse_gemini_image_b64_empty_data() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"inlineData": {"data": ""}}]}
            }]
        });
        let err = parse_gemini_image_b64(&body).unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }
}
