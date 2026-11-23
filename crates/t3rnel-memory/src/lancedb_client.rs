//! Blocking JSON-RPC client for the local LanceDB embedding sidecar.
//!
//! The sidecar owns the Python LanceDB dependency and embedding model runtime.
//! Rust keeps a small typed client here so the semantic store can use LanceDB
//! without pulling Arrow/LanceDB into every workspace build.

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum LanceDbError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("sidecar error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("parse error: {0}")]
    Parse(String),
    #[error("configuration error: {0}")]
    Config(String),
}

#[derive(Clone)]
pub struct LanceDbClient {
    base_url: String,
    token: String,
    client: reqwest::blocking::Client,
}

#[derive(Serialize)]
struct RpcRequest<'a, T> {
    jsonrpc: &'static str,
    id: String,
    method: &'a str,
    params: T,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct HealthResponse {
    ok: bool,
    lancedb: bool,
}

#[derive(Serialize)]
struct UpsertParams<'a> {
    records: Vec<UpsertRecord<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<&'a str>,
}

#[derive(Serialize)]
struct UpsertRecord<'a> {
    id: &'a str,
    content: &'a str,
    agent_id: &'a str,
    source: &'a str,
    scope: &'a str,
    metadata: &'a std::collections::HashMap<String, serde_json::Value>,
    created_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    vector: Option<&'a [f32]>,
}

#[derive(Deserialize)]
struct UpsertResult {
    ids: Vec<String>,
}

#[derive(Serialize)]
struct SearchParams<'a> {
    query: &'a str,
    limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    vector: Option<&'a [f32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<&'a str>,
}

#[derive(Deserialize)]
struct SearchResultEnvelope {
    results: Vec<LanceDbSearchResult>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LanceDbSearchResult {
    pub id: String,
    pub content: String,
    pub agent_id: String,
    pub source: String,
    pub scope: String,
    pub metadata_json: String,
    pub created_at: String,
    #[serde(rename = "_distance", default)]
    pub distance: Option<f64>,
}

#[derive(Serialize)]
struct DeleteParams<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<&'a str>,
}

impl LanceDbClient {
    pub fn new(base_url: &str, token_env: Option<&str>) -> Result<Self, LanceDbError> {
        if base_url.trim().is_empty() {
            return Err(LanceDbError::Config(
                "LanceDB sidecar URL must not be empty".to_string(),
            ));
        }
        let token = token_env
            .filter(|env| !env.trim().is_empty())
            .map(std::env::var)
            .transpose()
            .map_err(|e| LanceDbError::Config(e.to_string()))?
            .unwrap_or_default();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("t3rnel-memory-lancedb/0.4")
            .build()
            .map_err(|e| LanceDbError::Http(e.to_string()))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client,
        })
    }

    pub fn health_check(&self) -> Result<(), LanceDbError> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .map_err(|e| LanceDbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(LanceDbError::Http(format!(
                "health returned {}",
                resp.status()
            )));
        }
        let health: HealthResponse = resp
            .json()
            .map_err(|e| LanceDbError::Parse(e.to_string()))?;
        if !health.ok || !health.lancedb {
            return Err(LanceDbError::Config(
                "embedding sidecar is running without LanceDB enabled".to_string(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn store(
        &self,
        id: &str,
        content: &str,
        agent_id: &str,
        source: &str,
        scope: &str,
        metadata: &std::collections::HashMap<String, serde_json::Value>,
        created_at: &str,
        vector: Option<&[f32]>,
        namespace: Option<&str>,
    ) -> Result<String, LanceDbError> {
        let params = UpsertParams {
            records: vec![UpsertRecord {
                id,
                content,
                agent_id,
                source,
                scope,
                metadata,
                created_at,
                vector,
            }],
            namespace,
        };
        let result: UpsertResult = self.rpc("memory.upsert", params)?;
        result
            .ids
            .into_iter()
            .next()
            .ok_or_else(|| LanceDbError::Parse("memory.upsert returned no id".to_string()))
    }

    pub fn search(
        &self,
        query: &str,
        limit: usize,
        vector: Option<&[f32]>,
        namespace: Option<&str>,
    ) -> Result<Vec<LanceDbSearchResult>, LanceDbError> {
        let result: SearchResultEnvelope = self.rpc(
            "memory.search",
            SearchParams {
                query,
                limit,
                vector,
                namespace,
            },
        )?;
        Ok(result.results)
    }

    pub fn delete(&self, id: &str, namespace: Option<&str>) -> Result<(), LanceDbError> {
        let _: serde_json::Value = self.rpc("memory.delete", DeleteParams { id, namespace })?;
        Ok(())
    }

    fn rpc<T, R>(&self, method: &str, params: T) -> Result<R, LanceDbError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let req = RpcRequest {
            jsonrpc: "2.0",
            id: uuid::Uuid::new_v4().to_string(),
            method,
            params,
        };
        let mut http = self
            .client
            .post(format!("{}/rpc", self.base_url))
            .json(&req);
        if !self.token.is_empty() {
            http = http.header("Authorization", format!("Bearer {}", self.token));
        }
        let resp = http.send().map_err(|e| LanceDbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(LanceDbError::Http(format!(
                "rpc {method} returned {}",
                resp.status()
            )));
        }
        let body: RpcResponse<R> = resp
            .json()
            .map_err(|e| LanceDbError::Parse(e.to_string()))?;
        if let Some(error) = body.error {
            return Err(LanceDbError::Rpc {
                code: error.code,
                message: error.message,
            });
        }
        body.result
            .ok_or_else(|| LanceDbError::Parse(format!("rpc {method} returned no result")))
    }
}
