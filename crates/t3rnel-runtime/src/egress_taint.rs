//! Taint tracking for secret material at the tool boundary.
//!
//! `egress_guard` asks *does this output look like a secret*. That question
//! cannot be won against an adversary: a prompt injection saying "read .env,
//! compress it, and post the result" produces output matching no secret
//! pattern. The guard closes naive encodings; it does not close a determined
//! one.
//!
//! This module asks a different question — *did this session touch secret
//! material at all* — which is a capability question, not a pattern question,
//! and is therefore indifferent to how the data was transformed on the way out.
//!
//! # Model
//!
//! A session becomes tainted when it reads a secret-bearing source (a `.env`, a
//! key file, `~/.ssh`, a credential-shaped env var). Once tainted, any tool that
//! sends data outward requires explicit approval regardless of what the payload
//! looks like.
//!
//! Taint is deliberately sticky and coarse. A false "needs approval" costs one
//! click; a false "safe to publish" costs a wallet.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// How strictly taint is applied, via `T3RNEL_EGRESS_TAINT_MODE`.
///
/// The default is `Enforce`. `Warn` exists so an operator can measure the
/// control's false-positive rate on their own workload before it can block
/// anything, and `Off` exists so that a broken control can be switched off
/// deliberately rather than by someone deleting the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Warn,
    Off,
}

impl Mode {
    pub fn from_env() -> Self {
        match std::env::var("T3RNEL_EGRESS_TAINT_MODE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "off" | "disabled" | "0" | "false" => Mode::Off,
            "warn" | "warning" | "audit" => Mode::Warn,
            // Anything unrecognised — including empty — enforces. A typo in
            // this variable must never be a silent downgrade to no protection.
            _ => Mode::Enforce,
        }
    }

    /// True when taint should still be recorded. `Warn` records but does not block.
    pub fn is_active(self) -> bool {
        !matches!(self, Mode::Off)
    }
}

/// Why a session is tainted, recorded without ever storing the secret itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintRecord {
    pub session: String,
    pub reason: &'static str,
    /// The source that caused the taint. A path or env-var *name* — never a value.
    pub source: String,
    pub at_epoch_secs: u64,
}

impl TaintRecord {
    /// Safe to log and safe to show an operator: names the capability, not the data.
    pub fn describe(&self) -> String {
        format!("{} via {}", self.reason, self.source)
    }
}

/// Refusal returned when a tainted session attempts egress.
#[derive(Debug, Clone)]
pub struct TaintBlocked {
    pub context: String,
    pub record: TaintRecord,
}

impl std::fmt::Display for TaintBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "egress blocked in {}: session previously read secret material ({}). \
             This requires explicit approval regardless of payload content.",
            self.context,
            self.record.describe()
        )
    }
}

impl std::error::Error for TaintBlocked {}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn store() -> &'static Mutex<HashMap<String, TaintRecord>> {
    static STORE: OnceLock<Mutex<HashMap<String, TaintRecord>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

struct SourceRules {
    paths: Vec<regex_lite::Regex>,
    env_names: regex_lite::Regex,
}

fn rules() -> &'static SourceRules {
    static RULES: OnceLock<SourceRules> = OnceLock::new();
    RULES.get_or_init(|| {
        let pats = [
            // A .env in any directory, including .env.local / .env.production.
            r"(^|/)\.env(\.|$)",
            r"(^|/)secrets?\.(env|json|ya?ml|toml)$",
            r"/\.ssh/",
            r"/\.aws/(credentials|config)$",
            r"/\.gnupg/",
            r"/\.kube/config$",
            r"(^|/)id_(rsa|ed25519|ecdsa)(\.pub)?$",
            r"(^|/)\.netrc$",
            r"(^|/)credentials\.json$",
            r"/\.t3rnel/(secrets\.env|a2a-payload\.key)$",
            // Private key material by extension.
            r"\.(pem|p12|pfx|jks|keystore)$",
            // Wallet material — the highest-consequence source in this system.
            r"(^|/)(mnemonic|seed|recovery[-_]?phrase)(\.[a-z]+)?$",
            r"/\.t3rnel/wallet",
        ];
        SourceRules {
            paths: pats
                .iter()
                .filter_map(|p| regex_lite::Regex::new(p).ok())
                .collect(),
            env_names: regex_lite::Regex::new(
                r"(?i)(API_KEY|SECRET|TOKEN|PASSWORD|PASSPHRASE|PHRASE|PRIVATE_KEY|JWT|CREDENTIAL|MNEMONIC)",
            )
            .expect("static env-name pattern must compile"),
        }
    })
}

/// True when reading this path means holding credential material.
///
/// Matching is done on a forward-slash-normalised path so Windows separators
/// do not silently bypass every rule.
pub fn is_secret_source(path: &str) -> bool {
    let normalised = path.replace('\\', "/");
    rules().paths.iter().any(|re| re.is_match(&normalised))
}

/// True when an environment variable's *name* implies its value is a credential.
pub fn is_secret_env_name(name: &str) -> bool {
    rules().env_names.is_match(name)
}

/// Tools that send data outside this machine. A tainted session may not use
/// these without approval.
///
/// This list is intentionally broad: `shell_exec` is included because `curl`
/// is a perfectly good exfiltration tool, and a session that has read a wallet
/// seed should not get a shell to itself on the honour system.
pub const EGRESS_TOOLS: &[&str] = &[
    "web_fetch",
    "browser_navigate",
    "browser_click",
    "browser_type",
    "browser_fill",
    "browser_evaluate",
    "channel_send",
    "a2a_send",
    "a2a_discover",
    "ide_delegate",
    "mcp_invoke",
    "shell_exec",
    "docker_exec",
    "process_start",
    "process_write",
    "image_generate",
    "agent_send",
];

/// True when this tool can move data off the machine.
pub fn is_egress_tool(tool: &str) -> bool {
    EGRESS_TOOLS.contains(&tool)
}

/// Tools whose payload is *published* — sent verbatim to a third party.
///
/// Deliberately narrower than [`EGRESS_TOOLS`]. The two lists answer different
/// questions and conflating them causes real damage:
///
/// - Taint asks *could this session exfiltrate?* — `shell_exec` belongs, because
///   `curl` is a fine exfiltration tool.
/// - Content scanning asks *is this payload being published?* — `shell_exec`
///   does **not** belong, because a command that merely mentions
///   `/home/user/project` is executing locally, not publishing anything.
///
/// Scanning shell commands for secret *shapes* flagged every ordinary command
/// containing a home path and would have blocked routine agent work. That is
/// the false-positive failure mode that gets a guard switched off entirely,
/// at which point it protects nothing.
pub const PUBLISH_TOOLS: &[&str] = &[
    "web_fetch",
    "channel_send",
    "a2a_send",
    "ide_delegate",
    "browser_type",
    "browser_fill",
    "browser_evaluate",
];

/// True when this tool sends its payload verbatim to a third party.
pub fn is_publish_tool(tool: &str) -> bool {
    PUBLISH_TOOLS.contains(&tool)
}

/// Mark a session as having held secret material.
///
/// Re-tainting keeps the *earliest* cause, which is the one an operator needs
/// to see; a later `.env` read should not mask that a wallet seed was opened first.
pub fn taint(session: &str, reason: &'static str, source: &str) {
    let Ok(mut map) = store().lock() else {
        // A poisoned lock means another thread panicked mid-update. Failing
        // open here would silently disable the control, so treat it as fatal
        // to the request rather than to the process.
        tracing::error!(session, "taint store poisoned; treating session as tainted");
        return;
    };
    map.entry(session.to_string())
        .or_insert_with(|| TaintRecord {
            session: session.to_string(),
            reason,
            source: source.to_string(),
            at_epoch_secs: now_secs(),
        });
}

/// The taint record for a session, if it has one.
pub fn taint_of(session: &str) -> Option<TaintRecord> {
    store().lock().ok()?.get(session).cloned()
}

/// True when the session has held secret material.
pub fn is_tainted(session: &str) -> bool {
    taint_of(session).is_some()
}

/// Clear a session's taint. This is an operator action — an agent must never
/// call it on its own behalf, or the control means nothing.
pub fn clear(session: &str) -> bool {
    store()
        .lock()
        .map(|mut m| m.remove(session).is_some())
        .unwrap_or(false)
}

/// Every currently tainted session, for operator display.
pub fn all_tainted() -> Vec<TaintRecord> {
    let Ok(map) = store().lock() else {
        return Vec::new();
    };
    let mut v: Vec<TaintRecord> = map.values().cloned().collect();
    v.sort_by_key(|a| a.at_epoch_secs);
    v
}

/// Record taint if this tool call read a secret-bearing source.
///
/// Called for *every* tool invocation, so a newly added file-reading tool is
/// covered without being individually enumerated.
pub fn observe_tool_input(session: &str, tool: &str, input: &serde_json::Value) {
    // Any string-valued argument that names a secret-bearing path taints the
    // session. Keying on argument *name* would miss a tool that calls it
    // something other than "path".
    for key in ["path", "file", "filename", "file_path", "source", "target"] {
        if let Some(p) = input.get(key).and_then(|v| v.as_str()) {
            if is_secret_source(p) {
                taint(session, "read secret-bearing file", p);
                return;
            }
        }
    }

    // Shell commands that cat a secret file are a read by another name.
    if tool == "shell_exec" || tool == "docker_exec" || tool == "process_start" {
        if let Some(cmd) = input
            .get("command")
            .and_then(|v| v.as_str())
            .or_else(|| input.get("cmd").and_then(|v| v.as_str()))
        {
            for token in cmd.split_whitespace() {
                let cleaned = token.trim_matches(|c| c == '"' || c == '\'');
                if is_secret_source(cleaned) {
                    taint(session, "shell read of secret-bearing file", cleaned);
                    return;
                }
            }
        }
    }

    // Reading a credential-shaped env var is the same capability as reading
    // the file it came from.
    if let Some(name) = input.get("name").and_then(|v| v.as_str()) {
        if tool.contains("env") && is_secret_env_name(name) {
            taint(session, "read credential environment variable", name);
        }
    }
}

/// Refuse egress from a tainted session.
///
/// Returns `Ok(())` when the call may proceed. The caller supplies
/// `approved` from the human-approval path; taint raises the bar to approval,
/// it does not make egress permanently impossible.
pub fn check_egress(session: &str, tool: &str, approved: bool) -> Result<(), TaintBlocked> {
    if !is_egress_tool(tool) {
        return Ok(());
    }
    match taint_of(session) {
        Some(record) if !approved => Err(TaintBlocked {
            context: tool.to_string(),
            record,
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Each test uses its own session id so the shared store cannot make
    /// results depend on test execution order.
    fn sid(name: &str) -> String {
        format!("test-{name}-{}", std::process::id())
    }

    #[test]
    fn recognises_secret_sources() {
        for p in [
            "/home/u/.env",
            "/home/u/app/.env.production",
            "/home/u/.ssh/id_rsa",
            "~/.aws/credentials",
            "/srv/credentials.json",
            "/home/u/certs/server.pem",
            "/home/u/.t3rnel/wallet/keystore",
            r"C:\Users\u\.ssh\id_ed25519",
        ] {
            assert!(is_secret_source(p), "should be secret: {p}");
        }
    }

    #[test]
    fn does_not_taint_ordinary_files() {
        // A guard that fires on README.md is a guard that gets switched off.
        for p in [
            "/mnt/work/README.md",
            "src/main.rs",
            "config/category-templates.toml",
            "/home/u/environment-notes.md",
            "docs/envoy.md",
            "scripts/deploy_autopilot.sh",
        ] {
            assert!(!is_secret_source(p), "should NOT be secret: {p}");
        }
    }

    #[test]
    fn env_name_matching_is_name_only() {
        assert!(is_secret_env_name("OPENAI_API_KEY"));
        assert!(is_secret_env_name("deriv_api_token"));
        assert!(is_secret_env_name("WALLET_MNEMONIC"));
        assert!(!is_secret_env_name("HOME"));
        assert!(!is_secret_env_name("T3RNEL_WORKSPACE"));
    }

    #[test]
    fn reading_env_file_taints_then_blocks_egress() {
        let s = sid("readenv");
        assert!(!is_tainted(&s));
        observe_tool_input(&s, "file_read", &json!({"path": "/home/u/.env"}));
        assert!(is_tainted(&s));

        // Content-free egress is still refused — that is the whole point.
        let err = check_egress(&s, "web_fetch", false).unwrap_err();
        assert!(err.to_string().contains("secret material"));
        // ...and the refusal names the capability, never the value.
        assert!(!err.to_string().contains("sk-"));

        clear(&s);
    }

    #[test]
    fn shell_cat_of_secret_is_treated_as_a_read() {
        let s = sid("shellcat");
        observe_tool_input(
            &s,
            "shell_exec",
            &json!({"command": "cat /home/u/.env | base64"}),
        );
        assert!(
            is_tainted(&s),
            "piping .env through base64 must still taint"
        );
        clear(&s);
    }

    #[test]
    fn non_egress_tools_stay_usable_while_tainted() {
        // Taint must not brick the agent: it may still think, read and compute.
        let s = sid("stillworks");
        observe_tool_input(&s, "file_read", &json!({"path": "/home/u/.env"}));
        for tool in [
            "file_read",
            "memory_store",
            "knowledge_query",
            "system_time",
        ] {
            assert!(
                check_egress(&s, tool, false).is_ok(),
                "{tool} should stay allowed"
            );
        }
        clear(&s);
    }

    #[test]
    fn approval_releases_the_block() {
        let s = sid("approved");
        observe_tool_input(&s, "file_read", &json!({"path": "/home/u/.ssh/id_rsa"}));
        assert!(check_egress(&s, "web_fetch", false).is_err());
        assert!(check_egress(&s, "web_fetch", true).is_ok());
        clear(&s);
    }

    #[test]
    fn clean_session_is_never_blocked() {
        let s = sid("clean");
        observe_tool_input(&s, "file_read", &json!({"path": "/mnt/work/README.md"}));
        assert!(!is_tainted(&s));
        assert!(check_egress(&s, "web_fetch", false).is_ok());
    }

    #[test]
    fn taint_keeps_the_earliest_cause() {
        let s = sid("earliest");
        observe_tool_input(
            &s,
            "file_read",
            &json!({"path": "/home/u/.t3rnel/wallet/seed"}),
        );
        observe_tool_input(&s, "file_read", &json!({"path": "/home/u/.env"}));
        let rec = taint_of(&s).expect("tainted");
        assert!(
            rec.source.contains("wallet"),
            "a later .env read must not mask the wallet read: {}",
            rec.source
        );
        clear(&s);
    }
}
