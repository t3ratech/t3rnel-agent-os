//! The v1 plugin manifest (`04-app-bridge-and-connectors.md` §3) and its validation.
//!
//! Parsing is strict: an unknown key is an error, because a field the Bridge does not read can never be enforced
//! (truth rule 4). Validation collects every violation instead of stopping at the first.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityId, RiskClass};

pub const MANIFEST_VERSION: &str = "1.0";

/// The host services a plugin may require (04 §14.2). `requires` keys must
/// come from this list; the core refuses an install it cannot satisfy.
pub const HOST_SERVICES: &[&str] = &[
    "http", "storage", "memory", "tools", "routes", "schedule", "events", "approval", "llm",
    "sentinel", "ui", "agents", "notify", "audit",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: String,
    pub plugin: Plugin,
    pub application: Application,
    pub integration: Integration,
    pub capabilities: Vec<CapabilityEntry>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub agent_interfaces: Vec<AgentInterface>,
    #[serde(default)]
    pub ui: Ui,
    pub security: Security,
    pub tests: Tests,
    /// Host services the plugin needs and the minimum version of each, e.g.
    /// `{ storage: ">=1", http: ">=1" }`. Optional services are discovered at
    /// start; a `requires` entry the core cannot satisfy refuses the install.
    #[serde(default)]
    pub requires: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugin {
    pub id: String,
    /// Plugin kind: skill | hand | agent | connector | mcp-extension | pack.
    #[serde(rename = "type")]
    pub kind: PluginType,
    pub name: String,
    pub version: String,
    /// Minimum core version this plugin was built against (`X.Y.Z`).
    pub min_t3rnel_version: String,
    /// Platforms the package ships for, e.g. `linux-x86_64`.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Optional JSON Schema for non-secret settings stored in
    /// `~/.t3rnel/plugins/<id>/config.toml`.
    #[serde(default)]
    pub config_schema: Option<String>,
    pub publisher: String,
    pub licence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginType {
    Skill,
    Hand,
    Agent,
    Connector,
    McpExtension,
    Pack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub id: String,
    pub detect: Detect,
    pub supported_versions: String,
}

/// How the registry recognises the application; at least one must be given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    pub desktop_entry: Option<String>,
    pub windows_app: Option<String>,
    pub macos_bundle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integration {
    /// 1 native plugin, 2 adapter, 3 accessibility. Level 4 (visual control) is nested-workspace only and never declared.
    pub level: u8,
    pub transport: String,
    pub runtime: Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Runtime {
    #[serde(rename = "wasm")]
    Wasm,
    #[serde(rename = "process")]
    Process,
    #[serde(rename = "in-app")]
    InApp,
}

impl std::fmt::Display for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Runtime::Wasm => "wasm",
            Runtime::Process => "process",
            Runtime::InApp => "in-app",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEntry {
    pub id: CapabilityId,
    /// Optional; may never be lower than the reference class.
    #[serde(default)]
    pub risk: Option<RiskClass>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub filesystem: Filesystem,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub secrets: Secrets,
    /// How the credential-brokering proxy uses each secret on the plugin's
    /// behalf: which scheme, and bound to which hosts, methods and paths
    /// (05 §14.1, §14.5). A secret name here must also appear in
    /// `secrets.required`.
    #[serde(default)]
    pub auth: Vec<AuthRule>,
    /// The most sensitive data classes the plugin's LLM calls may carry
    /// (05 §14.10). Empty means it may inject no labelled data.
    #[serde(default)]
    pub data_classes: Vec<DataClass>,
    /// Local IPC brokers the plugin may use instead of raw sockets
    /// (05 §14.8): dbus, local-http, cli, a11y — each fully scoped.
    #[serde(default)]
    pub local: Vec<LocalBroker>,
}

/// One authentication rule: the proxy injects or signs with `secret` only
/// for requests matching the declared hosts, methods and paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRule {
    /// Secret *name* in the vault (never a value).
    pub secret: String,
    /// Authentication scheme from the fixed core list.
    pub scheme: AuthScheme,
    /// Hosts this rule applies to (same syntax as `network.hosts`).
    pub hosts: Vec<String>,
    /// HTTP methods, uppercase (e.g. `GET`, `POST`).
    pub methods: Vec<String>,
    /// Path patterns, each starting with `/`; `*` matches a suffix.
    pub paths: Vec<String>,
}

/// The fixed list of authentication/signing schemes the proxy implements
/// (05 §14.1). Adding a scheme is a core release, never a plugin feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthScheme {
    Bearer,
    Header,
    Basic,
    QueryKey,
    HmacSha256,
    #[serde(rename = "aws-sigv4")]
    AwsSigV4,
}

/// Data classification of content (05 §14.10). Declaration order is
/// sensitivity order: later variants may only go to more trusted providers.
/// `Unclassified` is the default for anything unlabelled and never leaves
/// the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataClass {
    Public,
    PluginPrivate,
    Personal,
    Financial,
    CredentialAdjacent,
    Unclassified,
}

impl std::fmt::Display for DataClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DataClass::Public => "public",
            DataClass::PluginPrivate => "plugin-private",
            DataClass::Personal => "personal",
            DataClass::Financial => "financial",
            DataClass::CredentialAdjacent => "credential-adjacent",
            DataClass::Unclassified => "unclassified",
        })
    }
}

/// A local IPC broker declaration (05 §14.8). The plugin cannot open
/// sockets; the core brokers these channels, each scoped to what is listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBroker {
    pub broker: LocalBrokerKind,
    /// `dbus`: allowed bus names.
    #[serde(default)]
    pub bus_names: Vec<String>,
    /// `dbus`: allowed interfaces.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// `dbus`: allowed methods (interface.member or bare member).
    #[serde(default)]
    pub methods: Vec<String>,
    /// `local-http`: allowed `127.0.0.1:port` targets.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// `cli`: allowed executables (absolute paths).
    #[serde(default)]
    pub executables: Vec<String>,
    /// `cli`: allowed argument patterns (glob-style, e.g. `status *`).
    #[serde(default)]
    pub argument_patterns: Vec<String>,
    /// `a11y`: applications the accessibility actions may target.
    #[serde(default)]
    pub applications: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalBrokerKind {
    Dbus,
    LocalHttp,
    Cli,
    A11y,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

/// Network is deny-by-default; `default: allow` does not parse. Each host the adapter may reach is listed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub default: NetworkDefault,
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDefault {
    #[default]
    Deny,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    #[serde(default)]
    pub required: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentInterface {
    Mcp,
    Rest,
    Cli,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    #[serde(default)]
    pub dashboard_widget: bool,
    #[serde(default)]
    pub activity_events: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReapprovalTrigger {
    NewCapability,
    NewPermission,
    NewNetworkHost,
}

pub const ALL_TRIGGERS: [ReapprovalTrigger; 3] = [
    ReapprovalTrigger::NewCapability,
    ReapprovalTrigger::NewPermission,
    ReapprovalTrigger::NewNetworkHost,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    pub signed: bool,
    pub audit: bool,
    pub update_requires_reapproval_if: Vec<ReapprovalTrigger>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tests {
    pub conformance: String,
}

/// One reason a manifest is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    #[error("manifest_version must be {MANIFEST_VERSION:?}, found {0:?}")]
    UnsupportedVersion(String),
    #[error("plugin.id {0:?} must be reverse-DNS with at least three lowercase parts, e.g. org.t3rnel.vlc-bridge")]
    BadPluginId(String),
    #[error("plugin.version {0:?} must be MAJOR.MINOR.PATCH")]
    BadPluginVersion(String),
    #[error("plugin.min_t3rnel_version {0:?} must be MAJOR.MINOR.PATCH")]
    BadMinT3rnelVersion(String),
    #[error(
        "plugin.targets entry {0:?} must look like linux-x86_64, windows-x86_64 or macos-aarch64"
    )]
    BadTarget(String),
    #[error("permissions.auth rule for secret {0:?} must name at least one host, method and path")]
    UnscopedAuthRule(String),
    #[error("permissions.auth rule references secret {0:?} which is not in secrets.required")]
    AuthSecretNotRequired(String),
    #[error("permissions.auth rule for secret {0:?} has invalid host {1:?}")]
    BadAuthHost(String, String),
    #[error("permissions.auth rule for secret {0:?} has invalid method {1:?} (uppercase token expected)")]
    BadAuthMethod(String, String),
    #[error("permissions.auth rule for secret {0:?} has invalid path {1:?} (must start with /)")]
    BadAuthPath(String, String),
    #[error("permissions.local broker {0:?} has fields that do not belong to its kind or misses required ones")]
    BadLocalBroker(String),
    #[error("requires key {0:?} is not a known host service (see HOST_SERVICES)")]
    UnknownHostService(String),
    #[error("requires[{0}] version requirement {1:?} must be X.Y.Z or >=X.Y.Z")]
    BadVersionReq(String, String),
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("application.detect needs at least one of desktop_entry, windows_app, macos_bundle")]
    NoDetection,
    #[error("integration.level {0} is not 1, 2 or 3")]
    BadLevel(u8),
    #[error("runtime in-app is only for level 1 (native plugin), found level {0}")]
    InAppNeedsLevelOne(u8),
    #[error("a manifest must advertise at least one capability")]
    NoCapabilities,
    #[error("capability {0} is advertised twice")]
    DuplicateCapability(CapabilityId),
    #[error("capability {0} is not in the reference table")]
    UnknownCapability(CapabilityId),
    #[error("capability {id} declares risk {declared} but the reference class is {reference}; a manifest cannot lower it")]
    RiskBelowReference {
        id: CapabilityId,
        declared: RiskClass,
        reference: RiskClass,
    },
    #[error("network host {0:?} must be a bare lowercase host name")]
    BadHost(String),
    #[error("security.signed must be true: the Bridge refuses unsigned packages")]
    Unsigned,
    #[error("security.audit must be true: every call is recorded")]
    AuditDisabled,
    #[error("update_requires_reapproval_if must include {0:?}")]
    MissingReapprovalTrigger(ReapprovalTrigger),
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest does not parse: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("manifest is invalid: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Invalid(Vec<Violation>),
}

/// The set of capabilities whose conformance tests passed, as produced by the conformance harness.
#[derive(Debug, Clone, Default)]
pub struct ConformanceReport {
    passed: BTreeSet<CapabilityId>,
}

impl ConformanceReport {
    pub fn from_passed(passed: impl IntoIterator<Item = CapabilityId>) -> Self {
        ConformanceReport {
            passed: passed.into_iter().collect(),
        }
    }
}

impl Manifest {
    /// Parse and validate. Nothing that fails validation is returned.
    pub fn parse(yaml: &str) -> Result<Manifest, ManifestError> {
        let manifest: Manifest = serde_yaml::from_str(yaml)?;
        let violations = manifest.violations();
        if violations.is_empty() {
            Ok(manifest)
        } else {
            Err(ManifestError::Invalid(violations))
        }
    }

    pub fn violations(&self) -> Vec<Violation> {
        let mut out = Vec::new();
        if self.manifest_version != MANIFEST_VERSION {
            out.push(Violation::UnsupportedVersion(self.manifest_version.clone()));
        }
        if !valid_plugin_id(&self.plugin.id) {
            out.push(Violation::BadPluginId(self.plugin.id.clone()));
        }
        if !valid_version(&self.plugin.version) {
            out.push(Violation::BadPluginVersion(self.plugin.version.clone()));
        }
        if !valid_version(&self.plugin.min_t3rnel_version) {
            out.push(Violation::BadMinT3rnelVersion(
                self.plugin.min_t3rnel_version.clone(),
            ));
        }
        for target in &self.plugin.targets {
            if !valid_target(target) {
                out.push(Violation::BadTarget(target.clone()));
            }
        }
        for (name, value) in [
            ("plugin.name", &self.plugin.name),
            ("plugin.publisher", &self.plugin.publisher),
            ("plugin.licence", &self.plugin.licence),
            ("application.id", &self.application.id),
            (
                "application.supported_versions",
                &self.application.supported_versions,
            ),
            ("integration.transport", &self.integration.transport),
            ("tests.conformance", &self.tests.conformance),
        ] {
            if value.trim().is_empty() {
                out.push(Violation::EmptyField(name));
            }
        }
        let d = &self.application.detect;
        if [&d.desktop_entry, &d.windows_app, &d.macos_bundle]
            .iter()
            .all(|v| v.as_deref().is_none_or(|s| s.trim().is_empty()))
        {
            out.push(Violation::NoDetection);
        }
        if !(1..=3).contains(&self.integration.level) {
            out.push(Violation::BadLevel(self.integration.level));
        }
        if self.integration.runtime == Runtime::InApp && self.integration.level != 1 {
            out.push(Violation::InAppNeedsLevelOne(self.integration.level));
        }
        if self.capabilities.is_empty() {
            out.push(Violation::NoCapabilities);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.capabilities {
            if !seen.insert(&entry.id) {
                out.push(Violation::DuplicateCapability(entry.id.clone()));
            }
            match entry.id.reference_risk() {
                None => out.push(Violation::UnknownCapability(entry.id.clone())),
                Some(reference) => {
                    if let Some(declared) = entry.risk.filter(|declared| *declared < reference) {
                        out.push(Violation::RiskBelowReference {
                            id: entry.id.clone(),
                            declared,
                            reference,
                        });
                    }
                }
            }
        }
        for host in &self.permissions.network.hosts {
            if !valid_host(host) {
                out.push(Violation::BadHost(host.clone()));
            }
        }
        let required_secrets: BTreeSet<&str> = self
            .permissions
            .secrets
            .required
            .iter()
            .map(String::as_str)
            .collect();
        for rule in &self.permissions.auth {
            if rule.secret.trim().is_empty() {
                out.push(Violation::UnscopedAuthRule(String::new()));
                continue;
            }
            if !required_secrets.contains(rule.secret.as_str()) {
                out.push(Violation::AuthSecretNotRequired(rule.secret.clone()));
            }
            if rule.hosts.is_empty() || rule.methods.is_empty() || rule.paths.is_empty() {
                out.push(Violation::UnscopedAuthRule(rule.secret.clone()));
            }
            for host in &rule.hosts {
                if !valid_host(host) {
                    out.push(Violation::BadAuthHost(rule.secret.clone(), host.clone()));
                }
            }
            for method in &rule.methods {
                if method.is_empty()
                    || !method.chars().all(|c| {
                        c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '*'
                    })
                {
                    out.push(Violation::BadAuthMethod(
                        rule.secret.clone(),
                        method.clone(),
                    ));
                }
            }
            for path in &rule.paths {
                if !path.starts_with('/') || path.contains("..") {
                    out.push(Violation::BadAuthPath(rule.secret.clone(), path.clone()));
                }
            }
        }
        for broker in &self.permissions.local {
            if !broker_fields_valid(broker) {
                out.push(Violation::BadLocalBroker(format!("{:?}", broker.broker)));
            }
        }
        for (service, req) in &self.requires {
            if !HOST_SERVICES.contains(&service.as_str()) {
                out.push(Violation::UnknownHostService(service.clone()));
            }
            if !valid_version_req(req) {
                out.push(Violation::BadVersionReq(service.clone(), req.clone()));
            }
        }
        if !self.security.signed {
            out.push(Violation::Unsigned);
        }
        if !self.security.audit {
            out.push(Violation::AuditDisabled);
        }
        for trigger in ALL_TRIGGERS {
            if !self
                .security
                .update_requires_reapproval_if
                .contains(&trigger)
            {
                out.push(Violation::MissingReapprovalTrigger(trigger));
            }
        }
        out
    }

    /// The effective risk class of each advertised capability: the reference class (a declaration can only raise it).
    pub fn effective_risk(&self, id: &CapabilityId) -> Option<RiskClass> {
        let entry = self.capabilities.iter().find(|c| &c.id == id)?;
        let reference = id.reference_risk()?;
        Some(
            entry
                .risk
                .map_or(reference, |declared| declared.max(reference)),
        )
    }

    /// Every advertised capability needs a passing conformance test. Returns the ones that have none.
    pub fn check_conformance(&self, report: &ConformanceReport) -> Result<(), Vec<CapabilityId>> {
        let missing: Vec<CapabilityId> = self
            .capabilities
            .iter()
            .filter(|c| !report.passed.contains(&c.id))
            .map(|c| c.id.clone())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

fn valid_plugin_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split('.').collect();
    parts.len() >= 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !p.starts_with('-')
                && !p.ends_with('-')
        })
}

fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars().all(|c| c.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

/// A host may be `name`, `name:port` (e.g. `127.0.0.1:8080` for a loopback
/// adapter interface) or `host/path`-free — paths belong to auth rules.
fn valid_host(h: &str) -> bool {
    let (host, port) = match h.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (h, None),
    };
    let host_ok = !host.is_empty()
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.len() <= 5
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| n > 0 && n <= 65535)
    });
    host_ok && port_ok
}

fn valid_target(t: &str) -> bool {
    !t.is_empty()
        && t.contains('-')
        && t.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Version requirement: `X.Y.Z` (means exactly that minimum) or `>=X[.Y[.Z]]`.
fn valid_version_req(req: &str) -> bool {
    let v = req.strip_prefix(">=").unwrap_or(req);
    // ">=1" and ">=1.2" are allowed; a bare requirement must be full semver.
    if req.starts_with(">=") {
        let parts: Vec<&str> = v.split('.').collect();
        return (1..=3).contains(&parts.len())
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    }
    valid_version(v)
}

/// Each local broker kind has its own field set; fields belonging to other
/// kinds must be empty and the kind's own list must be non-empty.
fn broker_fields_valid(b: &LocalBroker) -> bool {
    let empty = |v: &[String]| v.is_empty();
    match b.broker {
        LocalBrokerKind::Dbus => {
            !b.bus_names.is_empty()
                && empty(&b.hosts)
                && empty(&b.executables)
                && empty(&b.argument_patterns)
                && empty(&b.applications)
                && (empty(&b.interfaces) || !b.methods.is_empty())
        }
        LocalBrokerKind::LocalHttp => {
            !b.hosts.is_empty()
                && b.hosts.iter().all(|h| valid_host(h))
                && empty(&b.bus_names)
                && empty(&b.interfaces)
                && empty(&b.methods)
                && empty(&b.executables)
                && empty(&b.argument_patterns)
                && empty(&b.applications)
        }
        LocalBrokerKind::Cli => {
            !b.executables.is_empty()
                && !b.argument_patterns.is_empty()
                && empty(&b.bus_names)
                && empty(&b.interfaces)
                && empty(&b.methods)
                && empty(&b.hosts)
                && empty(&b.applications)
        }
        LocalBrokerKind::A11y => {
            !b.applications.is_empty()
                && empty(&b.bus_names)
                && empty(&b.interfaces)
                && empty(&b.methods)
                && empty(&b.hosts)
                && empty(&b.executables)
                && empty(&b.argument_patterns)
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// The VLC example from the specification, verbatim except for the capability list's `risk` keys being absent.
    pub const VLC: &str = r#"
manifest_version: "1.0"
plugin:
  id: "org.t3rnel.vlc-bridge"
  type: "connector"
  name: "VLC Bridge"
  version: "1.0.0"
  min_t3rnel_version: "1.0.0"
  targets: ["linux-x86_64", "windows-x86_64", "macos-aarch64"]
  config_schema: "config.schema.json"
  publisher: "t3rnel"
  licence: "Apache-2.0"
application:
  id: "vlc"
  detect:
    desktop_entry: "vlc.desktop"
    windows_app: "VideoLAN.VLC"
    macos_bundle: "org.videolan.vlc"
  supported_versions: "3.x"
integration:
  level: 2
  transport: "http-lua"
  runtime: "process"
capabilities:
  - id: media.play
  - id: media.pause
  - id: media.seek
  - id: media.playlist.read
  - id: media.metadata.read
permissions:
  filesystem: { read: ["user_approved_media_dirs"] }
  network:
    default: deny
    hosts: ["127.0.0.1:8080"]
  secrets:
    required: ["vlc_http_password"]
  auth:
    - secret: "vlc_http_password"
      scheme: "basic"
      hosts: ["127.0.0.1:8080"]
      methods: ["GET"]
      paths: ["/requests/*"]
  data_classes: ["personal"]
agent_interfaces: [mcp, rest, cli]
ui:
  dashboard_widget: true
  activity_events: true
security:
  signed: true
  audit: true
  update_requires_reapproval_if: ["new_capability", "new_permission", "new_network_host"]
tests:
  conformance: "tests/conformance.yaml"
requires: { storage: ">=1", http: ">=1" }
"#;
}

#[cfg(test)]
mod tests {
    use super::fixtures::VLC;
    use super::*;

    fn cap(s: &str) -> CapabilityId {
        s.parse().unwrap()
    }

    fn violations_of(yaml: &str) -> Vec<Violation> {
        match Manifest::parse(yaml) {
            Err(ManifestError::Invalid(v)) => v,
            other => panic!("expected an Invalid manifest, got {other:?}"),
        }
    }

    #[test]
    fn the_specification_example_parses_and_validates() {
        let m = Manifest::parse(VLC).unwrap();
        assert_eq!(m.plugin.id, "org.t3rnel.vlc-bridge");
        assert_eq!(m.capabilities.len(), 5);
        assert_eq!(m.integration.runtime, Runtime::Process);
        assert_eq!(m.permissions.secrets.required, ["vlc_http_password"]);
    }

    #[test]
    fn the_example_in_the_specification_document_is_the_fixture() {
        // Truth rule 1: the manifest shown in section 04 must parse with this code.
        let doc = crate::spec_section("04-app-bridge-and-connectors.md");
        let text = std::fs::read_to_string(doc).unwrap();
        let start = text
            .find("```yaml\nmanifest_version")
            .expect("yaml example")
            + "```yaml\n".len();
        let end = text[start..].find("```").unwrap() + start;
        let from_doc = text[start..end]
            .lines()
            .map(|l| l.split('#').next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = Manifest::parse(&from_doc)
            .unwrap_or_else(|e| panic!("the documented manifest is refused: {e}"));
        assert_eq!(parsed, Manifest::parse(VLC).unwrap());
    }

    #[test]
    fn an_unknown_key_is_a_parse_error_not_a_silently_ignored_field() {
        let yaml = VLC.replace(
            "transport: \"http-lua\"",
            "transport: \"http-lua\"\n  sandbox: off",
        );
        assert!(matches!(
            Manifest::parse(&yaml),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn network_default_allow_does_not_parse() {
        let yaml = VLC.replace("default: deny", "default: allow");
        assert!(matches!(
            Manifest::parse(&yaml),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn an_unknown_capability_is_refused() {
        let yaml = VLC.replace("  - id: media.seek", "  - id: media.teleport");
        assert_eq!(
            violations_of(&yaml),
            vec![Violation::UnknownCapability(cap("media.teleport"))]
        );
    }

    #[test]
    fn a_manifest_cannot_lower_a_risk_class() {
        let yaml = VLC.replace("  - id: media.seek", "  - id: fs.delete\n    risk: read");
        assert_eq!(
            violations_of(&yaml),
            vec![Violation::RiskBelowReference {
                id: cap("fs.delete"),
                declared: RiskClass::Read,
                reference: RiskClass::WriteIrreversible
            }]
        );
    }

    #[test]
    fn a_manifest_may_raise_a_risk_class_and_the_effective_class_is_the_higher() {
        let yaml = VLC.replace("  - id: media.seek", "  - id: media.seek\n    risk: system");
        let m = Manifest::parse(&yaml).unwrap();
        assert_eq!(
            m.effective_risk(&cap("media.seek")),
            Some(RiskClass::System)
        );
        assert_eq!(
            m.effective_risk(&cap("media.play")),
            Some(RiskClass::WriteReversible)
        );
        assert_eq!(m.effective_risk(&cap("fs.delete")), None, "not advertised");
    }

    #[test]
    fn duplicate_capabilities_are_refused() {
        let yaml = VLC.replace("  - id: media.seek", "  - id: media.play");
        assert_eq!(
            violations_of(&yaml),
            vec![Violation::DuplicateCapability(cap("media.play"))]
        );
    }

    #[test]
    fn unsigned_unaudited_or_ratchet_weakened_manifests_are_refused() {
        let yaml = VLC
            .replace("signed: true", "signed: false")
            .replace("audit: true", "audit: false")
            .replace("\"new_network_host\"", "");
        let yaml = yaml.replace("\"new_permission\", ", "\"new_permission\"");
        assert_eq!(
            violations_of(&yaml),
            vec![
                Violation::Unsigned,
                Violation::AuditDisabled,
                Violation::MissingReapprovalTrigger(ReapprovalTrigger::NewNetworkHost)
            ]
        );
    }

    #[test]
    fn in_app_runtime_requires_level_one() {
        let yaml = VLC.replace("runtime: \"process\"", "runtime: \"in-app\"");
        assert_eq!(violations_of(&yaml), vec![Violation::InAppNeedsLevelOne(2)]);
        let ok = yaml.replace("level: 2", "level: 1");
        assert!(Manifest::parse(&ok).is_ok());
    }

    #[test]
    fn level_four_is_never_declared_in_a_manifest() {
        let yaml = VLC.replace("level: 2", "level: 4");
        assert_eq!(violations_of(&yaml), vec![Violation::BadLevel(4)]);
    }

    #[test]
    fn identity_and_detection_fields_are_checked() {
        let yaml = VLC
            .replace("org.t3rnel.vlc-bridge", "vlc")
            .replace("version: \"1.0.0\"", "version: \"1.0\"")
            .replace("desktop_entry: \"vlc.desktop\"", "")
            .replace("windows_app: \"VideoLAN.VLC\"", "")
            .replace("macos_bundle: \"org.videolan.vlc\"", "");
        let v = violations_of(&yaml);
        assert!(v.contains(&Violation::BadPluginId("vlc".into())));
        assert!(v.contains(&Violation::BadPluginVersion("1.0".into())));
        assert!(v.contains(&Violation::NoDetection));
    }

    #[test]
    fn network_hosts_must_be_bare_host_names() {
        for bad in [
            "https://api.example.com",
            "api.example.com/path",
            "API.example.com",
            "a..b",
            "-x.com",
            "host with space",
            "",
        ] {
            let yaml = VLC.replace(
                "network:\n    default: deny\n    hosts: [\"127.0.0.1:8080\"]",
                &format!("network:\n    default: deny\n    hosts: [\"{bad}\"]"),
            );
            assert_eq!(
                violations_of(&yaml),
                vec![Violation::BadHost(bad.to_string())],
                "{bad:?}"
            );
        }
        let ok = VLC.replace(
            "hosts: [\"127.0.0.1:8080\"]\n  secrets:",
            "hosts: [\"graph.facebook.com\", \"127.0.0.1:8080\"]\n  secrets:",
        );
        assert!(Manifest::parse(&ok).is_ok());
        // host:port is a legitimate target for loopback adapter interfaces.
        let ok = VLC.replace(
            "hosts: [\"127.0.0.1:8080\"]\n  secrets:",
            "hosts: [\"127.0.0.1:8080\", \"192.168.1.10:9090\"]\n  secrets:",
        );
        assert!(Manifest::parse(&ok).is_ok());
        for bad in [
            "127.0.0.1:0",
            "127.0.0.1:99999",
            "127.0.0.1:",
            "127.0.0.1:80x",
        ] {
            let yaml = VLC.replace(
                "network:\n    default: deny\n    hosts: [\"127.0.0.1:8080\"]",
                &format!("network:\n    default: deny\n    hosts: [\"{bad}\"]"),
            );
            assert_eq!(
                violations_of(&yaml),
                vec![Violation::BadHost(bad.to_string())],
                "{bad:?}"
            );
        }
    }

    #[test]
    fn every_violation_is_reported_together() {
        let yaml = VLC
            .replace("signed: true", "signed: false")
            .replace("  - id: media.seek", "  - id: media.teleport");
        assert_eq!(violations_of(&yaml).len(), 2);
        let message = Manifest::parse(&yaml).unwrap_err().to_string();
        assert!(
            message.contains("unsigned") || message.contains("security.signed"),
            "{message}"
        );
        assert!(message.contains("media.teleport"), "{message}");
    }

    #[test]
    fn conformance_must_cover_every_advertised_capability() {
        let m = Manifest::parse(VLC).unwrap();
        let all = [
            "media.play",
            "media.pause",
            "media.seek",
            "media.playlist.read",
            "media.metadata.read",
        ]
        .map(cap);
        assert!(m
            .check_conformance(&ConformanceReport::from_passed(all.clone()))
            .is_ok());
        let partial = ConformanceReport::from_passed(all.iter().take(3).cloned());
        assert_eq!(
            m.check_conformance(&partial).unwrap_err(),
            vec![cap("media.playlist.read"), cap("media.metadata.read")]
        );
        assert_eq!(
            m.check_conformance(&ConformanceReport::default())
                .unwrap_err()
                .len(),
            5
        );
    }

    #[test]
    fn a_manifest_round_trips_through_yaml() {
        let m = Manifest::parse(VLC).unwrap();
        let again = Manifest::parse(&serde_yaml::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, again);
    }

    #[test]
    fn plugin_type_min_version_targets_and_config_schema_are_checked() {
        let m = Manifest::parse(VLC).unwrap();
        assert_eq!(m.plugin.kind, PluginType::Connector);
        assert_eq!(m.plugin.min_t3rnel_version, "1.0.0");
        assert_eq!(
            m.plugin.targets,
            ["linux-x86_64", "windows-x86_64", "macos-aarch64"]
        );
        assert_eq!(
            m.plugin.config_schema.as_deref(),
            Some("config.schema.json")
        );

        for bad in ["1.0", "v1", "1.0.0.0"] {
            let yaml = VLC.replace(
                "min_t3rnel_version: \"1.0.0\"",
                &format!("min_t3rnel_version: \"{bad}\""),
            );
            assert!(
                violations_of(&yaml).contains(&Violation::BadMinT3rnelVersion(bad.to_string())),
                "{bad}"
            );
        }
        for bad in ["Linux", "linux x86", "linuxx86_64", ""] {
            let yaml = VLC.replace(
                "targets: [\"linux-x86_64\", \"windows-x86_64\", \"macos-aarch64\"]",
                &format!("targets: [\"{bad}\"]"),
            );
            assert!(
                violations_of(&yaml).contains(&Violation::BadTarget(bad.to_string())),
                "{bad}"
            );
        }
        // Every documented plugin type parses.
        for (yaml_kind, expected) in [
            ("skill", PluginType::Skill),
            ("hand", PluginType::Hand),
            ("agent", PluginType::Agent),
            ("connector", PluginType::Connector),
            ("mcp-extension", PluginType::McpExtension),
            ("pack", PluginType::Pack),
        ] {
            let yaml = VLC.replace("type: \"connector\"", &format!("type: \"{yaml_kind}\""));
            assert_eq!(
                Manifest::parse(&yaml).unwrap().plugin.kind,
                expected,
                "{yaml_kind}"
            );
        }
        // An unknown type is a parse error, not a silent default.
        let yaml = VLC.replace("type: \"connector\"", "type: \"driver\"");
        assert!(matches!(
            Manifest::parse(&yaml),
            Err(ManifestError::Parse(_))
        ));
        // `type` is required.
        let yaml = VLC.replace("  type: \"connector\"\n", "");
        assert!(matches!(
            Manifest::parse(&yaml),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn auth_rules_must_be_fully_scoped_and_reference_required_secrets() {
        let m = Manifest::parse(VLC).unwrap();
        assert_eq!(m.permissions.auth.len(), 1);
        assert_eq!(m.permissions.auth[0].scheme, AuthScheme::Basic);

        // Secret not in secrets.required.
        let yaml = VLC.replace(
            "secret: \"vlc_http_password\"\n      scheme",
            "secret: \"other_key\"\n      scheme",
        );
        assert!(
            violations_of(&yaml).contains(&Violation::AuthSecretNotRequired("other_key".into()))
        );

        // Empty hosts.
        let yaml = VLC.replace(
            "hosts: [\"127.0.0.1:8080\"]\n      methods",
            "hosts: []\n      methods",
        );
        assert!(
            violations_of(&yaml).contains(&Violation::UnscopedAuthRule("vlc_http_password".into()))
        );

        // Bad host inside an auth rule.
        let yaml = VLC.replace(
            "hosts: [\"127.0.0.1:8080\"]\n      methods",
            "hosts: [\"HTTPS://x\"]\n      methods",
        );
        assert!(violations_of(&yaml).contains(&Violation::BadAuthHost(
            "vlc_http_password".into(),
            "HTTPS://x".into()
        )));

        // Lowercase method.
        let yaml = VLC.replace("methods: [\"GET\"]", "methods: [\"get\"]");
        assert!(violations_of(&yaml).contains(&Violation::BadAuthMethod(
            "vlc_http_password".into(),
            "get".into()
        )));

        // Path without leading slash and path traversal.
        for bad in ["requests/*", "../etc"] {
            let yaml = VLC.replace("paths: [\"/requests/*\"]", &format!("paths: [\"{bad}\"]"));
            assert!(
                violations_of(&yaml).contains(&Violation::BadAuthPath(
                    "vlc_http_password".into(),
                    bad.to_string()
                )),
                "{bad}"
            );
        }

        // Every scheme parses.
        for (yaml_scheme, expected) in [
            ("bearer", AuthScheme::Bearer),
            ("header", AuthScheme::Header),
            ("basic", AuthScheme::Basic),
            ("query-key", AuthScheme::QueryKey),
            ("hmac-sha256", AuthScheme::HmacSha256),
            ("aws-sigv4", AuthScheme::AwsSigV4),
        ] {
            let yaml = VLC.replace("scheme: \"basic\"", &format!("scheme: \"{yaml_scheme}\""));
            assert_eq!(
                Manifest::parse(&yaml).unwrap().permissions.auth[0].scheme,
                expected,
                "{yaml_scheme}"
            );
        }
    }

    #[test]
    fn data_classes_are_the_closed_set_from_the_security_spec() {
        let m = Manifest::parse(VLC).unwrap();
        assert_eq!(m.permissions.data_classes, [DataClass::Personal]);
        // Sensitivity order: provider policy relies on it (05 §14.10).
        assert!(DataClass::Public < DataClass::PluginPrivate);
        assert!(DataClass::PluginPrivate < DataClass::Personal);
        assert!(DataClass::Personal < DataClass::Financial);
        assert!(DataClass::Financial < DataClass::CredentialAdjacent);
        assert!(DataClass::CredentialAdjacent < DataClass::Unclassified);
        // An unknown class is a parse error.
        let yaml = VLC.replace(
            "data_classes: [\"personal\"]",
            "data_classes: [\"top-secret\"]",
        );
        assert!(matches!(
            Manifest::parse(&yaml),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn local_brokers_are_scoped_per_kind() {
        // A valid dbus broker parses.
        let yaml = VLC.replace(
            "  data_classes: [\"personal\"]\n",
            "  data_classes: [\"personal\"]\n  local:\n    - broker: dbus\n      bus_names: [\"org.videolan.vlc\"]\n      interfaces: [\"org.videolan.VLC\"]\n      methods: [\"org.videolan.VLC.play\"]\n",
        );
        let m = Manifest::parse(&yaml).unwrap();
        assert_eq!(m.permissions.local[0].broker, LocalBrokerKind::Dbus);
        assert_eq!(m.permissions.local[0].bus_names, ["org.videolan.vlc"]);

        // local-http with a bad host is refused.
        let yaml = VLC.replace(
            "  data_classes: [\"personal\"]\n",
            "  data_classes: [\"personal\"]\n  local:\n    - broker: local-http\n      hosts: [\"https://evil.example\"]\n",
        );
        assert!(violations_of(&yaml).contains(&Violation::BadLocalBroker("LocalHttp".into())));

        // cli requires executables AND argument patterns.
        let yaml = VLC.replace(
            "  data_classes: [\"personal\"]\n",
            "  data_classes: [\"personal\"]\n  local:\n    - broker: cli\n      executables: [\"/usr/bin/vlc\"]\n",
        );
        assert!(violations_of(&yaml).contains(&Violation::BadLocalBroker("Cli".into())));

        // Fields of another kind are refused.
        let yaml = VLC.replace(
            "  data_classes: [\"personal\"]\n",
            "  data_classes: [\"personal\"]\n  local:\n    - broker: a11y\n      applications: [\"vlc\"]\n      hosts: [\"127.0.0.1:1\"]\n",
        );
        assert!(violations_of(&yaml).contains(&Violation::BadLocalBroker("A11y".into())));

        // Unknown broker kind is a parse error.
        let yaml = VLC.replace(
            "  data_classes: [\"personal\"]\n",
            "  data_classes: [\"personal\"]\n  local:\n    - broker: magic\n      hosts: [\"x\"]\n",
        );
        assert!(matches!(
            Manifest::parse(&yaml),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn requires_names_known_services_with_sane_version_requirements() {
        let m = Manifest::parse(VLC).unwrap();
        assert_eq!(m.requires.get("storage").map(String::as_str), Some(">=1"));
        assert_eq!(m.requires.get("http").map(String::as_str), Some(">=1"));

        let yaml = VLC.replace(
            "requires: { storage: \">=1\", http: \">=1\" }",
            "requires: { quantum: \">=1\" }",
        );
        assert!(violations_of(&yaml).contains(&Violation::UnknownHostService("quantum".into())));

        for bad in ["latest", ">=x", "=>1", "1.0.0.0"] {
            let yaml = VLC.replace(
                "requires: { storage: \">=1\", http: \">=1\" }",
                &format!("requires: {{ storage: \"{bad}\" }}"),
            );
            assert!(
                violations_of(&yaml)
                    .contains(&Violation::BadVersionReq("storage".into(), bad.to_string())),
                "{bad}"
            );
        }
        // ">=1" and bare "1.2.3" are both fine.
        for ok in [
            "requires: { storage: \">=1\" }",
            "requires: { storage: \"1.2.3\" }",
            "requires: { storage: \">=1.2\" }",
        ] {
            let yaml = VLC.replace("requires: { storage: \">=1\", http: \">=1\" }", ok);
            assert!(Manifest::parse(&yaml).is_ok(), "{ok}");
        }
    }
}
