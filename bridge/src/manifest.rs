//! The v1 plugin manifest (`04-app-bridge-and-connectors.md` §3) and its validation.
//!
//! Parsing is strict: an unknown key is an error, because a field the Bridge does not read can never be enforced
//! (truth rule 4). Validation collects every violation instead of stopping at the first.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityId, RiskClass};

pub const MANIFEST_VERSION: &str = "1.0";

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugin {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub licence: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Runtime {
    #[serde(rename = "wasm")]
    Wasm,
    #[serde(rename = "process")]
    Process,
    #[serde(rename = "in-app")]
    InApp,
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

pub const ALL_TRIGGERS: [ReapprovalTrigger; 3] =
    [ReapprovalTrigger::NewCapability, ReapprovalTrigger::NewPermission, ReapprovalTrigger::NewNetworkHost];

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
    RiskBelowReference { id: CapabilityId, declared: RiskClass, reference: RiskClass },
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
        ConformanceReport { passed: passed.into_iter().collect() }
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
        for (name, value) in [
            ("plugin.name", &self.plugin.name),
            ("plugin.publisher", &self.plugin.publisher),
            ("plugin.licence", &self.plugin.licence),
            ("application.id", &self.application.id),
            ("application.supported_versions", &self.application.supported_versions),
            ("integration.transport", &self.integration.transport),
            ("tests.conformance", &self.tests.conformance),
        ] {
            if value.trim().is_empty() {
                out.push(Violation::EmptyField(name));
            }
        }
        let d = &self.application.detect;
        if [&d.desktop_entry, &d.windows_app, &d.macos_bundle].iter().all(|v| v.as_deref().is_none_or(|s| s.trim().is_empty())) {
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
                        out.push(Violation::RiskBelowReference { id: entry.id.clone(), declared, reference });
                    }
                }
            }
        }
        for host in &self.permissions.network.hosts {
            if !valid_host(host) {
                out.push(Violation::BadHost(host.clone()));
            }
        }
        if !self.security.signed {
            out.push(Violation::Unsigned);
        }
        if !self.security.audit {
            out.push(Violation::AuditDisabled);
        }
        for trigger in ALL_TRIGGERS {
            if !self.security.update_requires_reapproval_if.contains(&trigger) {
                out.push(Violation::MissingReapprovalTrigger(trigger));
            }
        }
        out
    }

    /// The effective risk class of each advertised capability: the reference class (a declaration can only raise it).
    pub fn effective_risk(&self, id: &CapabilityId) -> Option<RiskClass> {
        let entry = self.capabilities.iter().find(|c| &c.id == id)?;
        let reference = id.reference_risk()?;
        Some(entry.risk.map_or(reference, |declared| declared.max(reference)))
    }

    /// Every advertised capability needs a passing conformance test. Returns the ones that have none.
    pub fn check_conformance(&self, report: &ConformanceReport) -> Result<(), Vec<CapabilityId>> {
        let missing: Vec<CapabilityId> =
            self.capabilities.iter().filter(|c| !report.passed.contains(&c.id)).map(|c| c.id.clone()).collect();
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
                && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !p.starts_with('-')
                && !p.ends_with('-')
        })
}

fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && (p.len() == 1 || !p.starts_with('0')))
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && !h.contains("..")
        && h.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// The VLC example from the specification, verbatim except for the capability list's `risk` keys being absent.
    pub const VLC: &str = r#"
manifest_version: "1.0"
plugin:
  id: "org.t3rnel.vlc-bridge"
  name: "VLC Bridge"
  version: "1.0.0"
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
  network:    { default: deny }
  secrets:    { required: ["vlc_http_password"] }
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
        let doc = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/sections/04-app-bridge-and-connectors.md");
        let text = std::fs::read_to_string(doc).unwrap();
        let start = text.find("```yaml\nmanifest_version").expect("yaml example") + "```yaml\n".len();
        let end = text[start..].find("```").unwrap() + start;
        let from_doc = text[start..end].lines().map(|l| l.split('#').next().unwrap_or("")).collect::<Vec<_>>().join("\n");
        let parsed = Manifest::parse(&from_doc).unwrap_or_else(|e| panic!("the documented manifest is refused: {e}"));
        assert_eq!(parsed, Manifest::parse(VLC).unwrap());
    }

    #[test]
    fn an_unknown_key_is_a_parse_error_not_a_silently_ignored_field() {
        let yaml = VLC.replace("transport: \"http-lua\"", "transport: \"http-lua\"\n  sandbox: off");
        assert!(matches!(Manifest::parse(&yaml), Err(ManifestError::Parse(_))));
    }

    #[test]
    fn network_default_allow_does_not_parse() {
        let yaml = VLC.replace("network:    { default: deny }", "network:    { default: allow }");
        assert!(matches!(Manifest::parse(&yaml), Err(ManifestError::Parse(_))));
    }

    #[test]
    fn an_unknown_capability_is_refused() {
        let yaml = VLC.replace("  - id: media.seek", "  - id: media.teleport");
        assert_eq!(violations_of(&yaml), vec![Violation::UnknownCapability(cap("media.teleport"))]);
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
        assert_eq!(m.effective_risk(&cap("media.seek")), Some(RiskClass::System));
        assert_eq!(m.effective_risk(&cap("media.play")), Some(RiskClass::WriteReversible));
        assert_eq!(m.effective_risk(&cap("fs.delete")), None, "not advertised");
    }

    #[test]
    fn duplicate_capabilities_are_refused() {
        let yaml = VLC.replace("  - id: media.seek", "  - id: media.play");
        assert_eq!(violations_of(&yaml), vec![Violation::DuplicateCapability(cap("media.play"))]);
    }

    #[test]
    fn unsigned_unaudited_or_ratchet_weakened_manifests_are_refused() {
        let yaml = VLC.replace("signed: true", "signed: false").replace("audit: true", "audit: false").replace("\"new_network_host\"", "");
        let yaml = yaml.replace("\"new_permission\", ", "\"new_permission\"");
        assert_eq!(
            violations_of(&yaml),
            vec![Violation::Unsigned, Violation::AuditDisabled, Violation::MissingReapprovalTrigger(ReapprovalTrigger::NewNetworkHost)]
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
        for bad in ["https://api.example.com", "api.example.com/path", "API.example.com", "a..b", "-x.com", "host with space", ""] {
            let yaml = VLC.replace("network:    { default: deny }", &format!("network:    {{ default: deny, hosts: [\"{bad}\"] }}"));
            assert_eq!(violations_of(&yaml), vec![Violation::BadHost(bad.to_string())], "{bad:?}");
        }
        let ok = VLC.replace("network:    { default: deny }", "network:    { default: deny, hosts: [\"graph.facebook.com\"] }");
        assert!(Manifest::parse(&ok).is_ok());
    }

    #[test]
    fn every_violation_is_reported_together() {
        let yaml = VLC.replace("signed: true", "signed: false").replace("  - id: media.seek", "  - id: media.teleport");
        assert_eq!(violations_of(&yaml).len(), 2);
        let message = Manifest::parse(&yaml).unwrap_err().to_string();
        assert!(message.contains("unsigned") || message.contains("security.signed"), "{message}");
        assert!(message.contains("media.teleport"), "{message}");
    }

    #[test]
    fn conformance_must_cover_every_advertised_capability() {
        let m = Manifest::parse(VLC).unwrap();
        let all = ["media.play", "media.pause", "media.seek", "media.playlist.read", "media.metadata.read"].map(cap);
        assert!(m.check_conformance(&ConformanceReport::from_passed(all.clone())).is_ok());
        let partial = ConformanceReport::from_passed(all.iter().take(3).cloned());
        assert_eq!(m.check_conformance(&partial).unwrap_err(), vec![cap("media.playlist.read"), cap("media.metadata.read")]);
        assert_eq!(m.check_conformance(&ConformanceReport::default()).unwrap_err().len(), 5);
    }

    #[test]
    fn a_manifest_round_trips_through_yaml() {
        let m = Manifest::parse(VLC).unwrap();
        let again = Manifest::parse(&serde_yaml::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, again);
    }
}
