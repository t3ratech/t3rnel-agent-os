//! The update ratchet (`05-security-and-trust.md` §5, `04` §14.4): an update
//! that adds a capability, a permission, a network host, an auth grant, a data
//! class, changes the runtime or adds a local broker is blocked until the user
//! approves it afresh. Removing authority never needs approval.

use std::collections::BTreeSet;

use crate::capability::CapabilityId;
use crate::manifest::{AuthScheme, DataClass, LocalBroker, Manifest};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
pub enum Reapproval {
    #[error("new capability {0}")]
    NewCapability(CapabilityId),
    #[error("new permission {0}")]
    NewPermission(String),
    #[error("new network host {0}")]
    NewNetworkHost(String),
    /// A secret/scheme/host/method/path combination the approved manifest did
    /// not grant, e.g. `hmac-sha256 binance_key api.exchange.com POST /api/v3/order`.
    #[error("new auth grant {0}")]
    NewAuthGrant(String),
    #[error("new data class {0}")]
    NewDataClass(DataClass),
    #[error("runtime changed to {0}")]
    ChangedRuntime(crate::manifest::Runtime),
    #[error("new local broker {0}")]
    NewLocalBroker(String),
}

/// Everything `updated` adds on top of `approved`, in a stable order. Empty means the update may proceed unprompted.
pub fn reapproval_needed(approved: &Manifest, updated: &Manifest) -> Vec<Reapproval> {
    let mut out = BTreeSet::new();

    let had: BTreeSet<&CapabilityId> = approved.capabilities.iter().map(|c| &c.id).collect();
    for entry in &updated.capabilities {
        if !had.contains(&entry.id) {
            out.insert(Reapproval::NewCapability(entry.id.clone()));
        }
    }

    let permissions = |m: &Manifest| -> BTreeSet<String> {
        let p = &m.permissions;
        p.filesystem
            .read
            .iter()
            .map(|s| format!("filesystem.read:{s}"))
            .chain(
                p.filesystem
                    .write
                    .iter()
                    .map(|s| format!("filesystem.write:{s}")),
            )
            .chain(p.secrets.required.iter().map(|s| format!("secret:{s}")))
            .collect()
    };
    let before = permissions(approved);
    for permission in permissions(updated).difference(&before) {
        out.insert(Reapproval::NewPermission(permission.clone()));
    }

    let hosts: BTreeSet<&String> = approved.permissions.network.hosts.iter().collect();
    for host in &updated.permissions.network.hosts {
        if !hosts.contains(host) {
            out.insert(Reapproval::NewNetworkHost(host.clone()));
        }
    }

    // --- auth grants: secret name, scheme, host, method and path must all
    // already be covered; any widening forces fresh approval.
    let approved_secrets: BTreeSet<&str> = approved
        .permissions
        .secrets
        .required
        .iter()
        .map(String::as_str)
        .chain(approved.permissions.auth.iter().map(|r| r.secret.as_str()))
        .collect();
    for rule in &updated.permissions.auth {
        if !approved_secrets.contains(rule.secret.as_str()) {
            out.insert(Reapproval::NewPermission(format!("secret:{}", rule.secret)));
        }
        for host in &rule.hosts {
            for method in &rule.methods {
                for path in &rule.paths {
                    if !auth_grant_covered(approved, &rule.secret, rule.scheme, host, method, path)
                    {
                        out.insert(Reapproval::NewAuthGrant(format!(
                            "{} {} {} {} {}",
                            scheme_name(rule.scheme),
                            rule.secret,
                            host,
                            method,
                            path
                        )));
                    }
                }
            }
        }
    }

    // --- data classes: a plugin may only widen what its LLM calls may carry
    // with fresh approval.
    let classes: BTreeSet<DataClass> = approved.permissions.data_classes.iter().copied().collect();
    for class in &updated.permissions.data_classes {
        if !classes.contains(class) {
            out.insert(Reapproval::NewDataClass(*class));
        }
    }

    // --- a changed runtime is a different trust shape entirely.
    if updated.integration.runtime != approved.integration.runtime {
        out.insert(Reapproval::ChangedRuntime(updated.integration.runtime));
    }

    // --- local brokers: same kind with a subset of the approved scopes is
    // fine; anything new or widened needs approval.
    for broker in &updated.permissions.local {
        if !broker_covered(&approved.permissions.local, broker) {
            out.insert(Reapproval::NewLocalBroker(format!("{:?}", broker)));
        }
    }

    out.into_iter().collect()
}

fn scheme_name(scheme: AuthScheme) -> &'static str {
    match scheme {
        AuthScheme::Bearer => "bearer",
        AuthScheme::Header => "header",
        AuthScheme::Basic => "basic",
        AuthScheme::QueryKey => "query-key",
        AuthScheme::HmacSha256 => "hmac-sha256",
        AuthScheme::AwsSigV4 => "aws-sigv4",
    }
}

/// `true` when an approved auth rule covers this (secret, scheme, host,
/// method, path) combination. Approved entries may use `*` as a wildcard for
/// method and as a path suffix wildcard.
fn auth_grant_covered(
    approved: &Manifest,
    secret: &str,
    scheme: AuthScheme,
    host: &str,
    method: &str,
    path: &str,
) -> bool {
    approved.permissions.auth.iter().any(|rule| {
        rule.secret == secret
            && rule.scheme == scheme
            && rule.hosts.iter().any(|h| host_matches(h, host))
            && rule.methods.iter().any(|m| method_matches(m, method))
            && rule.paths.iter().any(|p| path_matches(p, path))
    })
}

/// An approved host covers the updated one when equal, or when the approved
/// entry is a `*` suffix wildcard on the same base.
fn host_matches(approved: &str, updated: &str) -> bool {
    approved == updated
        || (approved.ends_with(".*") && updated.starts_with(&approved[..approved.len() - 1]))
}

fn method_matches(approved: &str, updated: &str) -> bool {
    approved == "*" || approved == updated
}

/// A path pattern covers an updated path when identical, when the approved
/// pattern is `*`, or when it is a `prefix/*` wildcard covering the updated
/// literal (or a narrower wildcard under the same prefix).
fn path_matches(approved: &str, updated: &str) -> bool {
    if approved == updated || approved == "*" {
        return true;
    }
    if let Some(prefix) = approved.strip_suffix("/*") {
        if updated == prefix || updated.starts_with(&format!("{prefix}/")) {
            return true;
        }
        // Wildcard-vs-wildcard: `updated` is covered when its own prefix sits
        // at or under the approved prefix.
        if let Some(up) = updated.strip_suffix("/*") {
            return up == prefix || up.starts_with(&format!("{prefix}/"));
        }
    }
    false
}

/// Every declared list of `broker` must be a subset of the same list on some
/// approved broker of the same kind.
fn broker_covered(approved: &[LocalBroker], broker: &LocalBroker) -> bool {
    approved.iter().any(|a| {
        a.broker == broker.broker
            && subset(&a.bus_names, &broker.bus_names)
            && subset(&a.interfaces, &broker.interfaces)
            && subset(&a.methods, &broker.methods)
            && subset(&a.hosts, &broker.hosts)
            && subset(&a.executables, &broker.executables)
            && subset(&a.argument_patterns, &broker.argument_patterns)
            && subset(&a.applications, &broker.applications)
    })
}

fn subset(approved: &[String], updated: &[String]) -> bool {
    let set: BTreeSet<&String> = approved.iter().collect();
    updated.iter().all(|u| set.contains(u))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::fixtures::VLC;

    fn base() -> Manifest {
        Manifest::parse(VLC).unwrap()
    }

    fn cap(s: &str) -> CapabilityId {
        s.parse().unwrap()
    }

    #[test]
    fn an_identical_update_needs_nothing() {
        assert!(reapproval_needed(&base(), &base()).is_empty());
    }

    #[test]
    fn a_new_capability_blocks_the_update() {
        let updated = Manifest::parse(&VLC.replace(
            "  - id: media.seek",
            "  - id: media.seek\n  - id: media.stop",
        ))
        .unwrap();
        assert_eq!(
            reapproval_needed(&base(), &updated),
            vec![Reapproval::NewCapability(cap("media.stop"))]
        );
    }

    #[test]
    fn a_new_host_a_new_folder_and_a_new_secret_are_each_reported() {
        let yaml = VLC
            .replace(
                "filesystem: { read: [\"user_approved_media_dirs\"] }",
                "filesystem: { read: [\"user_approved_media_dirs\", \"home\"], write: [\"downloads\"] }",
            )
            .replace("network:\n    default: deny\n    hosts: [\"127.0.0.1:8080\"]", "network:\n    default: deny\n    hosts: [\"127.0.0.1:8080\", \"tracker.example.com\"]")
            .replace("[\"vlc_http_password\"]", "[\"vlc_http_password\", \"mail_token\"]");
        let updated = Manifest::parse(&yaml).unwrap();
        assert_eq!(
            reapproval_needed(&base(), &updated),
            vec![
                Reapproval::NewPermission("filesystem.read:home".into()),
                Reapproval::NewPermission("filesystem.write:downloads".into()),
                Reapproval::NewPermission("secret:mail_token".into()),
                Reapproval::NewNetworkHost("tracker.example.com".into()),
            ]
        );
    }

    #[test]
    fn removing_authority_never_needs_approval() {
        let slim = VLC
            .replace("  - id: media.pause\n", "")
            .replace("  filesystem: { read: [\"user_approved_media_dirs\"] }\n", "")
            .replace("  network:\n    default: deny\n    hosts: [\"127.0.0.1:8080\"]\n", "")
            .replace("  auth:\n    - secret: \"vlc_http_password\"\n      scheme: \"basic\"\n      hosts: [\"127.0.0.1:8080\"]\n      methods: [\"GET\"]\n      paths: [\"/requests/*\"]\n", "")
            .replace("  data_classes: [\"personal\"]\n", "")
            .replace("requires: { storage: \">=1\", http: \">=1\" }\n", "");
        let updated = Manifest::parse(&slim).unwrap();
        assert!(reapproval_needed(&base(), &updated).is_empty());
    }

    #[test]
    fn the_ratchet_does_not_forgive_authority_that_was_dropped_and_comes_back() {
        let slim = Manifest::parse(&VLC.replace("  - id: media.pause\n", "")).unwrap();
        assert_eq!(
            reapproval_needed(&slim, &base()),
            vec![Reapproval::NewCapability(cap("media.pause"))]
        );
    }

    #[test]
    fn a_new_auth_scheme_for_an_existing_secret_needs_approval() {
        let yaml = VLC.replace("scheme: \"basic\"", "scheme: \"hmac-sha256\"");
        let updated = Manifest::parse(&yaml).unwrap();
        let needed = reapproval_needed(&base(), &updated);
        assert_eq!(needed.len(), 1, "{needed:?}");
        assert!(
            matches!(&needed[0], Reapproval::NewAuthGrant(g) if g.contains("hmac-sha256") && g.contains("vlc_http_password"))
        );
    }

    #[test]
    fn a_widened_auth_host_method_or_path_needs_approval() {
        // Wider host.
        let yaml = VLC.replace(
            "hosts: [\"127.0.0.1:8080\"]\n      methods",
            "hosts: [\"127.0.0.1:8080\", \"192.168.1.5:8080\"]\n      methods",
        );
        let updated = Manifest::parse(&yaml).unwrap();
        assert!(reapproval_needed(&base(), &updated)
            .iter()
            .any(|r| matches!(r, Reapproval::NewAuthGrant(g) if g.contains("192.168.1.5"))));
        // Wider method.
        let yaml = VLC.replace("methods: [\"GET\"]", "methods: [\"GET\", \"POST\"]");
        let updated = Manifest::parse(&yaml).unwrap();
        assert!(reapproval_needed(&base(), &updated)
            .iter()
            .any(|r| matches!(r, Reapproval::NewAuthGrant(g) if g.contains("POST"))));
        // Wider path: "/requests/*" does not cover "/admin/*".
        let yaml = VLC.replace(
            "paths: [\"/requests/*\"]",
            "paths: [\"/requests/*\", \"/admin/*\"]",
        );
        let updated = Manifest::parse(&yaml).unwrap();
        assert!(reapproval_needed(&base(), &updated)
            .iter()
            .any(|r| matches!(r, Reapproval::NewAuthGrant(g) if g.contains("/admin/*"))));
    }

    #[test]
    fn an_auth_rule_narrowed_to_a_subset_needs_no_approval() {
        // Re-declaring the identical rule is a no-op.
        assert!(reapproval_needed(&base(), &base()).is_empty());
    }

    #[test]
    fn a_new_secret_name_in_auth_needs_approval() {
        let yaml = VLC
            .replace("[\"vlc_http_password\"]", "[\"vlc_http_password\", \"exchange_key\"]")
            .replace(
                "      paths: [\"/requests/*\"]\n",
                "      paths: [\"/requests/*\"]\n    - secret: \"exchange_key\"\n      scheme: \"hmac-sha256\"\n      hosts: [\"127.0.0.1:8080\"]\n      methods: [\"POST\"]\n      paths: [\"/orders\"]\n",
            );
        let updated = Manifest::parse(&yaml).unwrap();
        let needed = reapproval_needed(&base(), &updated);
        assert!(
            needed.contains(&Reapproval::NewPermission("secret:exchange_key".into())),
            "{needed:?}"
        );
        assert!(needed
            .iter()
            .any(|r| matches!(r, Reapproval::NewAuthGrant(_))));
    }

    #[test]
    fn a_new_data_class_needs_approval_and_removing_one_does_not() {
        let yaml = VLC.replace(
            "data_classes: [\"personal\"]",
            "data_classes: [\"personal\", \"financial\"]",
        );
        let updated = Manifest::parse(&yaml).unwrap();
        assert_eq!(
            reapproval_needed(&base(), &updated),
            vec![Reapproval::NewDataClass(DataClass::Financial)]
        );
        // Removing the only declared class is removing authority.
        let yaml = VLC.replace("  data_classes: [\"personal\"]\n", "");
        let updated = Manifest::parse(&yaml).unwrap();
        assert!(reapproval_needed(&base(), &updated).is_empty());
    }

    #[test]
    fn a_changed_runtime_needs_approval() {
        let yaml = VLC.replace("runtime: \"process\"", "runtime: \"wasm\"");
        let updated = Manifest::parse(&yaml).unwrap();
        assert_eq!(
            reapproval_needed(&base(), &updated),
            vec![Reapproval::ChangedRuntime(crate::manifest::Runtime::Wasm)]
        );
    }

    #[test]
    fn a_new_or_widened_local_broker_needs_approval_but_a_subset_does_not() {
        let with_broker = VLC.replace(
            "  data_classes: [\"personal\"]\n",
            "  data_classes: [\"personal\"]\n  local:\n    - broker: dbus\n      bus_names: [\"org.videolan.vlc\"]\n      interfaces: [\"org.videolan.VLC\"]\n      methods: [\"org.videolan.VLC.play\"]\n",
        );
        let approved = Manifest::parse(&with_broker).unwrap();
        assert!(reapproval_needed(&base(), &approved)
            .iter()
            .any(|r| matches!(r, Reapproval::NewLocalBroker(_))));

        // Identical broker: no reapproval.
        assert!(reapproval_needed(&approved, &approved).is_empty());

        // Narrower broker (fewer methods): still covered, no reapproval.
        // Approved declares two methods; the update keeps one.
        let two = with_broker.replace(
            "methods: [\"org.videolan.VLC.play\"]",
            "methods: [\"org.videolan.VLC.play\", \"org.videolan.VLC.pause\"]",
        );
        let approved2 = Manifest::parse(&two).unwrap();
        let one = two.replace(", \"org.videolan.VLC.pause\"", "");
        let updated2 = Manifest::parse(&one).unwrap();
        assert!(reapproval_needed(&approved2, &updated2).is_empty());

        // Widened: a second bus name needs approval.
        let wider = two.replace(
            "bus_names: [\"org.videolan.vlc\"]",
            "bus_names: [\"org.videolan.vlc\", \"org.gnome.Nautilus\"]",
        );
        let updated3 = Manifest::parse(&wider).unwrap();
        assert!(reapproval_needed(&approved2, &updated3)
            .iter()
            .any(|r| matches!(r, Reapproval::NewLocalBroker(_))));
    }
}
