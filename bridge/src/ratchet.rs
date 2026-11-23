//! The update ratchet (`05-security-and-trust.md` §5): an update that adds a capability, a permission or a network host
//! is blocked until the user approves it afresh. Removing authority never needs approval.

use std::collections::BTreeSet;

use crate::capability::CapabilityId;
use crate::manifest::Manifest;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
pub enum Reapproval {
    #[error("new capability {0}")]
    NewCapability(CapabilityId),
    #[error("new permission {0}")]
    NewPermission(String),
    #[error("new network host {0}")]
    NewNetworkHost(String),
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
            .chain(p.filesystem.write.iter().map(|s| format!("filesystem.write:{s}")))
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
    out.into_iter().collect()
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
        let updated = Manifest::parse(&VLC.replace("  - id: media.seek", "  - id: media.seek\n  - id: media.stop")).unwrap();
        assert_eq!(reapproval_needed(&base(), &updated), vec![Reapproval::NewCapability(cap("media.stop"))]);
    }

    #[test]
    fn a_new_host_a_new_folder_and_a_new_secret_are_each_reported() {
        let yaml = VLC
            .replace(
                "filesystem: { read: [\"user_approved_media_dirs\"] }",
                "filesystem: { read: [\"user_approved_media_dirs\", \"home\"], write: [\"downloads\"] }",
            )
            .replace("network:    { default: deny }", "network:    { default: deny, hosts: [\"tracker.example.com\"] }")
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
        let slim = VLC.replace("  - id: media.pause\n", "").replace("  filesystem: { read: [\"user_approved_media_dirs\"] }\n", "");
        let updated = Manifest::parse(&slim).unwrap();
        assert!(reapproval_needed(&base(), &updated).is_empty());
    }

    #[test]
    fn the_ratchet_does_not_forgive_authority_that_was_dropped_and_comes_back() {
        let slim = Manifest::parse(&VLC.replace("  - id: media.pause\n", "")).unwrap();
        assert_eq!(reapproval_needed(&slim, &base()), vec![Reapproval::NewCapability(cap("media.pause"))]);
    }
}
