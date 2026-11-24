//! T3rnel App Bridge.
//!
//! One permission-controlled doorway from agents to applications (`docs/sections/04-app-bridge-and-connectors.md`,
//! `05-security-and-trust.md`). The daemon alone holds policy; this crate is that policy.
//!
//! * [`capability`] — capability names and the reference risk table no manifest may undercut.
//! * [`manifest`] — the v1 plugin manifest and its validation.
//! * [`policy`] — grants, standing rules and the allow / approve / deny decision.
//! * [`ratchet`] — which manifest changes force a fresh approval.
//! * [`audit`] — the hash-chained record of every call.
//! * [`category`] — prohibited / restricted / unrestricted classification of requests and connectors.

pub mod audit;
pub mod capability;
pub mod category;
pub mod manifest;
pub mod policy;
pub mod ratchet;

/// Locate a plan/spec document by searching `docs/sections/` in every
/// ancestor of this crate. Works both in the monorepo layout (docs at
/// `products/os/docs`, sibling of `t3rnel-agent-os`) and when the sections
/// are vendored at the repository root.
#[cfg(test)]
pub(crate) fn spec_section(file: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in manifest_dir.ancestors() {
        let candidate = dir.join("docs/sections").join(file);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "spec section {file} not found in any docs/sections above {}",
        manifest_dir.display()
    );
}
