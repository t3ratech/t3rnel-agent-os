//! Scope fence — hardcoded deny-list for self-improvement proposals.
//!
//! Any proposal touching these areas requires human-in-the-loop approval.

use std::path::Path;

/// Paths and patterns that require human approval before modification.
const DENY_LIST: &[&str] = &[
    // Kill-switch logic
    "self_improvement.rs",
    "scope_fence.rs",
    "SELF_IMPROVEMENT_HALT",
    // Audit chain
    "audit.rs",
    "audit_log",
    // Vault encryption
    "vault",
    "credential",
    "encryption",
    "cipher",
];

/// Check if a proposal (represented by changed file paths) breaches the scope fence.
///
/// Returns `Err(breached_paths)` if any path matches the deny-list,
/// or `Ok(())` if the proposal is within scope.
pub fn check_proposal(paths: &[&Path]) -> Result<(), Vec<String>> {
    let mut breached = Vec::new();
    for path in paths {
        let path_str = path.to_string_lossy().to_lowercase();
        for denied in DENY_LIST {
            if path_str.contains(denied) {
                breached.push(path.display().to_string());
                break;
            }
        }
    }
    if breached.is_empty() {
        Ok(())
    } else {
        Err(breached)
    }
}

/// Check if a single path breaches the scope fence.
pub fn path_breaches_fence(path: &Path) -> bool {
    check_proposal(&[path]).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn scope_fence_blocks_audit() {
        let binding = PathBuf::from("crates/t3rnel-kernel/src/audit.rs");
        let paths = vec![binding.as_path()];
        assert!(check_proposal(&paths).is_err());
    }

    #[test]
    fn scope_fence_allows_safe() {
        let binding = PathBuf::from("crates/t3rnel-api/src/routes.rs");
        let paths = vec![binding.as_path()];
        assert!(check_proposal(&paths).is_ok());
    }
}
