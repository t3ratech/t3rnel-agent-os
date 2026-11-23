//! Compile-time embedded agent templates.
//!
//! All bundled agent templates are embedded into the binary via `include_str!`.
//! This ensures `t3rnel agent new` works immediately after install — no filesystem
//! discovery needed.

/// Returns all bundled agent templates as `(name, toml_content)` pairs.
pub fn bundled_agents() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "analyst",
            include_str!("../../../agents/analyst/agent.toml"),
        ),
        (
            "architect",
            include_str!("../../../agents/architect/agent.toml"),
        ),
        (
            "assistant",
            include_str!("../../../agents/assistant/agent.toml"),
        ),
        ("coder", include_str!("../../../agents/coder/agent.toml")),
        (
            "code-reviewer",
            include_str!("../../../agents/code-reviewer/agent.toml"),
        ),
        (
            "customer-support",
            include_str!("../../../agents/customer-support/agent.toml"),
        ),
        (
            "data-scientist",
            include_str!("../../../agents/data-scientist/agent.toml"),
        ),
        (
            "debugger",
            include_str!("../../../agents/debugger/agent.toml"),
        ),
        (
            "backend-builder",
            include_str!("../../../agents/backend-builder/agent.toml"),
        ),
        (
            "devops-lead",
            include_str!("../../../agents/devops-lead/agent.toml"),
        ),
        (
            "frontend-builder",
            include_str!("../../../agents/frontend-builder/agent.toml"),
        ),
        (
            "doc-writer",
            include_str!("../../../agents/doc-writer/agent.toml"),
        ),
        (
            "email-assistant",
            include_str!("../../../agents/email-assistant/agent.toml"),
        ),
        (
            "health-tracker",
            include_str!("../../../agents/health-tracker/agent.toml"),
        ),
        (
            "hello-world",
            include_str!("../../../agents/hello-world/agent.toml"),
        ),
        (
            "home-automation",
            include_str!("../../../agents/home-automation/agent.toml"),
        ),
        (
            "legal-assistant",
            include_str!("../../../agents/legal-assistant/agent.toml"),
        ),
        (
            "meeting-assistant",
            include_str!("../../../agents/meeting-assistant/agent.toml"),
        ),
        ("ops", include_str!("../../../agents/ops/agent.toml")),
        (
            "planner",
            include_str!("../../../agents/planner/agent.toml"),
        ),
        (
            "recruiter",
            include_str!("../../../agents/recruiter/agent.toml"),
        ),
        (
            "release-manager",
            include_str!("../../../agents/release-manager/agent.toml"),
        ),
        (
            "researcher",
            include_str!("../../../agents/researcher/agent.toml"),
        ),
        (
            "reviewer",
            include_str!("../../../agents/reviewer/agent.toml"),
        ),
        (
            "security-auditor",
            include_str!("../../../agents/security-auditor/agent.toml"),
        ),
        (
            "test-engineer",
            include_str!("../../../agents/test-engineer/agent.toml"),
        ),
        (
            "translator",
            include_str!("../../../agents/translator/agent.toml"),
        ),
        (
            "travel-planner",
            include_str!("../../../agents/travel-planner/agent.toml"),
        ),
        ("tutor", include_str!("../../../agents/tutor/agent.toml")),
        ("writer", include_str!("../../../agents/writer/agent.toml")),
    ]
}

/// Install bundled agent templates to `~/.t3rnel/agents/`.
/// Skips any template that already exists on disk (user customization preserved).
pub fn install_bundled_agents(agents_dir: &std::path::Path) {
    for (name, content) in bundled_agents() {
        let dest_dir = agents_dir.join(name);
        let dest_file = dest_dir.join("agent.toml");
        if dest_file.exists() {
            continue; // Preserve user customization
        }
        if std::fs::create_dir_all(&dest_dir).is_ok() {
            let _ = std::fs::write(&dest_file, content);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use t3rnel_types::agent::AgentManifest;

    #[test]
    fn bundled_phase_one_role_manifests_parse() {
        let agents = bundled_agents();
        let names: HashSet<&str> = agents.iter().map(|(name, _)| *name).collect();
        for required in [
            "architect",
            "backend-builder",
            "frontend-builder",
            "coder",
            "test-engineer",
            "reviewer",
            "security-auditor",
            "doc-writer",
            "release-manager",
        ] {
            assert!(names.contains(required), "missing bundled role: {required}");
        }

        for (name, content) in agents {
            let manifest: AgentManifest =
                toml::from_str(content).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(manifest.name, name);
        }
    }
}
