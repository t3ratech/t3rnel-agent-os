# T3rnel Agent OS

T3rnel is an open-source Agent Operating System written in Rust. It runs
LLM-driven agents with memory, skills, sandboxed tool execution, MCP
integrations, and a permission-controlled **App Bridge** for letting agents
operate desktop applications through capability-scoped connectors.

## Workspace layout

| Path | What it is |
|---|---|
| `crates/t3rnel-kernel` | Kernel — agent orchestration, trust/taint tracking |
| `crates/t3rnel-runtime` | Agent loop, model drivers, sandbox, tool policy, egress guard |
| `crates/t3rnel-api` | HTTP/WebSocket/gRPC server and dashboard |
| `crates/t3rnel-cli` | `t3rnel` binary — start the daemon, manage agents/skills |
| `crates/t3rnel-mcp` | MCP transport and server support |
| `crates/t3rnel-memory` | Persistent memory, briefs, recall, export |
| `crates/t3rnel-skills` | Skill loader, installer, registry, marketplace client |
| `crates/t3rnel-hands` | Curated autonomous capability packages ("Hands") |
| `crates/t3rnel-extensions` | Integration registry, credential vault, OAuth, health |
| `crates/t3rnel-channels` | Chat-channel adapters |
| `crates/t3rnel-types` / `t3rnel-wire` / `t3rnel-prompts` / `t3rnel-eval` / `t3rnel-migrate` | Shared types, wire protocol, prompts, evals, migrations |
| `bridge/` | **App Bridge** — capability risk classes, manifest validation, permission engine, update ratchet, audit chain |
| `agents/` | Bundled agent templates (embedded into the CLI at compile time) |
| `sdk/` | Client SDKs (JavaScript, Python) |
| `proto/` | Protobuf / WIT API definitions |
| `xtask` | Developer automation tasks |

## Quick start

```bash
cp .env.example .env   # add at least one LLM provider key
cargo build --workspace
./target/debug/t3rnel start
# API + dashboard: http://127.0.0.1:4200
```

See `ARCHITECTURE.md` for the system design and `./t3rnel-services.sh --help`
for build/test/daemon commands.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
