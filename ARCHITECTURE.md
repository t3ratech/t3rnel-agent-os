# T3rnel Agent OS — Architecture

T3rnel is an open-source Agent Operating System written in Rust. This document
describes the public core: the daemon, agent runtime, memory, skills, MCP
integrations, channels, and the App Bridge permission layer.

## 1. Design principles

- **Truth rule.** The system reports only what it can verify. UI surfaces,
  health endpoints and agent claims distinguish measured state from aspiration.
- **Fail-fast contract.** Invalid configuration, missing credentials and
  policy violations fail loudly at the boundary rather than silently degrading.
- **Sandbox first.** Agents run tool calls inside a subprocess sandbox with an
  egress guard; every outbound request passes one chokepoint.
- **License.** GPL-3.0-or-later.

## 2. Workspace layout

| Crate | Responsibility |
|---|---|
| `t3rnel-types` | Shared types and configuration schema |
| `t3rnel-wire` | Wire protocol types between services |
| `t3rnel-prompts` | Prompt templates and frontmatter schema |
| `t3rnel-memory` | Persistent memory: store, event log, consolidation, export |
| `t3rnel-runtime` | Agent loop, model drivers, tool policy, subprocess sandbox, egress guard/taint |
| `t3rnel-kernel` | Orchestration kernel: agent lifecycle, scheduling, approvals, trust propagation |
| `t3rnel-api` | HTTP/WebSocket/gRPC server, dashboard static assets |
| `t3rnel-cli` | `t3rnel` binary: `start`, agent/skill/memory commands |
| `t3rnel-mcp` | MCP transport and server support |
| `t3rnel-skills` | Skill loader, installer, registry, marketplace client |
| `t3rnel-hands` | Curated capability packages ("Hands") |
| `t3rnel-extensions` | Integration registry (bundled MCP templates), credential vault (AES-256-GCM), OAuth2 PKCE, health monitor |
| `t3rnel-channels` | Chat-channel adapters (Slack, Discord, Matrix, email, WhatsApp, Telegram) |
| `t3rnel-eval` | Evaluation harness and golden tasks |
| `t3rnel-migrate` | Config/data migrations |
| `t3rnel-social` | Social publishing transports |
| `bridge` | App Bridge: capability risk classes, plugin manifests, permission engine, update ratchet, hash-chained audit log |

`agents/` holds the bundled agent templates embedded into `t3rnel-cli` at
compile time via `include_str!` — the directory must exist for the build.

## 3. System topology

```
 clients (web dashboard / mobile / desktop / IDE / CLI)
        │  HTTP · WebSocket · gRPC
        ▼
   t3rnel-api ──────────────┐
        │                   │
        ▼                   ▼
   t3rnel-kernel        t3rnel-memory (SQLite + event store)
        │
        ▼
   t3rnel-runtime ── model drivers (OpenAI/Anthropic/Gemini/Groq/NIM/…)
        │
        ├── t3rnel-skills / t3rnel-hands   (capability packages)
        ├── t3rnel-extensions              (MCP integrations + vault)
        ├── t3rnel-channels                (chat surfaces)
        ├── subprocess sandbox + egress guard (tool execution boundary)
        └── bridge                         (App Bridge policy for app connectors)
```

## 4. Agent runtime

The runtime drives the agent loop: assemble context (memory recall, skills,
prompts), call the model through a provider driver with fallback chains,
execute tool calls under `tool_policy`, and meter cost against budgets.
Subprocess execution is sandboxed (`subprocess_sandbox`, `docker_sandbox`)
and all egress passes `egress_guard`/`egress_taint` so untrusted content
cannot silently widen what an agent may reach.

## 5. Memory

`t3rnel-memory` provides a persistent store with an append-only event log,
consolidation, per-agent briefs, recall queries, and a vault export format
other tools can grep. Session state lives under `~/.t3rnel` by default
(`T3RNEL_HOME` overrides).

## 6. Skills, Hands, Extensions

- **Skills** (`t3rnel-skills`): `SKILL.md` packages with a loader, installer,
  registry, verification, and a marketplace client. Sixty generic professional
  skills ship bundled in the binary.
- **Hands** (`t3rnel-hands`): curated, domain-complete agent configurations
  activated from a registry — heavier than skills, with schedules, memory and
  dashboard metrics.
- **Extensions** (`t3rnel-extensions`): one-click integrations backed by MCP
  server templates, an AES-256-GCM credential vault with OS keyring support,
  OAuth2 PKCE flows, and a health monitor with reconnect/backoff.

## 7. App Bridge (`bridge/`)

The permission-controlled doorway from agents to applications:

- **capability** — `<domain>.<verb>` capability IDs with a six-level risk
  table (read → write-reversible → write-irreversible → external-effect →
  financial → system) that manifests cannot undercut.
- **manifest** — strict v1 plugin manifest parsing and validation.
- **policy** — per-agent grants, scopes (app / folders), and allow / approve
  / deny decisions.
- **ratchet** — detects which manifest changes force re-approval.
- **audit** — hash-chained record of every bridged call.
- **category** — prohibited / restricted / unrestricted classification.

## 8. Providers and health

Model access is provider-pluggable with free and paid drivers, routing rules,
credential resolution order, per-provider health metrics, token/rate control,
and a circuit-breaker fallback chain so a dead provider degrades gracefully.

## 9. Surfaces

The same kernel serves the web dashboard (Alpine.js SPA in
the desktop, mobile, web and IDE surfaces.

## 10. Repository layout

See the root `README.md` table. `proto/` defines the API contract, `sdk/`
ships JavaScript and Python clients, `xtask` holds developer automation, and
`evals/` contains evaluation tasks and the parity harness.
