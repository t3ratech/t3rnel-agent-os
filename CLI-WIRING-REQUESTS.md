# CLI / server wiring requests (owner-reserved areas — do NOT edit crates/t3rnel-cli)

## Plugin admin REST routes (9.7) — WIRED (server.rs)

DONE in `crates/t3rnel-api/src/server.rs` (`build_router`): the
`plugin_admin::router` is merged into the axum app after `.with_state(state)`
(the plugin router carries its own `PluginAdminState`; axum only merges
identical state types). The auth → GCRA rate-limit → security-headers →
request-logging middleware stack is re-applied to the plugin router.

Config fields added to `KernelConfig` (`crates/t3rnel-types/src/config.rs`):
- `plugin_trusted_signers: Vec<String>` — hex pubkeys OR paths to files
  containing a pubkey (resolved in `server.rs::resolve_plugin_trusted_signers`)
- `plugin_dev_mode: bool` (default false) — enables unsigned installs and
  turns on the extremely-loud dev-mode warnings (boot banner, per-install
  WARN log, `plugin.dev_mode.*` audit events in both the plugin audit table
  and the main Merkle audit chain, `dev_mode`/`dev_mode_warning` fields in
  `GET /api/plugins`, `/api/status`, `/api/health/detail`, `/api/sentinel`).

Endpoints live: `GET /api/plugins`, `POST /api/plugins/install`,
`GET|DELETE /api/plugins/{id}`, `POST /api/plugins/{id}/update`,
`POST /api/plugins/{id}/rollback`, `GET /api/plugins/{id}/launch-check`.

NOTE: a `dev_mode: true` flag in the install/update request body is now only
honoured when the HOST runs `plugin_dev_mode` — previously any client could
relax signature checks (fixed).

## Per-account plugin binding (9.7 addendum)

`PluginManifestLite.entitlement_account` (inside the signed manifest bytes)
binds a package to `local_plugin_account_fingerprint(home)`
(`crates/t3rnel-runtime/src/plugin_lifecycle.rs`) — a SHA-256 over a
domain-separated per-install key at `<home>/plugin-account.key` plus the
canonical home path. Raw key material is never exposed. Mismatch →
`LifecycleError::AccountBinding`, enforced even in dev mode. The signer
computes the fingerprint on the target machine (or the plugin author ships a
per-customer manifest) and embeds it before signing.

## CLI commands to add (crates/t3rnel-cli — owner reserved)

- `t3rnel plugin install <path> [--dev]` → POST /api/plugins/install
- `t3rnel plugin list` → GET /api/plugins
- `t3rnel plugin update <path>` → POST /api/plugins/{id}/update
- `t3rnel plugin rollback <id>` → POST /api/plugins/{id}/rollback
- `t3rnel plugin remove <id>` → DELETE /api/plugins/{id}
- `t3rnel plugin run <id>` (9.8 dev loop) → spawns confined process via
  `plugin_sandbox::scoped_argv` + `confined_command`
- `t3rnel plugin dev <dir>` (9.8) → unsigned dev-mode install + watch

## Plugin signing CLI commands to add (crates/t3rnel-cli — owner reserved)

The signing pipeline exists as a LIBRARY (`t3rnel_runtime::plugin_sign`)
plus `cargo run -p xtask -- plugin-keygen|plugin-sign` today; expose it in
the real CLI:

- `t3rnel plugin keygen --dir <dir>` → `ReleaseSigner::generate` — writes
  `release-signing.key` (0600) + `release-signing.pub`; prints the pubkey
  for `plugin_trusted_signers`.
- `t3rnel plugin sign --src <plugin-src-dir> --out <pkg-dir> --key <key-file>
  [--account-home <t3rnel-home>]` → `package_plugin` — parses
  `manifest.yaml`, writes `manifest.json` + payload + `signature.bin` +
  `signer.pub`; `--account-home` binds `entitlement_account` to that home's
  fingerprint before signing.

## gRPC plugin dispatch (blocked)

`proto/t3rnel/plugin/v1/plugin.proto` compiles (`buf build` passes;
`buf`/`protoc` installed at `/mnt/ext4_work/tools/bin` — see
NEEDS-FROM-TOOLS.md for the lint baseline). Next: run `buf generate`
(needs `protoc-gen-es` for the TS client) to produce tonic stubs, then
implement the dispatch layer that routes plugin callback streams to
`PluginHost`/`PluginServices`.
