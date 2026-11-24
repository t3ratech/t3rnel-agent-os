# CLI / server wiring requests (owner-reserved areas — do NOT edit crates/t3rnel-cli)

## Plugin admin REST routes (9.7)

`crates/t3rnel-api/src/plugin_admin.rs` provides `plugin_admin::router(manager, opts)`.
To expose it, in `crates/t3rnel-api/src/server.rs` (or wherever the main
`Router` is assembled), add approximately:

```rust
let plugin_mgr = std::sync::Arc::new(
    t3rnel_runtime::plugin_lifecycle::PluginManager::new(&config.home),
);
let plugin_opts = t3rnel_runtime::plugin_lifecycle::InstallOptions {
    require_signature: !config.dev_mode,
    trusted_keys: config.plugin_trusted_signers.clone(), // new config field
    dev_mode: config.dev_mode,
};
router = router.merge(crate::plugin_admin::router(plugin_mgr, plugin_opts));
```

New config fields needed on the API/kernel config (owner to add):
- `plugin_trusted_signers: Vec<String>` (ed25519 pubkey hex)
- `dev_mode: bool` (already may exist for other dev features — reuse)

Endpoints: `GET /api/plugins`, `POST /api/plugins/install`,
`GET|DELETE /api/plugins/{id}`, `POST /api/plugins/{id}/update`,
`POST /api/plugins/{id}/rollback`, `GET /api/plugins/{id}/launch-check`.

## CLI commands to add (crates/t3rnel-cli — owner reserved)

- `t3rnel plugin install <path> [--dev]` → POST /api/plugins/install
- `t3rnel plugin list` → GET /api/plugins
- `t3rnel plugin update <path>` → POST /api/plugins/{id}/update
- `t3rnel plugin rollback <id>` → POST /api/plugins/{id}/rollback
- `t3rnel plugin remove <id>` → DELETE /api/plugins/{id}
- `t3rnel plugin run <id>` (9.8 dev loop) → spawns confined process via
  `plugin_sandbox::scoped_argv` + `confined_command`
- `t3rnel plugin dev <dir>` (9.8) → unsigned dev-mode install + watch

## gRPC plugin dispatch (blocked)

`proto/t3rnel/plugin/v1/plugin.proto` is written but cannot be compiled —
`buf`/`protoc` are not installed (see NEEDS-FROM-TOOLS.md). Once available:
run `buf generate` to produce tonic stubs, then implement the dispatch layer
that routes plugin callback streams to `PluginHost`/`PluginServices`.
