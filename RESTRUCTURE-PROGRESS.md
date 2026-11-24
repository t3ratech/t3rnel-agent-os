# Restructure progress — working notes (not a spec)

State as of this session. The authoritative spec is
`../docs/sections/17-implementation-guide.md`; read it before continuing.

## Done and verified

- **R1 marketplace repo** (`../t3rnel-marketplace`): workspace `Cargo.toml`,
  `registry-client/` crate compiles against path deps
  `../../t3rnel-agent-os/{crates/t3rnel-skills,bridge}`; `registry_client.rs`
  + `tarball.rs` unchanged, `lib.rs` re-exports `installer`/`verify`/`SkillError`.
  `cargo check`, `cargo test` (15 tests), `cargo clippy -D warnings` all pass.
  `README.md` written; `backend/`+`pipelines/` intentionally absent (no real
  content yet). No commits, no remote — owner action pending (guide C-19).
- **R2 §9.1 proto**: `proto/t3rnel/plugin/v1/plugin.proto` written — 14 host
  services + `PluginCallbacks`, draft (pre-freeze). NOT lint-compiled: `buf`
  and `protoc` missing → `NEEDS-FROM-TOOLS.md` at repo root.
- **R2 §9.2 bridge**: `manifest.rs` gained `plugin.type` (PluginType),
  `min_t3rnel_version`, `targets`, `config_schema`, `permissions.auth`
  (AuthRule+AuthScheme: bearer/header/basic/query-key/hmac-sha256/aws-sigv4),
  `permissions.data_classes` (closed DataClass enum per 05 §14.10),
  `permissions.local` (LocalBroker: dbus/local-http/cli/a11y, per-kind field
  validation), top-level `requires` (HOST_SERVICES keys + version reqs).
  `valid_host` now accepts `host:port`. `ratchet.rs` reapproval covers new
  secret names, auth grants (scheme/host/method/path widening, wildcard-aware),
  data classes, runtime changes, local brokers (subset semantics). Capability
  table already complete (doc-parity test enforces). 76 tests pass; clippy
  clean; fmt applied. NOTE: spec doc `04 §3` example `data_classes` changed
  `"media-metadata"` → `"personal"` to match the §14.10 closed set — flagged
  for owner review.
- **Pre-existing test breakage fixed**: bridge tests referenced
  `bridge/../docs/sections` which doesn't exist in this layout; added
  `crate::spec_section()` ancestor-search helper in `bridge/src/lib.rs`.
- **R2 §9.3 sandbox (partial)**: `crates/t3rnel-runtime/src/plugin_sandbox.rs`
  — REAL confinement, all 7 tests pass on this kernel:
  seccomp-bpf deny-list (socket/socketcall/io_uring/bpf/ptrace/mount/unshare/
  setns/pivot_root/chroot/init_module/finit_module/delete_module/mount_setattr/
  perf_event_open/userfaultfd/open_by_handle_at/name_to_handle_at/quotactl/
  acct/swapon/swapoff/reboot/kexec_*), Landlock ABI-v1 fs restrictions
  (read_write + read_only dir tiers via raw syscalls 444/445/446),
  PR_SET_NO_NEW_PRIVS, env scrub to SAFE_PLUGIN_ENV, `confined_command`
  pre_exec helper, fail-closed `confinement_available()` probe.
  `libc = "0.2"` added to t3rnel-runtime deps. `cargo check`+`clippy` clean.
  cgroup scope: `scoped_argv`/`ResourceLimits`/`cgroup_scope_available` added
  (systemd-run --user --scope MemoryMax/RuntimeMaxSec/TasksMax; 3 tests).
  DONE: `GuestState.plugin_proxy: Option<Arc<PluginProxy>>` — when set,
  `host_net_fetch` routes through the proxy (egress rules + auth schemes,
  proxy refusal before any network I/O), and `host_shell_exec`/`host_env_read`
  refuse outright ("use declared host services"). Non-plugin guests unchanged
  (plugin_proxy=None everywhere by default). 3 new tests prove proxy routing,
  shell/env refusal; all 22 host_functions tests pass. STILL OPEN: gRPC
  plugin stream wiring (tonic; blocked on buf/protoc).

- **R2 §9.4 plugin_proxy (core)**: `crates/t3rnel-runtime/src/plugin_proxy.rs`
  + `plugin_proxy/schemes.rs`. `PluginProxy` validates URL/path/headers/
  framing, enforces egress rules (host incl. host:port + bracketed IPv6,
  methods, path patterns), refuses private/special upstreams incl. IPv6 ULA,
  link-local, CGNAT, NAT64, IPv4-mapped IPv6 — unless `allow_private` declared;
  resolves DNS via tokio and refuses if ANY answer is private. Never follows
  redirects (returns them + `blocked_redirects`). Secrets resolved through
  `SecretResolver` trait (Zeroizing), applied via 6 schemes
  (bearer/header/basic/query-key/hmac-sha256/aws-sigv4 — real HMAC chains),
  response body scanned and echoed secrets replaced with `secret:NAME`.
  19 tests pass incl. live fake-upstream e2e (injected auth verified on the
  wire, secret echo redacted) and redirect non-follow. Clippy clean,
  stub_gate 0. `hmac` dep added to t3rnel-runtime. GAPS: not wired into
  host_functions http service yet; no CredentialVault impl yet (trait seam
  ready); audit events not emitted; proxy errors not yet mapped to proto
  status codes.

## NOT done (remaining work, in guide order)

- ~~9.4 plugin_proxy~~ DONE (see below). Remaining 9.4 gaps: proxy not yet
  wired into the http host service / gRPC stream; vault-backed
  SecretResolver impl (currently ClosureResolver trait only); audit-emission
  hook not yet attached.
- ~~9.5 vault brokering~~ DONE (core): `plugin_vault.rs` — VaultBroker over
  CredentialVault, §14.14 unlock order (host key → dev-only env key →
  interactive reported), T3RNEL_VAULT_KEY refused unless dev_mode, canary
  creds `t3rn:canary:<id>`, `as_resolver()` → SecretResolver, confined-env
  no-secret test. 5 tests pass. `t3rnel-extensions` + `rand` deps added to
  t3rnel-runtime. STILL OPEN: vault-backed resolver not yet injected into a
  running PluginProxy instance (wiring lands with http host service).
- ~~9.6 storage (first service)~~ DONE (core): `plugin_storage.rs` —
  PluginStorage per plugin at `<home>/plugins/<id>/data/plugin.db`,
  validated plugin ids (no traversal), WAL+FK pragmas, host-run migrations
  with `plugin_schema_migrations` bookkeeping + `VACUUM INTO` pre-migration
  snapshots + transactional rollback, plugin_kv, append-only plugin_audit.
  5 tests pass. NEVER exposes substrate usage_conn (separate file per plugin
  by construction). STILL OPEN: remaining 13 services in order
  (audit→http→tools→routes→schedule→events→approval→memory→llm→sentinel→
  ui→agents→notify) and the gRPC dispatch layer that routes plugin calls to
  them.
- ~~9.7 installer/lifecycle~~ DONE (core): `plugin_lifecycle.rs` in
  t3rnel-runtime — PluginManager with install (ed25519 signature verify via
  signature.bin+signer.pub, revocation via home/revoked-signers, trusted-key
  allowlist, dev_mode unsigned), staged update (staging→backup .prev→swap,
  data/ preserved across binary swap, migration+health failure rolls back
  binary AND keeps data), rollback (restores prev binary + newest
  pre-migration storage snapshot), uninstall, list, permissions display in
  InstallReport, health check (entry exists + executable bit), crash
  quarantine (3 crashes/3600s in plugin DB → launch_permitted refuses).
  6 tests pass incl. real ed25519 sign/verify/revoke. `plugin_admin.rs` in
  t3rnel-api — axum router /api/plugins{,/{id},/install,/update,/rollback,
  /launch-check} over PluginManager; mount snippet + CLI command list in
  CLI-WIRING-REQUESTS.md (server.rs mount NOT done — needs owner config
  fields plugin_trusted_signers/dev_mode; documented). 1 route test passes.
  STILL OPEN: server.rs merge line + config fields (owner), gRPC dispatch.
- ~~9.8 plugin dev loop~~ DONE (core): `plugin_dev.rs` — DevSigner
  (ed25519 keypair under <home>/dev-keys/, sign_package writes the same
  signature.bin/signer.pub the lifecycle verifier checks — dev packages pass
  the REAL verify path), DevLoop::dev_install_options (unsigned dev install
  + dev pubkey trusted), check_reload hot-reload decision (manifest bytes +
  entry diff + mtime → Install/Reinstall/Unchanged), assert_dev_secret_name
  gate (only t3rn:canary:*/dev:* provisionable in dev). 3 tests pass.
  STILL OPEN: inotify watcher wiring + `t3rnel plugin dev` CLI (owner).
- 9.9 memory taint permanence + data classes
- 9.10 code mode spike → docs/code-mode-spike.md
- 9.11 reference plugins Research/Trading/hand-pack + parity
- R3 plugin extraction, R4 private-repo reduction, R5 public launch prep

## Cautions for the next session

- `cargo fmt -p <crate>` reformats the WHOLE crate; it touched ~12 unrelated
  runtime files — those were reverted. Format only files you edited
  (`rustfmt <file>`) or expect collateral and revert it.
- Disk is tight (~6 GB free); delete `target/debug/deps` test binaries newer
  than your marker after each crate's test run.
- Never run `cargo test --workspace`; per-crate only, `-j 1`, systemd-run
  scope as in guide §5.1.


## Session 10 additions

- **9.10 code-mode spike**: `docs/code-mode-spike.md` written with REAL
  measured wasmtime numbers (engine 47.9ms, compile 46.6ms, instantiate
  0.44ms, ~2.7µs/call over 100k) via `crates/t3rnel-runtime/tests/
  spike_wasmtime.rs` (test kept — it IS the probe). Decision documented:
  QuickJS→Wasm under wasmtime primary (reuses sandbox fuel/store), rquickjs
  fallback. BLOCKER for build: no quickjs-wasm artifact vendored; evaluate
  quickjs-emscripten dep next.
- **9.11 reference plugins v0.1**: `/mnt/ext4_work/t3rnel/plugins/{research,
  trading,hand-pack}/` — real manifest.yaml (bridge schema) + working
  plugin.py + passing unittest each (5 tests total). PARITY.md documents
  honest status: structural ports, NOT at parity — missing host-service
  wiring, importers, URL parity, manifest-loader validation.
- **R3–R5 handover**: all R2 foundations done. Remaining: gRPC/tonic dispatch
  (buf/protoc), server.rs route merge + config fields (owner), unified_*
  taint columns, Message provenance field, plugin→PluginHost runtime wiring,
  data importers on COPIES, URL parity, private-repo reduction (R4), public
  launch prep (R5).
