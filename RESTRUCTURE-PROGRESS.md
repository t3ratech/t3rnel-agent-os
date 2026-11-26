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
  (AuthRule+AuthScheme: bearer/header/basic/query-key/hmac-sha256),
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
  (bearer/header/basic/query-key/hmac-sha256 — real HMAC chains),
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
  CLI-WIRING-REQUESTS.md. 1 route test passes.
  **WIRED (session 11)**: `server.rs::build_router` merges the plugin router
  post-`.with_state` (own `PluginAdminState`) and re-applies auth → GCRA →
  security-headers → request-logging. New `KernelConfig` fields
  `plugin_trusted_signers: Vec<String>` (hex or file path, resolved in
  server.rs) and `plugin_dev_mode: bool` (default false). Dev mode is
  EXTREMELY LOUD: multi-line `DEV_MODE_BOOT_WARNING` at boot, per-install
  WARN banner via `dev_mode_banner()`, `plugin.dev_mode.{install,update}`
  events in both the plugin audit table and the main Merkle chain
  (`AuditAction::PluginLifecycle`), and `dev_mode`/`dev_mode_warning`
  surfaced in `GET /api/plugins`, `/api/status`, `/api/health/detail`,
  `/api/sentinel`. SECURITY FIX: request-body `dev_mode:true` is now only
  honoured when the host runs `plugin_dev_mode` (was: any client could
  bypass signatures). Per-account binding added:
  `PluginManifestLite.entitlement_account` vs
  `local_plugin_account_fingerprint(home)` (SHA-256 over
  `<home>/plugin-account.key` + canonical home path; raw key never exposed)
  → `LifecycleError::AccountBinding`, enforced even in dev mode.
  Verified live: scratch T3RNEL_HOME daemon on :47891, unsigned dev install
  via POST /api/plugins/install returned `dev_mode:true, signed:false` and
  both audit trails recorded `plugin.dev_mode.install`. 10 lifecycle +
  2 config + 1 route tests pass; clippy -D warnings clean on all 4 crates.
  STILL OPEN: gRPC dispatch; `t3rnel plugin` CLI (owner).
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

## Session 12 additions — signed-plugin pipeline proven end-to-end (dev_mode OFF)

- **Signing tooling**: new `crates/t3rnel-runtime/src/plugin_sign.rs` —
  the missing half of the pipeline (lifecycle only *verifies*). Library
  API: `ReleaseSigner::generate/load/pubkey_hex/sign_package_dir`,
  `build_package` (manifest.yaml → manifest.json + payload copy + exec
  bit), `package_plugin` (build → optional `entitlement_account` binding
  via `local_plugin_account_fingerprint(account_home)` → sign the exact
  manifest.json bytes → signature.bin + signer.pub). Source schema is
  strict (`deny_unknown_fields`); `__pycache__`/`*.pyc`/manifest files are
  excluded from payload. 7 unit tests: sign→verify→install roundtrip with
  `dev_mode:false`, tamper→Signature reject, unsigned→Signature reject,
  wrong-home→AccountBinding, untrusted signer→Signature, keygen
  overwrite refusal + load roundtrip, bad yaml/missing entry.
- **xtask**: `cargo run -p xtask -- plugin-keygen --dir <dir>` and
  `plugin-sign --src <dir> --out <dir> --key <key> [--account-home <home>]`.
  NOT in t3rnel-cli (owner-reserved) — CLI equivalents requested in
  CLI-WIRING-REQUESTS.md.
- **Reference plugins signed as PIPELINE PROOF ONLY** (Python v0.1
  scaffolding — operator decided no Python plugins ship; these packages
  in `/mnt/ext4_work/scratch/plugin-proof/packages/` are NOT shippable):
  research, trading, hand-pack all built+signed+account-bound to scratch
  home-a. Release keypair generated at
  `/mnt/ext4_work/scratch/plugin-proof/keys/` (throwaway proof key —
  real release-key custody is TUF/isolation/transparency-log work per
  guide §14.11, still future).
- **Live verification, dev_mode OFF** (scratch T3RNEL_HOMEs, real
  `target/debug/t3rnel start` daemons, `plugin_dev_mode` unset → false,
  `plugin_trusted_signers=[release pubkey]`):
  - POST /api/plugins/install ×3 → **HTTP 201**, `signed:true`,
    `dev_mode:false`, `account_bound:true`, correct signer hex.
  - Tampered manifest.json (version bump post-sign) → **403**
    `ed25519 verify failed`.
  - Unsigned package → **403** `signature.bin missing`; same with
    `"dev_mode":true` in the request body → still **403** (host dev_mode
    OFF ignores the flag — the b6a7776 fix holds).
  - Same account-bound package installed on a DIFFERENT T3RNEL_HOME →
    **403** `entitlement_account mismatch` (AccountBinding).
  - `GET /api/plugins` on home-a lists all 3; `dev_mode:false`, no
    dev_mode_warning; daemon logs contain zero DEV MODE banners.
- **Fix shipped with the proof**: `plugin_admin::err` mapped
  `AccountBinding` to HTTP 500 (catch-all) — now **403 Forbidden** like
  Signature/Revoked; new route test
  `account_binding_maps_to_forbidden` asserts status+body. Verified live
  (was 500, now 403).
- **buf/protoc unblocked**: `/mnt/ext4_work/tools/bin/{buf,protoc}`
  (buf 1.47.2, libprotoc 29.3). `buf build` PASSES — plugin.proto
  compiles, WKTs resolve. `buf lint` baseline = 81 STANDARD naming
  findings (Service-suffix/RPC naming) — expected on the pre-freeze
  draft; recorded in NEEDS-FROM-TOOLS.md (now resolved). `buf generate`
  still needs `protoc-gen-es` for the TS client.
- Checks: `cargo check`/`test -p t3rnel-runtime plugin_sign` (7 pass)/
  `test -p t3rnel-api plugin_admin` (2 pass)/`clippy -p t3rnel-runtime
  -p xtask -p t3rnel-api --all-targets -D warnings` clean; rustfmt on
  touched files only; stub_gate 0 on touched files; test binaries
  deleted; scratch daemons stopped; live `~/.t3rnel` daemon untouched.
- STILL OPEN: `t3rnel plugin` CLI (owner), gRPC dispatch via buf
  generate + tonic, release-key custody (TUF §14.11), real (non-Python)
  reference plugin implementations.

## Section 18 core — conversations / approvals / briefings (verified + completed 2026-11-25)

Prior agent's uncommitted work verified, gaps fixed, proven live on a
scratch `T3RNEL_HOME` daemon (port 14321; live `~/.t3rnel` daemon on
50051 untouched, no commits made).

**What was already there:** `conversations.rs` (inbound router,
approval binding w/ policy re-check + single-use + expiry + defer cap,
notification fan-out w/ templates/quiet-hours/rate limits, thread
store), `channels.rs` (`ChannelAdapter` trait, `ChannelRegistry`,
`BrokeredCreds` vault-scoped resolution, `LocalChannel`), `briefing.rs`
(collect→compile→deliver→store, UNREACHABLE-on-timeout, approval-binding
of ActionRequests, `briefing:<date>` memory key), `plugin_auth.rs`
(scoped `authref:` tokens, scope-subset enforcement, TTL caps, vault
refresh), proto `BriefingReport`/`BriefingQuery`/`StatusQuery`/
`StatusReport`/`Auth`, API routes + `PendingApprovalPort` over the
pending-actions ledger.

**Fixed this session:**
- `briefing.rs`: plugin queries were SEQUENTIAL — spec §5.3 requires
  parallel; both `run()` collect and `collect_status()` now use
  `futures::future::join_all` (order preserved).
- `server.rs`: adapters were never connected and no inbound loop
  existed — `connect_all()` now runs at router build (per-account
  failures logged) and a 5s `poll_all()`→`handle_inbound` task feeds
  the router. Without this every send failed `NotConnected`.
- **Route collision (live-caught)**: `/api/channels` GET already
  belonged to the legacy channel-config surface → axum panicked
  "Overlapping method route" at boot. Conversation channel routes moved
  to `/api/conversations/channels*`; tests updated.
- `plugin_host.rs`: `PluginHost::auth()` exposes `ScopedTokenService`
  over the host vault (the §8 host-service seam for the future gRPC
  dispatch).
- `t3rnel-api/Cargo.toml`: added `zeroize` dev-dep (test fixture).
- api `conversations.rs`: briefing 404s map to NOT_FOUND (was 500);
  test fixture `set_vault` ordering fixed for `Arc<ChannelRegistry>`;
  clippy fixes (needless borrow, map-identity, field-reassign).
- clippy `-D warnings` clean on both crates; `#[allow(too_many_arguments)]`
  on `deliver_approval`/`bind_action` per repo convention; single_match
  refactored to `if`.

**Live proof (scratch daemon, `T3RNEL_HOME=/tmp/t3rnel-conv-uG9j`):**
- `GET /api/conversations/channels` + `/accounts` → local:dashboard
  adapter + linked account (secret_names only).
- `POST /inbound` "hello" → thread created; `GET /threads` shows it.
- `POST /approvals/deliver` (no ref) → registered real `P-1` in
  pending-actions, binding `AB-000002` delivered via connected local
  channel.
- `POST /inbound` "YES" → `ApprovalDecided`; binding `approved`;
  `pending-actions.json` shows `P-1 state=approved decided_by=
  local:dashboard:...`; second "YES" falls through to agent route
  (single-use proven).
- `POST /api/conversations/notify` → `{"Ok":null}` delivery.
- `POST /api/briefing/run` → doc with core section (pending_approvals
  metric from live ledger); `GET /api/briefing/latest|/{date}` 200,
  missing date → 404; `GET /api/briefing/status` OK.
- Audit chain (`audit_entries` table) records `Conversation` actions:
  `approval.deliver`, `approval.decide ... via=local:dashboard:...`,
  `notify.deliver ... corr=Some("briefing:2026-11-25")` — all hashed.
- Briefing persisted to `briefings/2026-11-25.json` AND unified memory
  `briefing:2026-11-25` (verified in `unified_records`).

**Checks:** `cargo check`/`clippy -p t3rnel-runtime -p t3rnel-api
--all-targets -D warnings` clean; `cargo test -p t3rnel-runtime --lib`
filtered (conversations|channels|briefing|plugin_auth) 21 pass;
`cargo test -p t3rnel-api --lib conversations` 6 pass; `buf build` OK;
`buf lint` new findings match the recorded STANDARD naming baseline;
`protoc -Iproto -I/mnt/ext4_work/tools/include` descriptor OK;
rustfmt edition-2021 on touched files; stub_gate 0 on all touched
files; test binaries deleted; scratch daemon stopped.

**Still open (not this task):** no real channel adapters yet (whatsapp
wrap is §7 step 4); gRPC tonic dispatch for `BriefingQuery`/
`StatusQuery`/`Auth` pending buf generate; `RoutedInbound::AgentMessage`
resolution returns the target but no agent-dispatch consumer yet;
briefing approval bindings target only the first linked account.

## WhatsApp ChannelAdapter — spec §7 step 4 (2026-11-25, uncommitted)

First real `ChannelAdapter` impls behind the §3 contract, wrapping the
existing Baileys gateway + Cloud API surface. No commits/pushes.

**New code**
- `crates/t3rnel-runtime/src/channels/whatsapp.rs` (+ `channels/whatsapp/tests.rs`):
  - `WhatsAppAdapter` (`"whatsapp"`) — personal/QR mode. `connect` resolves
    the gateway URL (explicit > `GatewayStarter` closure wired to
    `t3rnel_kernel::whatsapp_gateway::ensure_gateway_running` >
    `WHATSAPP_WEB_GATEWAY_URL`), health-checks `/health`, reads `/linked`,
    and retains declared vault secrets zeroized. Session creds = gateway
    `auth_store` (never vault, never plugin-visible). `send` →
    `POST /message/send` (+ `/file`, `/notify` image for attachments);
    `poll_inbound` → `GET /inbound/events?since=` normalized to
    `ConversationEvent` (channel `whatsapp`, thread key = chat id/group JID
    or DM phone, tainted `untrusted`/`personal` provenance, media
    placeholders → attachment handles). `needs_linking` state machine:
    `Offline | NeedsLinking | Linked | Connected`; sends fail with an
    actionable QR-flow error until linked. Capabilities: text+media
    (inbound placeholders, file/image outbound), threads (groups), no
    buttons, no receipts.
  - `WhatsAppBusinessAdapter` (`"whatsapp-business"`) — Cloud API mode:
    vault-brokered `*:access-token` / `*:verify-token` /
    `*:phone-number-id` secrets (declared via `secret_names` on the linked
    account), send via `graph.facebook.com/v21.0/{pnid}/messages` (4096-char
    chunking, https-link media), inbound via Meta webhook POSTs normalized
    into shared `BusinessWebhookState` (bounded 1024 queue) drained by
    `poll_inbound`. `is_configured()` fails the webhook closed until
    connect resolves credentials.
- `packages/whatsapp-gateway/index.js`: bounded inbound ring
  (`recordInboundEvent`, clock-seeded monotonic `seq` surviving restarts),
  every authorized inbound message buffered pre-routing; new loopback-only
  `GET /inbound/events?since&limit` returning `{events, latest, linked,
  connected, number}`. `node --check` + 23 gateway unit tests pass.
- `crates/t3rnel-api/src/conversations.rs`: registers both adapters in
  `build_conversation_stack` (personal always — starter wired to kernel;
  auto-links account `whatsapp:default` when `[channels.whatsapp]` is
  configured OR `whatsapp-gateway/auth_store/creds.json` exists, since the
  QR flow predates the registry; business when `phone_number_id` set, no
  auto-link). New `ConversationState.whatsapp_business` + routes
  `GET|POST /api/conversations/channels/whatsapp-business/webhook`
  (verify-token handshake + payload ingest, fail-closed).
- `crates/t3rnel-runtime/Cargo.toml`: `axum` dev-dep for mock-server tests.

**Checks:** `cargo check`/`clippy -p t3rnel-runtime -p t3rnel-api
--all-targets -D warnings` clean (scoped systemd-run, -j1);
`cargo test -p t3rnel-runtime --lib channels::whatsapp` 10/10 pass;
`cargo test -p t3rnel-api --lib conversations` 6/6 pass; rustfmt
edition-2021 on touched files; no stub markers; test binaries deleted.

**Left / known gaps:**
- Gateway still forwards messages to agents directly (`forwardToT3rnel`)
  AND the adapter now surfaces the same messages as ConversationEvents —
  double-processing until the legacy forward path is retired or gated.
- Inbound media is placeholder text + message-id handle only; the gateway
  has no media-download endpoint yet.
- `/inbound/events` seq is clock-seeded per boot; buffer is in-memory so a
  gateway restart drops undelivered events (cursor still consistent).
- Business webhook has no `X-Hub-Signature-256` validation (no app-secret
  config exists); verify-token handshake + loopback bind are the current
  trust anchors — add app-secret signing before exposing publicly.
- Live gateway smoke not run (needs `npm install` of baileys; unit tests
  cover the HTTP contract against a mock).
- Telegram adapter is §7 step 5+ (not this task).

## Session 13 additions — gRPC dispatch landed + consent/agent-consumer wiring (uncommitted)

- **gRPC/tonic dispatch (blocker 1, core side DONE)**: `crates/t3rnel-runtime/build.rs`
  runs `tonic-build` via `protoc-bin-vendored` (no system protoc needed) over
  `proto/t3rnel/plugin/v1/plugin.proto`. `src/plugin_grpc.rs` (~2000 ln)
  implements all 14 host services on one `PluginHostGrpc` struct +
  `PluginDispatch::serve(Arc<Self>, addr)`; per-plugin `PluginRuntime`
  (PluginHost + RouteRegistry + tool/view maps) keyed by signed manifest id,
  `manifest_digest` verified byte-for-byte, `x-plugin-id`/`x-plugin-callback`
  metadata enforced, `PluginCallbacksClient` cached per plugin for
  CallTool/HandleRoute/ScheduleTick/OnEvent/RenderView/Health/BriefingQuery/
  StatusQuery. Storage service got namespaced KV (`ns\x1fkey` encoding),
  authorizer-guarded plugin SQL connection (host tables + ATTACH/PRAGMA
  denied, progress-handler deadline), content-addressed blobs, batched
  migrations with snapshots. `PluginHostConfig` is now built from the
  *signed* manifest `permissions` block (`host_config_from_manifest`,
  `SignedPermissions`/`SignedAuthRule` added to `PluginManifestLite`;
  `plugin_sign.rs` populates it for v1 and lite packages — packages signed
  before the block existed fail closed). LLM/agent seams are honest
  `UNAVAILABLE` until `with_llm`/`with_agent_dispatcher` inject backends.
- **Daemon wiring**: `plugin_grpc_addr` config (default `127.0.0.1:50061`,
  empty disables); `build_router` spawns `PluginDispatch::serve` and stores
  `Arc<PluginDispatch>` on `AppState.plugin_dispatch`.
- **Agent-message consumer (blocker 3, DONE)**: the inbound poll loop now
  handles `RoutedInbound::AgentMessage{agent_id:Some}` — resolves the bound
  agent (name or UUID via `routes::resolve_agent_id`, now `pub(crate)`),
  runs `send_message_with_handle_and_blocks`, and sends the reply back
  through `ConversationService::send_message` on the same channel/thread.
- **OAuth consent → store_grant (blocker 2, mechanics DONE)**:
  `t3rnel-extensions/src/oauth.rs` split `run_pkce_flow` into
  `begin_pkce_flow` (returns auth_url + StartedPkceFlow), `exchange_code`
  and `finish_pkce_flow`. `plugin_admin.rs` adds `POST /api/plugins/oauth/
  {start,complete}` + `GET /status?provider=` — start returns the auth URL
  and spawns background callback→exchange→`ScopedTokenService::store_grant`
  (vault `oauth:<provider>`); complete finishes explicitly with a code
  (mock/non-browser path). Grants then resolve through `Auth.Token` /
  `oauth-access:<provider>` proxy injection.
- **Checks**: `cargo check -p t3rnel-api` (incl. runtime/extensions/types)
  clean; rustfmt edition-2021 on all touched files. Clippy + live gRPC
  smoke still running at report time — see FINAL-REPORT.md.

**Still open**: plugin-side `GrpcHostClient` in `plugins/plugin-core`
(comms `main.rs` `T3RNEL_PLUGIN_ADDR` swap); WhatsApp gateway
`GET /media/:id` + adapter attachment resolution; `X-Hub-Signature-256`
app-secret HMAC on the Business webhook; TUF roles (§14.11); live
daemon proof of dispatch↔plugin binary and oauth mock-provider flow.
