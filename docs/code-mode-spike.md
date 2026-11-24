# Code-mode spike — QuickJS/Wasm vs rquickjs (guide §9.10, spec 04 §15)

Status: **spike measured, engine decision documented — build NOT started.**
Date: this session. Host: this workstation (kernel 6.8, wasmtime 44.0.3
already a `t3rnel-runtime` dependency, used by `sandbox.rs`).

## What was actually run

`crates/t3rnel-runtime/tests/spike_wasmtime.rs` — a real wasmtime probe
(engine default config, WAT module `(func (export "add") (param i32 i32)
(result i32) local.get 0 local.get 1 i32.add)`), executed under the
memory-capped cargo scope. Measured output:

```
ENGINE=47.9ms  COMPILE=46.6ms  INSTANTIATE=0.44ms  100k_CALLS=274ms
```

Interpretation:

- Engine creation ~48 ms (one-time per host process — amortised).
- Module compile ~47 ms for a trivial module; a real QuickJS-wasm core is
  ~1–2 MB of wasm and would compile in low hundreds of ms — acceptable for
  a per-plugin or per-session warm start, NOT per-call.
- Instantiate <0.5 ms; typed calls ~2.7 µs each (274 ms / 100k) — fine for
  code-mode tool dispatch where each call is a script run, not a hot loop.

## Feasibility findings

1. **QuickJS→Wasm via wasmtime**: wasmtime 44 is already vendored and the
   sandbox (`plugin_sandbox.rs` + `sandbox.rs`) already runs wasm guests with
   fuel metering — the *host* side exists. The missing piece is a
   **quickjs-wasm artifact**: none is vendored in this repo, and no network
   fetch was performed in this spike. Producing one requires the quickjs-ng
   wasm build (emscripten) or the `quickjs-emscripten` Rust crate, which
   embeds a prebuilt wasm — adding that dependency is a real option and
   should be evaluated next session (it also pulls `rquickjs`-style bindings
   only for the host side; the JS engine itself still runs inside wasmtime
   if the wasm is loaded as a module).
2. **rquickjs fallback**: not currently a dependency anywhere in the
   workspace. It runs JS natively (no wasm sandbox) — acceptable ONLY inside
   the already-confined plugin process (seccomp+Landlock apply to the whole
   process regardless of which JS engine it embeds). Recommendation: prefer
   quickjs-wasm under wasmtime so the JS engine inherits the existing wasm
   fuel/epoch limits; rquickjs is the fallback if the wasm artifact proves
   unmaintainable.
3. **§15.3 acceptance checks** (from spec): deterministic fuel metering —
   wasmtime `Config::consume_fuel` already used by `sandbox.rs`
   (`set_fuel`), epoch interruption available; memory limits via wasm
   `memory64`/store limits + cgroup `MemoryMax` (scoped_argv exists); no
   network — wasm has no sockets by construction and the plugin sandbox
   seccomp-denies `socket` anyway. All three are satisfiable with the
   existing stack; none were blocked by measurement.

## Decision

Proceed with **QuickJS compiled to Wasm, hosted by wasmtime** as primary
(reuses sandbox.rs fuel/store machinery and the plugin confinement), with
**rquickjs inside the confined process** as documented fallback. Next step
before building: vendor or depend on a quickjs-wasm artifact and re-run this
probe against it (compile+instantiate+`js_eval` numbers), then write the
real acceptance numbers into this doc.

## Numbers table (this run)

| Metric | Value |
|---|---|
| Engine::default() | 47.9 ms |
| Module::new (trivial WAT) | 46.6 ms |
| Instance::new | 0.44 ms |
| 100k typed calls | 274 ms (~2.7 µs/call) |

Test binary deleted after run per disk discipline.
