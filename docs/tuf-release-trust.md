# TUF release trust for plugins — gap analysis (17 §14.11)

Status: **analysis only — no crypto built here.** This document records what
the plugin supply chain has today, what The Update Framework (TUF) would add,
and the precise roles/metadata still needed before public plugin distribution.

## What exists today

| Piece | Where | What it proves |
|---|---|---|
| ed25519 package signing | `plugin_sign.rs`, `plugin_lifecycle.rs` | A package's `manifest.json` + payload files are covered by one signature; `files` map binds every payload file by SHA-256 |
| Signer verification at install | `plugin_lifecycle.rs` (`trusted_keys`, `dev_mode`) | Install/update refuses unknown signers unless `plugin_dev_mode` |
| Per-account entitlement | `PluginManifestLite.entitlement_account` | Signed manifest can pin installs to one machine's account fingerprint |
| Tamper-evident audit | plugin audit table + Merkle chain (`plugin.dev_mode.*` events) | Install/update/rollback events are recorded |
| Dev signer | `plugin_dev.rs` | Local key for development packages |

## What a single signature does NOT give you

1. **No root of trust rotation.** Compromise of the one release key = forge
   anything, forever. There is no threshold, no recovery path.
2. **No compromise recovery.** A leaked key cannot be revoked without every
   client already trusting a *new* key — which requires a channel TUF provides
   (root rotation signed by threshold of root keys).
3. **No transparency.** Clients cannot detect *which* keys signed *which*
   releases historically — a silently swapped release is indistinguishable
   from a legitimate one after the fact.
4. **No timestamping.** Signatures carry no trusted time; rollback to an old
   (vulnerable) signed package is undetectable.
5. **No delegated roles.** One key signs everything: targets, snapshots,
   timestamp. Least-privilege separation (a CI key that can only sign
   targets, never root) is impossible.

## TUF roles needed (per client)

| Role | Key count | Signs | Compromise impact |
|---|---|---|---|
| **root** | ≥3, threshold ≥2 | root.json (delegated roles + key lists) | Catastrophic — rotate via threshold-signed root update |
| **targets** | ≥2, threshold ≥2 | targets.json (package → hash/version map) | Can push bad packages — detected by snapshot/timestamp bounds |
| **snapshot** | 1–2 | snapshot.json (targets.json hash at seq N) | Limits rollback to ≤N targets versions |
| **timestamp** | 1 | timestamp.json (freshness of snapshot) | Can hide *new* releases; cannot forge old ones |

Optional: **delegated target roles** per plugin family (e.g. `community`
plugins signed by a separate, less-trusted key set so a community-key
compromise cannot touch first-party packages).

## Metadata the repository must serve

```
/tuf/
  root.json          — keys + role thresholds + expiry
  targets.json       — plugin id → {version, url, hash(es)}
  snapshot.json      — {meta: {version, hashes}} of targets.json
  timestamp.json     — {meta: {version, expires}} freshness proof
```

Each plugin package additionally needs a signed **targets entry** carrying the
existing `manifest_digest` so install-time verification chains:
`root → targets → package manifest → payload files`.

## What exists vs. what is needed

| TUF requirement | Status |
|---|---|
| ed25519 signing primitive | ✅ exists (`plugin_sign.rs`) |
| Package hash binding | ✅ exists (`files` map + manifest digest) |
| Root role + threshold config | ❌ missing — needs `plugin_trusted_roots` config + root.json parser |
| targets/snapshot/timestamp roles | ❌ missing — repository layout + client fetch/verify loop |
| Expiry + rollback protection | ❌ missing — needs `seq`/`expires` enforcement at install |
| Key transparency / CT-style log | ❌ missing — optional; enables "which key signed what" audit |
| Offline/federated roots | ❌ missing — needed only for multi-publisher model |

## Recommended build order (do NOT half-build crypto)

1. Freeze the TUF repo layout + `tuf.json` client config schema (pure data,
   no crypto decisions).
2. Vendor a reviewed TUF client library (e.g. `tuf`/`tufie` in Rust, or call
   the reference Python implementation behind a narrow FFI — decide before
   writing any verification code).
3. Implement root→targets→package verification as a *single* module with
   the existing `plugin_lifecycle` signature check as the inner leaf —
   do not touch `plugin_sign.rs` until the chain verifies end-to-end.
4. Add threshold + expiry tests before enabling for any non-dev install.
5. Transparency log is a separate workstream — do not block releases on it.

## Non-goals for now

- No TUF metadata signing inside this repo yet (needs the roles above).
- `plugin_trusted_signers` stays the dev-mode mechanism; production installs
   must fail closed until TUF lands.
- WASM/plugin sandbox crypto is unrelated — this doc covers *distribution*
  trust only.
