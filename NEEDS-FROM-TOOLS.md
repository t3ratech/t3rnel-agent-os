# NEEDS-FROM-TOOLS — resolved: buf / protoc now installed

RESOLVED (this session): `buf` 1.47.2 and `protoc` (libprotoc 29.3) are
installed at `/mnt/ext4_work/tools/bin` — add it to PATH
(`export PATH=/mnt/ext4_work/tools/bin:$PATH`) before running buf commands.

Verified against `proto/t3rnel/plugin/v1/plugin.proto`:

- `buf build` — **passes** (exit 0): the proto is well-formed and all
  imports (incl. `google/protobuf/{timestamp,empty}.proto` well-known types)
  resolve via buf's standard includes.
- `buf lint` — **81 findings, all STANDARD naming conventions** on the draft
  contract: service names lack the `Service` suffix (e.g. `Http`, `Storage`,
  `PluginCallbacks`) and RPC request/response types don't follow the
  `<Service><Method>Request/Response` pattern. This is the recorded lint
  BASELINE — the proto is explicitly pre-freeze (draft per §9.1), so these
  are expected. Before freezing the contract either fix the names or add a
  `buf.yaml` lint exception list; do not silently ignore.
- `buf breaking --against '.git#branch=main'` — still to run at freeze time
  (needs a committed baseline; nothing committed yet per owner rule).

Still needed later (not blocking): `protoc-gen-es` for `buf.gen.yaml` TS
client generation — check `which protoc-gen-es` before running `buf generate`.
