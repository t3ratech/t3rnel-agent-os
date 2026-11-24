# NEEDS: buf / protoc not installed on this machine

Step R2 §9.1 requires `buf lint` and `buf breaking` for
`proto/t3rnel/plugin/v1/plugin.proto`. Neither `buf` nor `protoc` is installed
(`which buf protoc` finds nothing; `/mnt/ext4_work/tools/bin` does not exist).

The proto file was written by hand following the style of
`proto/t3rnel/v1/t3rnel.proto`, but **it has not been linted or compiled**.
Before freezing the contract:

1. Install `buf` into `/mnt/ext4_work/tools/bin` (owner approval needed per
   guide §5.6 — it must not touch the root disk).
2. Run `buf lint` and `buf breaking --against '.git#branch=main'` in
   `t3rnel-agent-os`.
3. If `cargo check -p t3rnel-api` later fails on missing `protoc`, the owner
   must install it (guide §5.6).

Also note: `google/protobuf/timestamp.proto` and `google/protobuf/empty.proto`
are imported implicitly by buf's standard includes; if the build setup uses a
vendored proto path, confirm both well-known types resolve.
