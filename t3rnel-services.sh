#!/usr/bin/env bash
# t3rnel-services — single entry point for build, test, lint, daemon and
# client operations. Every operational command goes through this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

# ── Environment ───────────────────────────────────────────────────────────────

load_repo_env() {
  local env_file="${SCRIPT_DIR}/.env"
  [[ -f "${env_file}" ]] || return 0
  local line key value
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    if [[ ${#value} -ge 2 ]]; then
      if [[ "${value:0:1}" == "\"" && "${value: -1}" == "\"" ]]; then
        value="${value:1:${#value}-2}"
      elif [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
        value="${value:1:${#value}-2}"
      fi
    fi
    if [[ -z "${!key:-}" ]]; then
      export "${key}=${value}"
    fi
  done <"${env_file}"
}

if [[ "${T3RNEL_SKIP_REPO_ENV:-0}" != "1" ]]; then
  load_repo_env
fi

# Resource-safe Rust defaults (this project's machines vary; override freely).
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-${T3RNEL_CARGO_JOBS:-4}}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RUSTFLAGS="${RUSTFLAGS:--C debuginfo=0}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"

T3RNEL_LOCAL_DAEMON_HOME="${T3RNEL_LOCAL_DAEMON_HOME:-${HOME}/.t3rnel}"
T3RNEL_LOCAL_DAEMON_PORT="${T3RNEL_LOCAL_DAEMON_PORT:-50051}"
T3RNEL_E2E_DAEMON_PORT="${T3RNEL_E2E_DAEMON_PORT:-50061}"
T3RNEL_WEB_PORT="${T3RNEL_WEB_PORT:-5173}"
T3RNEL_WEB_PID_PATH="${T3RNEL_WEB_PID_PATH:-${TMPDIR:-/tmp}/t3rnel-web.pid}"
T3RNEL_DESKTOP_PID_PATH="${T3RNEL_DESKTOP_PID_PATH:-${TMPDIR:-/tmp}/t3rnel-desktop.pid}"

# ── Helpers ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { printf '%s==>%s %s\n' "${GREEN}" "${NC}" "$*"; }
warn() { printf '%sWARN:%s %s\n' "${YELLOW}" "${NC}" "$*" >&2; }
fail() { printf '%sERROR:%s %s\n' "${RED}" "${NC}" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

require_compose_file() {
  [[ -f "${COMPOSE_FILE}" ]] || fail "missing ${COMPOSE_FILE}"
}

compose_cmd() {
  if have docker && docker compose version >/dev/null 2>&1; then
    printf 'docker compose -f %q' "${COMPOSE_FILE}"
  elif have docker-compose; then
    printf 'docker-compose -f %q' "${COMPOSE_FILE}"
  else
    fail "docker compose is not installed"
  fi
}

run_compose() { require_compose_file; eval "$(compose_cmd) $*"; }

run_cargo() {
  have cargo || fail "cargo is not installed"
  (cd "${SCRIPT_DIR}" && cargo "$@")
}

run_pnpm() {
  have pnpm || fail "pnpm is not installed"
  (cd "${SCRIPT_DIR}" && pnpm "$@")
}

run_gently() {
  if have nice; then
    nice -n 10 "$@"
  else
    "$@"
  fi
}

# ── Build / test / lint ───────────────────────────────────────────────────────

run_build() {
  local profile="${1:-debug}"
  case "${profile}" in
    debug) run_cargo build --workspace ;;
    release) run_cargo build --workspace --release ;;
    *) fail "unknown build profile: ${profile} (debug|release)" ;;
  esac
}

run_release() { run_cargo build --workspace --release; }

run_test() {
  local suite="${1:?usage: --test <suite>}"
  case "${suite}" in
    unit-rust)      run_cargo test --workspace --lib ;;
    unit-rust:*)    run_cargo test --workspace --lib "${suite#unit-rust:}" ;;
    unit-ts)        run_pnpm -r test ;;
    shellcheck)
      have shellcheck || fail "shellcheck is not installed"
      shellcheck -S error "${SCRIPT_DIR}/t3rnel-services.sh"
      [[ -f "${SCRIPT_DIR}/scripts/install.sh" ]] && shellcheck -S error "${SCRIPT_DIR}/scripts/install.sh"
      ;;
    security)       security_scan ;;
    *)              fail "unknown test suite: ${suite} (unit-rust[:filter], unit-ts, shellcheck, security)" ;;
  esac
}

security_scan() {
  if have cargo-audit; then cargo audit; else warn "cargo-audit not installed"; fi
  if have semgrep; then semgrep scan; else warn "semgrep not installed"; fi
  if have cargo && cargo tree 2>/dev/null | grep -iE 'GPL|AGPL|LGPL|SSPL'; then
    fail "copyleft dependency marker detected"
  fi
}

run_lint() {
  run_cargo clippy --workspace --all-targets -- -D warnings
  if have shellcheck; then
    shellcheck -S error "${SCRIPT_DIR}/t3rnel-services.sh"
  else
    warn "shellcheck is not installed; shell lint skipped"
  fi
  if [[ -f package.json ]]; then run_pnpm lint; fi
}

run_format() {
  run_cargo fmt --all
  if [[ -f package.json ]]; then run_pnpm format; fi
}

run_check() { run_cargo check --workspace --all-targets; }

run_migrate() {
  local direction="${1:-status}"
  case "${direction}" in
    up|down|status) run_cargo run -p t3rnel-migrate -- "${direction}" ;;
    *) fail "unknown migration direction: ${direction}" ;;
  esac
}

run_bench() { run_cargo bench --workspace; }

# ── Daemon ────────────────────────────────────────────────────────────────────

local_daemon_health_url() { printf 'http://127.0.0.1:%s/api/health' "${T3RNEL_LOCAL_DAEMON_PORT}"; }
local_daemon_is_healthy() { curl -fsS --max-time 5 "$(local_daemon_health_url)" >/dev/null 2>&1; }

daemon_binary_needs_rebuild() {
  local bin="${SCRIPT_DIR}/target/debug/t3rnel"
  [[ ! -x "${bin}" ]] && return 0
  [[ -n "$(find "${SCRIPT_DIR}/crates" -name '*.rs' -newer "${bin}" -print -quit 2>/dev/null)" ]]
}

start_local_daemon() {
  local bin="${SCRIPT_DIR}/target/debug/t3rnel"
  [[ -x "${bin}" ]] || { info "Building daemon"; run_build debug; }
  if local_daemon_is_healthy; then
    info "Daemon already healthy on :${T3RNEL_LOCAL_DAEMON_PORT}"
    return 0
  fi
  info "Starting daemon on :${T3RNEL_LOCAL_DAEMON_PORT} (home: ${T3RNEL_LOCAL_DAEMON_HOME})"
  T3RNEL_HOME="${T3RNEL_LOCAL_DAEMON_HOME}" \
    "${bin}" start --port "${T3RNEL_LOCAL_DAEMON_PORT}" &
  local pid=$!
  echo "${pid}" > "${TMPDIR:-/tmp}/t3rnel-daemon.pid"
  for _ in $(seq 1 30); do
    sleep 1
    local_daemon_is_healthy && { info "Daemon healthy: $(local_daemon_health_url)"; return 0; }
  done
  fail "Daemon did not become healthy; check logs"
}

stop_local_daemon() {
  local pid_file="${TMPDIR:-/tmp}/t3rnel-daemon.pid"
  if [[ -f "${pid_file}" ]]; then
    local pid; pid="$(cat "${pid_file}")"
    kill "${pid}" 2>/dev/null || true
    rm -f "${pid_file}"
    info "Stopped daemon (pid ${pid})"
  else
    pkill -f 'target/debug/t3rnel start' 2>/dev/null && info "Stopped daemon" || warn "No daemon pid file and no matching process"
  fi
}

status_local_daemon() {
  if local_daemon_is_healthy; then
    info "daemon: healthy on :${T3RNEL_LOCAL_DAEMON_PORT}"
    curl -fsS "$(local_daemon_health_url)" || true; echo
  else
    warn "daemon: not healthy on :${T3RNEL_LOCAL_DAEMON_PORT}"
  fi
}

restart_local_daemon() { stop_local_daemon || true; sleep 2; start_local_daemon; }

# ── Clients ───────────────────────────────────────────────────────────────────

start_web_app() {
  [[ -d "${SCRIPT_DIR}/clients/web" ]] || fail "clients/web not found"
  have pnpm || fail "pnpm is not installed"
  info "Starting web client on :${T3RNEL_WEB_PORT}"
  (cd "${SCRIPT_DIR}/clients/web" && T3RNEL_API_URL="http://127.0.0.1:${T3RNEL_LOCAL_DAEMON_PORT}" pnpm dev --port "${T3RNEL_WEB_PORT}") &
  echo $! > "${T3RNEL_WEB_PID_PATH}"
}

stop_web_app() {
  if [[ -f "${T3RNEL_WEB_PID_PATH}" ]]; then
    kill "$(cat "${T3RNEL_WEB_PID_PATH}")" 2>/dev/null || true
    rm -f "${T3RNEL_WEB_PID_PATH}"
    info "Stopped web client"
  fi
}

start_desktop_app() {
  [[ -d "${SCRIPT_DIR}/clients/desktop" ]] || fail "clients/desktop not found"
  info "Starting desktop client (see clients/desktop README for platform steps)"
}

stop_desktop_app() {
  if [[ -f "${T3RNEL_DESKTOP_PID_PATH}" ]]; then
    kill "$(cat "${T3RNEL_DESKTOP_PID_PATH}")" 2>/dev/null || true
    rm -f "${T3RNEL_DESKTOP_PID_PATH}"
  fi
}

# ── Housekeeping ──────────────────────────────────────────────────────────────

run_doctor() {
  local ok=1
  for cmd in cargo rustc pnpm node; do
    if have "${cmd}"; then info "${cmd}: $("${cmd}" --version 2>/dev/null | head -1)"; else warn "${cmd}: MISSING"; ok=0; fi
  done
  have shellcheck && info "shellcheck: ok" || warn "shellcheck: missing (optional)"
  have cargo-audit && info "cargo-audit: ok" || warn "cargo-audit: missing (optional)"
  [[ -f "${SCRIPT_DIR}/.env" ]] && info ".env: present" || warn ".env: missing (cp .env.example .env)"
  [[ ${ok} -eq 1 ]] || fail "doctor found missing prerequisites"
}

run_memory_export() {
  have cargo || fail "cargo is not installed"
  run_cargo run -p t3rnel-cli -- memory export --home "${T3RNEL_LOCAL_DAEMON_HOME}"
}

run_clean() {
  info "Cleaning build artifacts"
  run_cargo clean
  rm -rf "${SCRIPT_DIR}/clients/web/node_modules/.vite" "${SCRIPT_DIR}/clients/web/dist" 2>/dev/null || true
}

show_status() {
  printf '\nT3rnel services status\n'
  status_local_daemon
  [[ -f "${T3RNEL_WEB_PID_PATH}" ]] && info "web client: pid $(cat "${T3RNEL_WEB_PID_PATH}")" || true
}

show_urls() {
  printf 'daemon api:  http://127.0.0.1:%s\n' "${T3RNEL_LOCAL_DAEMON_PORT}"
  printf 'dashboard:   http://127.0.0.1:%s/\n' "${T3RNEL_LOCAL_DAEMON_PORT}"
  printf 'web client:  http://127.0.0.1:%s\n' "${T3RNEL_WEB_PORT}"
}

usage() {
  cat <<'EOF'
Usage: ./t3rnel-services.sh <command>

Build & test
  --doctor                 Check prerequisites
  --build [debug|release]  Build the workspace (default: debug)
  --release                Build release binaries
  --check                  cargo check --workspace --all-targets
  --lint                   clippy -D warnings + shellcheck + pnpm lint
  --format                 cargo fmt + pnpm format
  --bench                  cargo bench --workspace
  --test <suite>           unit-rust[:filter] | unit-ts | shellcheck | security
  --migrate <up|down|status>  Run database migrations
  --clean                  Remove build artifacts

Daemon
  --daemon-start           Build (if needed) and start the daemon
  --daemon-stop            Stop the daemon
  --daemon-restart         Restart the daemon
  --daemon-status          Health-check the daemon
  --logs                   Tail daemon output (Ctrl-C to stop)

Clients
  --web-start / --web-stop       Web dashboard dev server
  --desktop-start / --desktop-stop

Other
  --memory-export          Export memory vault
  --status                 Show all service status
  --urls                   Print service URLs
  --compose <args>         docker compose passthrough
  --help                   This message
EOF
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

main() {
  case "${1:-help}" in
    --doctor) run_doctor ;;
    --build) run_build "${2:-debug}" ;;
    --release) run_release ;;
    --check) run_check ;;
    --lint) run_lint ;;
    --format) run_format ;;
    --bench) run_bench ;;
    --test) run_test "${2:?missing suite}" ;;
    --migrate) run_migrate "${2:-status}" ;;
    --clean) run_clean ;;
    --daemon-start) start_local_daemon ;;
    --daemon-stop) stop_local_daemon ;;
    --daemon-restart) restart_local_daemon ;;
    --daemon-status) status_local_daemon ;;
    --logs) tail -f "${TMPDIR:-/tmp}/t3rnel-daemon.log" 2>/dev/null || warn "no daemon log" ;;
    --web-start) start_web_app ;;
    --web-stop) stop_web_app ;;
    --desktop-start) start_desktop_app ;;
    --desktop-stop) stop_desktop_app ;;
    --memory-export) run_memory_export ;;
    --status) show_status ;;
    --urls) show_urls ;;
    --compose) shift; run_compose "$@" ;;
    -h|--help|help) usage ;;
    *) fail "unknown command: $1 (try --help)" ;;
  esac
}

main "$@"
