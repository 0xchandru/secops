#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
#  SecOps Console — Log Forwarder Start Script
#  Installs dependencies, builds, and starts the forwarder agent
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✓${RESET}  $*"; }
info() { echo -e "${CYAN}  →${RESET}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET}  $*"; }
err()  { echo -e "${RED}  ✗${RESET}  $*" >&2; }
hr()   { echo -e "${CYAN}────────────────────────────────────────${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo -e "${BOLD}${CYAN}  SecOps Console — Log Forwarder${RESET}"
hr

# ── Verify Node.js ────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  err "Node.js not found. Install Node.js 18+ from https://nodejs.org"
  exit 1
fi
ok "Node.js $(node -e "process.stdout.write(process.versions.node)")"

# ── Install dependencies ──────────────────────────────────────────────────────
if [[ ! -d "node_modules" ]]; then
  info "Installing dependencies…"
  npm install --prefer-offline 2>&1 | tail -3
  ok "Dependencies installed"
else
  ok "Dependencies up to date"
fi

# ── Check conf/outputs.conf ───────────────────────────────────────────────────
if [[ ! -f "conf/outputs.conf" ]]; then
  err "conf/outputs.conf not found."
  echo "      Copy conf/outputs.conf.example and set your SecOps Console URL + API key."
  exit 1
fi

# Validate the SecOps Console URL is set
if grep -q "url = http://localhost:8080" conf/outputs.conf 2>/dev/null; then
  warn "outputs.conf still has the default localhost URL."
  warn "Update [secops_console] url = in conf/outputs.conf to point to your instance."
fi

# ── Build (if dist is missing or stale) ──────────────────────────────────────
if [[ ! -d "dist" ]] || [[ "src/cli.ts" -nt "dist/cli.js" ]]; then
  info "Building forwarder…"
  if [[ -f "build.mjs" ]]; then
    node build.mjs 2>&1 | tail -4
  else
    npx tsx src/cli.ts --help &>/dev/null || true
    info "Using tsx for development mode"
    hr
    echo -e "${BOLD}  Starting forwarder (dev mode)${RESET}"
    hr
    exec npx tsx src/cli.ts start
  fi
  ok "Build complete"
fi

# ── Start forwarder ───────────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Starting forwarder${RESET}"
hr
echo -e "  Tailing inputs defined in ${CYAN}conf/inputs.conf${RESET}"
echo -e "  Forwarding to ${CYAN}conf/outputs.conf${RESET}"
echo -e "  Press ${BOLD}Ctrl+C${RESET} to stop."
echo ""

exec node dist/cli.js start
