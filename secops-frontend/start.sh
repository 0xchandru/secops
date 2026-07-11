#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
#  SecOps Console — Frontend Start Script
#  Installs dependencies and starts the Vite development server
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✓${RESET}  $*"; }
info() { echo -e "${CYAN}  →${RESET}  $*"; }
err()  { echo -e "${RED}  ✗${RESET}  $*" >&2; }
hr()   { echo -e "${CYAN}────────────────────────────────────────${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FRONTEND_PORT="${PORT:-5000}"

echo ""
echo -e "${BOLD}${CYAN}  SecOps Console — Frontend${RESET}"
hr

# ── Verify Node.js ────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  err "Node.js not found. Install Node.js 22+ from https://nodejs.org"
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

# ── Start Vite dev server ─────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Starting Vite on :${FRONTEND_PORT}${RESET}"
hr
echo -e "  Open ${CYAN}http://localhost:${FRONTEND_PORT}${RESET} in your browser."
echo -e "  The backend API must be running on ${CYAN}:8080${RESET}."
echo ""

exec npx vite --host 0.0.0.0 --port "$FRONTEND_PORT"
