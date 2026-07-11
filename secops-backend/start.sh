#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
#  SecOps Console — Backend Start Script
#  Installs deps, pushes schema, builds, and starts the API server
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

BACKEND_PORT="${PORT:-8080}"

echo ""
echo -e "${BOLD}${CYAN}  SecOps Console — Backend${RESET}"
hr

# ── Verify Node.js ────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  err "Node.js not found. Install Node.js 22+ from https://nodejs.org"
  exit 1
fi
ok "Node.js $(node -e "process.stdout.write(process.versions.node)")"

# ── Redis check ───────────────────────────────────────────────────────────────
if redis-cli ping &>/dev/null 2>&1; then
  ok "Redis running"
else
  warn "Redis is not running. Start it with: redis-server --daemonize yes"
fi

# ── PostgreSQL check ──────────────────────────────────────────────────────────
if pg_isready -q 2>/dev/null; then
  ok "PostgreSQL running"
elif [[ -n "${DATABASE_URL:-}" ]]; then
  ok "PostgreSQL connection string provided via DATABASE_URL"
else
  err "PostgreSQL not detected and DATABASE_URL is not set."
  echo "      Ubuntu: sudo systemctl start postgresql"
  echo "      macOS:  brew services start postgresql@15"
  exit 1
fi

# ── .env setup ────────────────────────────────────────────────────────────────
if [[ ! -f ".env" && -z "${DATABASE_URL:-}" ]]; then
  info "Creating .env with default values…"
  cat > .env << 'ENVEOF'
PORT=8080
NODE_ENV=development
DATABASE_URL=postgresql://secops:secops_pass@localhost:5432/secops
REDIS_URL=redis://localhost:6379
JWT_SECRET=change-me-to-a-long-random-string-before-production
JWT_REFRESH_SECRET=change-me-to-another-long-random-string-before-production
ENABLE_WORKER=true
ENABLE_SYSLOG=false
SYSLOG_UDP_PORT=1514
SYSLOG_TCP_PORT=1514
LOG_LEVEL=info
ENVEOF
  warn "Edit .env and set DATABASE_URL + JWT secrets before production use."
fi

# ── Install dependencies ──────────────────────────────────────────────────────
if [[ ! -f "node_modules/.bin/esbuild" ]]; then
  info "Installing dependencies…"
  npm install --prefer-offline 2>&1 | tail -3
  ok "Dependencies installed"
else
  ok "Dependencies up to date"
fi

# ── Apply schema ──────────────────────────────────────────────────────────────
info "Applying database schema…"
npm run db:push 2>&1 | grep -v "^\[" | grep -v "^$" | grep -v "^>" | tail -5 || true
ok "Schema applied"

# ── Build ─────────────────────────────────────────────────────────────────────
info "Building with esbuild…"
if ! node build.mjs 2>&1 | tail -4; then
  err "Build failed."
  exit 1
fi
ok "Build complete"

# ── Start ─────────────────────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Starting backend on :${BACKEND_PORT}${RESET}"
hr

if [[ -f ".env" ]]; then
  exec node --env-file=".env" --enable-source-maps ./dist/index.mjs
else
  exec node --enable-source-maps ./dist/index.mjs
fi
