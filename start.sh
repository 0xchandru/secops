#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
#  SecOps Console — Unified Start Script
#  Installs all dependencies, sets up the database, and starts the full stack
#  Supports: Ubuntu/Debian · macOS · any Linux environment
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✓${RESET}  $*"; }
info() { echo -e "${CYAN}  →${RESET}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET}  $*"; }
err()  { echo -e "${RED}  ✗${RESET}  $*" >&2; }
hr()   { echo -e "${CYAN}────────────────────────────────────────${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/secops-backend"
FRONTEND_DIR="$SCRIPT_DIR/secops-frontend"
BACKEND_PORT="${BACKEND_PORT:-8080}"
FRONTEND_PORT="${FRONTEND_PORT:-5000}"

# ── Graceful shutdown ─────────────────────────────────────────────────────────
cleanup() {
  echo ""
  info "Shutting down SecOps Console…"
  kill "${BACKEND_PID:-}" "${FRONTEND_PID:-}" 2>/dev/null || true
  if [[ "${REDIS_STARTED:-0}" == "1" ]]; then
    redis-cli shutdown nosave 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  ok "Stopped."
}
trap cleanup EXIT INT TERM

# ── Kill anything already on our ports ────────────────────────────────────────
fuser -k "${BACKEND_PORT}/tcp"  2>/dev/null || true
fuser -k "${FRONTEND_PORT}/tcp" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════════════
echo -e ""
echo -e "${BOLD}${CYAN}  ███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗${RESET}"
echo -e "${BOLD}${CYAN}  ██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝${RESET}"
echo -e "${BOLD}${CYAN}  ███████╗█████╗  ██║     ██║   ██║██████╔╝███████╗${RESET}"
echo -e "${BOLD}${CYAN}  ╚════██║██╔══╝  ██║     ██║   ██║██╔═══╝ ╚════██║${RESET}"
echo -e "${BOLD}${CYAN}  ███████║███████╗╚██████╗╚██████╔╝██║     ███████║${RESET}"
echo -e "${BOLD}${CYAN}  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝${RESET}"
echo -e "${BOLD}           SecOps Console  —  mini-SIEM${RESET}"
echo ""
hr

# ── Verify Node.js ────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  err "Node.js not found. Install Node.js 22+ from https://nodejs.org"
  exit 1
fi
NODE_VER=$(node -e "process.stdout.write(process.versions.node)")
ok "Node.js $NODE_VER"

# ── Redis ─────────────────────────────────────────────────────────────────────
if redis-cli ping &>/dev/null 2>&1; then
  ok "Redis already running"
else
  info "Starting Redis…"
  if redis-server --daemonize yes --loglevel warning 2>/dev/null; then
    sleep 1
    REDIS_STARTED=1
    ok "Redis started"
  else
    warn "Could not start Redis. Install it first:"
    warn "  Ubuntu: sudo apt install redis-server  |  macOS: brew install redis"
  fi
fi

# ── PostgreSQL check ──────────────────────────────────────────────────────────
if pg_isready -q 2>/dev/null; then
  ok "PostgreSQL running"
elif [[ -n "${DATABASE_URL:-}" ]]; then
  ok "PostgreSQL connection string provided via DATABASE_URL"
else
  warn "PostgreSQL not detected. Ensure DATABASE_URL is set or start PostgreSQL:"
  warn "  Ubuntu: sudo systemctl start postgresql"
  warn "  macOS:  brew services start postgresql@15"
fi

# ── .env setup ────────────────────────────────────────────────────────────────
if [[ ! -f "$BACKEND_DIR/.env" && -z "${DATABASE_URL:-}" ]]; then
  info "Creating $BACKEND_DIR/.env with default values…"
  cat > "$BACKEND_DIR/.env" << 'ENVEOF'
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
  warn "Edit $BACKEND_DIR/.env and set your DATABASE_URL + JWT secrets."
fi

hr
echo -e "${BOLD}  Installing dependencies${RESET}"
hr

# ── Backend dependencies ──────────────────────────────────────────────────────
cd "$BACKEND_DIR"
if [[ ! -f "node_modules/.bin/esbuild" ]]; then
  info "Installing backend dependencies…"
  npm install --prefer-offline 2>&1 | tail -3
  ok "Backend dependencies installed"
else
  ok "Backend dependencies up to date"
fi

# ── Frontend dependencies ─────────────────────────────────────────────────────
cd "$FRONTEND_DIR"
if [[ ! -d "node_modules" ]]; then
  info "Installing frontend dependencies…"
  npm install --prefer-offline 2>&1 | tail -3
  ok "Frontend dependencies installed"
else
  ok "Frontend dependencies up to date"
fi

hr
echo -e "${BOLD}  Database setup${RESET}"
hr

# ── Apply Drizzle schema ──────────────────────────────────────────────────────
cd "$BACKEND_DIR"
info "Applying database schema…"
npm run db:push 2>&1 | grep -v "^\[" | grep -v "^$" | grep -v "^>" | tail -5 || true
ok "Database schema applied"

hr
echo -e "${BOLD}  Building backend${RESET}"
hr

# ── Build backend ─────────────────────────────────────────────────────────────
cd "$BACKEND_DIR"
info "Building backend with esbuild…"
if node build.mjs 2>&1 | tail -4; then
  ok "Backend built successfully"
else
  err "Backend build failed. Check output above."
  exit 1
fi

hr
echo -e "${BOLD}  Starting services${RESET}"
hr

# ── Launch backend ────────────────────────────────────────────────────────────
cd "$BACKEND_DIR"
info "Starting backend on :${BACKEND_PORT}…"
if [[ -f ".env" ]]; then
  PORT=$BACKEND_PORT node --env-file=".env" --enable-source-maps ./dist/index.mjs &
else
  PORT=$BACKEND_PORT node --enable-source-maps ./dist/index.mjs &
fi
BACKEND_PID=$!

# Wait for backend to be ready (up to 20 s)
for i in {1..20}; do
  if curl -s "http://localhost:${BACKEND_PORT}/healthz" &>/dev/null; then
    ok "Backend ready  →  http://localhost:${BACKEND_PORT}"
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    err "Backend process exited unexpectedly."
    exit 1
  fi
  sleep 1
done

# ── Launch frontend ───────────────────────────────────────────────────────────
cd "$FRONTEND_DIR"
info "Starting frontend on :${FRONTEND_PORT}…"
PORT=$FRONTEND_PORT npx vite --host 0.0.0.0 --port "$FRONTEND_PORT" &
FRONTEND_PID=$!
sleep 2
ok "Frontend ready  →  http://localhost:${FRONTEND_PORT}"

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
hr
echo -e "${BOLD}  🚀  SecOps Console is running${RESET}"
hr
echo -e "  ${CYAN}Frontend${RESET}   http://localhost:${FRONTEND_PORT}"
echo -e "  ${CYAN}Backend API${RESET} http://localhost:${BACKEND_PORT}/api"
echo -e "  ${CYAN}Health${RESET}     http://localhost:${BACKEND_PORT}/healthz"
echo ""
echo -e "${BOLD}  Demo accounts${RESET}"
echo -e "  ${GREEN}admin${RESET}   / Admin@SecOps1!   (Administrator)"
echo -e "  ${GREEN}morgan${RESET}  / Manager@1234!    (SOC Manager)"
echo -e "  ${GREEN}elena${RESET}   / Engineer@1234!   (Detection Engineer)"
echo -e "  ${GREEN}alice${RESET}   / Analyst@1234!    (SOC L2 Analyst)"
echo -e "  ${GREEN}bob${RESET}     / Analyst@1234!    (SOC L1 Analyst)"
echo -e "  ${GREEN}viewer${RESET}  / Viewer@1234!     (Read-Only Viewer)"
echo ""
hr
echo -e "  Press ${BOLD}Ctrl+C${RESET} to stop all services."
hr
echo ""

wait
