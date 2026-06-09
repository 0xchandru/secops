#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  SecOps Console — Unified Start Script
#  Works on Replit (auto-detects) and local Linux/macOS machines
# ═══════════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/secops-backend"
FRONTEND_DIR="$SCRIPT_DIR/secops-frontend"
BACKEND_PORT=${BACKEND_PORT:-8080}
FRONTEND_PORT=${FRONTEND_PORT:-5000}

# ── Detect Replit environment ──────────────────────────────────────
IS_REPLIT=${REPL_SLUG:-${REPL_ID:-""}}

# ── Graceful shutdown ──────────────────────────────────────────────
cleanup() {
  echo ""
  echo "Shutting down SecOps Console..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
  # Only stop Redis if we started it (not on managed platforms)
  if [ -z "$IS_REPLIT" ] && [ "${REDIS_STARTED:-0}" = "1" ]; then
    redis-cli shutdown nosave 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  echo "Stopped."
}
trap cleanup EXIT INT TERM

# ── Kill anything already using our ports ─────────────────────────
fuser -k "${BACKEND_PORT}/tcp" 2>/dev/null || true
fuser -k "${FRONTEND_PORT}/tcp" 2>/dev/null || true

echo "═══════════════════════════════════════"
echo "  SecOps Console"
echo "═══════════════════════════════════════"

# ── Redis ──────────────────────────────────────────────────────────
if redis-cli ping &>/dev/null 2>&1; then
  echo "[ OK ] Redis already running"
else
  echo "Starting Redis..."
  redis-server --daemonize yes --loglevel warning
  sleep 1
  REDIS_STARTED=1
  echo "[ OK ] Redis started"
fi

# ── PostgreSQL check (local only) ─────────────────────────────────
if [ -z "$IS_REPLIT" ]; then
  if ! pg_isready -q 2>/dev/null; then
    echo ""
    echo "[ERR] PostgreSQL is not running."
    echo "      Ubuntu/Debian : sudo systemctl start postgresql"
    echo "      macOS Homebrew: brew services start postgresql@15"
    echo ""
    exit 1
  fi
  echo "[ OK ] PostgreSQL is running"
fi

# ── .env setup (local only) ──────────────────────────────────────
if [ -z "$IS_REPLIT" ]; then
  if [ ! -f "$BACKEND_DIR/.env" ]; then
    echo ""
    echo "Creating $BACKEND_DIR/.env with default values..."
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
    echo "      Edit $BACKEND_DIR/.env to set your DATABASE_URL and secrets."
    echo ""
  fi
fi

# ── Backend dependencies ───────────────────────────────────────────
cd "$BACKEND_DIR"
if [ ! -f "node_modules/.bin/esbuild" ]; then
  echo "Installing backend dependencies..."
  npm install
fi

# ── Apply database schema ─────────────────────────────────────────
echo "Applying database schema..."
npm run db:push 2>&1 | grep -v "^\[" | grep -v "^$" || true

# ── Build backend ─────────────────────────────────────────────────
echo "Building backend..."
node build.mjs

# ── Start backend ─────────────────────────────────────────────────
echo "Starting backend on :${BACKEND_PORT}..."
if [ -z "$IS_REPLIT" ] && [ -f "$BACKEND_DIR/.env" ]; then
  PORT=$BACKEND_PORT node --env-file="$BACKEND_DIR/.env" --enable-source-maps ./dist/index.mjs &
else
  PORT=$BACKEND_PORT node --enable-source-maps ./dist/index.mjs &
fi
BACKEND_PID=$!

# Give backend time to initialise
sleep 4

# ── Frontend dependencies ─────────────────────────────────────────
cd "$FRONTEND_DIR"
if [ ! -d "node_modules" ]; then
  echo "Installing frontend dependencies..."
  npm install
fi

# ── Start frontend ────────────────────────────────────────────────
echo "Starting frontend on :${FRONTEND_PORT}..."
PORT=$FRONTEND_PORT npx vite --host 0.0.0.0 --port "$FRONTEND_PORT" &
FRONTEND_PID=$!

echo ""
echo "═══════════════════════════════════════"
echo "  SecOps Console is running"
echo "  Backend:  http://localhost:${BACKEND_PORT}"
echo "  Frontend: http://localhost:${FRONTEND_PORT}"
echo ""
echo "  Demo accounts (all seeded automatically):"
echo "    admin          / Admin@123"
echo "    senior_analyst / Analyst@123"
echo "    analyst        / Analyst@123"
echo "    tier1 (bob)    / Tier1@123"
echo ""
echo "  Press Ctrl+C to stop."
echo "═══════════════════════════════════════"

wait
