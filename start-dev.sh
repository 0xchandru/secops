#!/bin/bash
# SecOps Console — Development Start Script
# Requires: PostgreSQL and Redis running locally
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm use 22 2>/dev/null || true

cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait 2>/dev/null
    echo "Stopped."
}
trap cleanup EXIT INT TERM

echo "================================="
echo "  SecOps Console Development"
echo "================================="

# Check prerequisites
if ! pg_isready -q 2>/dev/null; then
    echo "WARNING: PostgreSQL is not running. Backend will fail to connect."
    echo "  Start PostgreSQL first, then re-run this script."
fi

if ! redis-cli ping >/dev/null 2>&1; then
    echo "WARNING: Redis is not running. Some features may not work."
fi

# Backend
echo "[1/2] Starting Backend on :8080..."
cd "$SCRIPT_DIR/secops-backend"
if [ ! -d "node_modules" ]; then
    echo "  Installing npm dependencies..."
    npm install
fi
node build.mjs
node --env-file=../.env --enable-source-maps ./dist/index.mjs &
BACKEND_PID=$!
sleep 2

# Frontend
echo "[2/2] Starting Frontend on :5173..."
cd "$SCRIPT_DIR/secops-frontend"
if [ ! -d "node_modules" ]; then
    echo "  Installing npm dependencies..."
    npm install
fi
npx vite --host 0.0.0.0 --port 5173 &
FRONTEND_PID=$!
sleep 1

echo ""
echo "================================="
echo "  SecOps Console running:"
echo "  - API:  http://localhost:8080"
echo "  - UI:   http://localhost:5173"
echo ""
echo "  ThreatLens integration:"
echo "  - Start ThreatLens separately on :8000"
echo "  - IOC enrichment available in Alerts page"
echo "================================="
echo "Press Ctrl+C to stop."

wait
