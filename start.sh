#!/bin/bash
set -e

# Kill any previous processes on our ports
fuser -k 8080/tcp 2>/dev/null || true
fuser -k 5000/tcp 2>/dev/null || true

cleanup() {
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    redis-cli shutdown nosave 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Start Redis if not already running
if ! redis-cli ping &>/dev/null 2>&1; then
    echo "Starting Redis..."
    redis-server --daemonize yes --loglevel warning
    sleep 1
fi

# Install backend deps if needed
cd /home/runner/workspace/secops-backend
if [ ! -f "node_modules/.bin/esbuild" ]; then
    echo "Installing backend dependencies..."
    npm install
fi

# Build backend
echo "Building backend..."
node build.mjs

# Start backend on port 8080 (env vars already available in Replit env)
echo "Starting backend on :8080..."
PORT=8080 node --enable-source-maps ./dist/index.mjs &
BACKEND_PID=$!

# Wait for backend to be ready
sleep 4

# Install frontend deps if needed
cd /home/runner/workspace/secops-frontend
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# Start frontend on port 5000 (proxies /api and /ws to backend:8080)
echo "Starting frontend on :5000..."
PORT=5000 npx vite --host 0.0.0.0 --port 5000 &
FRONTEND_PID=$!

echo "SecOps Console running:"
echo "  Backend:  http://localhost:8080"
echo "  Frontend: http://localhost:5000"

wait
