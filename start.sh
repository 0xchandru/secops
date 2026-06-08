#!/bin/bash
set -e

# Kill any previous processes on our ports
fuser -k 8080/tcp 2>/dev/null || true
fuser -k 5000/tcp 2>/dev/null || true

cleanup() {
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Start backend
echo "Starting backend on :8080..."
cd /home/runner/workspace/secops-backend
node --enable-source-maps ./dist/index.mjs &
BACKEND_PID=$!

# Wait for backend to be ready
sleep 3

# Start frontend on port 5000
echo "Starting frontend on :5000..."
cd /home/runner/workspace/secops-frontend
npx vite --host 0.0.0.0 --port 5000 &
FRONTEND_PID=$!

echo "SecOps Console running:"
echo "  Backend:  http://localhost:8080"
echo "  Frontend: http://localhost:5000"

wait
