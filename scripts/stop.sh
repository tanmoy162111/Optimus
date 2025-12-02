#!/bin/bash

# Optimus Stop Script
# Stops both backend and frontend servers

set -e

PROJECT_ROOT=$(pwd)
LOGS_DIR="$PROJECT_ROOT/logs"

echo "🛑 Stopping Optimus Platform..."

# Stop backend server
if [ -f "$PROJECT_ROOT/.backend_pid" ]; then
    BACKEND_PID=$(cat "$PROJECT_ROOT/.backend_pid")
    echo "Stopping Backend Server (PID: $BACKEND_PID)..."
    kill "$BACKEND_PID" 2>/dev/null || true
    rm "$PROJECT_ROOT/.backend_pid"
    echo "✅ Backend Server Stopped"
else
    echo "⚠️  No Backend PID file found"
fi

# Stop frontend server
if [ -f "$PROJECT_ROOT/.frontend_pid" ]; then
    FRONTEND_PID=$(cat "$PROJECT_ROOT/.frontend_pid")
    echo "Stopping Frontend Server (PID: $FRONTEND_PID)..."
    kill "$FRONTEND_PID" 2>/dev/null || true
    rm "$PROJECT_ROOT/.frontend_pid"
    echo "✅ Frontend Server Stopped"
else
    echo "⚠️  No Frontend PID file found"
fi

# Kill any remaining processes on ports 5000 and 5173
echo "🧹 Cleaning up any remaining processes..."
lsof -ti:5000 | xargs kill -9 2>/dev/null || true
lsof -ti:5173 | xargs kill -9 2>/dev/null || true

echo "✅ Optimus Platform Stopped!"
echo "📝 Logs: $LOGS_DIR/"