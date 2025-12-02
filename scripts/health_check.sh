#!/bin/bash

# Optimus Health Check Script
# Checks the status of backend and frontend servers

set -e

PROJECT_ROOT=$(pwd)
LOGS_DIR="$PROJECT_ROOT/logs"

echo "🏥 Checking Optimus Platform Health..."

# Check if logs directory exists
if [ ! -d "$LOGS_DIR" ]; then
    echo "❌ Logs directory not found"
    exit 1
fi

# Check backend health
echo "🔧 Checking Backend Health..."
if curl -s http://localhost:5000/health | grep -q '"status": "healthy"'; then
    echo "✅ Backend is healthy"
else
    echo "❌ Backend is not responding or unhealthy"
    echo "📋 Backend log tail:"
    tail -10 "$LOGS_DIR/backend.log" 2>/dev/null || echo "No backend log found"
fi

# Check frontend health (basic connectivity)
echo "🎨 Checking Frontend Health..."
if curl -s http://localhost:5173 | grep -q '<title>'; then
    echo "✅ Frontend is responding"
else
    echo "❌ Frontend is not responding"
    echo "📋 Frontend log tail:"
    tail -10 "$LOGS_DIR/frontend.log" 2>/dev/null || echo "No frontend log found"
fi

# Check running processes
echo "rPid Checking Running Processes..."
if [ -f "$PROJECT_ROOT/.backend_pid" ]; then
    BACKEND_PID=$(cat "$PROJECT_ROOT/.backend_pid")
    if ps -p "$BACKEND_PID" > /dev/null 2>&1; then
        echo "✅ Backend process running (PID: $BACKEND_PID)"
    else
        echo "❌ Backend process not running (PID: $BACKEND_PID)"
    fi
else
    echo "⚠️  No Backend PID file found"
fi

if [ -f "$PROJECT_ROOT/.frontend_pid" ]; then
    FRONTEND_PID=$(cat "$PROJECT_ROOT/.frontend_pid")
    if ps -p "$FRONTEND_PID" > /dev/null 2>&1; then
        echo "✅ Frontend process running (PID: $FRONTEND_PID)"
    else
        echo "❌ Frontend process not running (PID: $FRONTEND_PID)"
    fi
else
    echo "⚠️  No Frontend PID file found"
fi

echo "✅ Health check completed!"