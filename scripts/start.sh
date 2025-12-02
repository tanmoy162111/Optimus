#!/bin/bash

# Optimus Start Script
# Starts both backend and frontend servers

set -e

PROJECT_ROOT=$(pwd)
LOGS_DIR="$PROJECT_ROOT/logs"
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

# Create logs directory
mkdir -p "$LOGS_DIR"

echo "🚀 Starting Optimus Platform..."

# Export environment variables
export PYTHONPATH="$BACKEND_DIR:$PYTHONPATH"
export NODE_ENV=development

# Start backend server in background
echo "🔧 Starting Backend Server..."
cd "$BACKEND_DIR"
nohup python app.py > "$LOGS_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

# Wait a moment for backend to start
sleep 3

# Start frontend server in background
echo "🎨 Starting Frontend Server..."
cd "$FRONTEND_DIR"
nohup npm run dev > "$LOGS_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"

# Save PIDs to file
echo "$BACKEND_PID" > "$PROJECT_ROOT/.backend_pid"
echo "$FRONTEND_PID" > "$PROJECT_ROOT/.frontend_pid"

echo "✅ Optimus Platform Started!"
echo "🌐 Frontend: http://localhost:5173"
echo "🔧 Backend API: http://localhost:5000"
echo "📝 Logs: $LOGS_DIR/"

# Show initial logs
echo "📋 Initial Backend Log:"
head -10 "$LOGS_DIR/backend.log"
echo ""
echo "📋 Initial Frontend Log:"
head -10 "$LOGS_DIR/frontend.log"