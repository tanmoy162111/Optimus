#!/bin/bash
# Start Frontend Dev Server Script
echo "============================================================"
echo "Starting Optimus Frontend Dev Server"
echo "============================================================"

# Change to frontend directory
cd "$(dirname "$0")/frontend" || exit 1

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "Failed to install dependencies!"
        exit 1
    fi
fi

# Check if frontend is already running
if pgrep -f "vite" > /dev/null 2>&1; then
    echo "Frontend dev server is already running."
    exit 0
fi

echo "Starting frontend dev server on port 5173..."
npm run dev &
FRONTEND_PID=$!
if [ $? -eq 0 ]; then
    echo "Frontend dev server started successfully! (PID: $FRONTEND_PID)"
    echo "Access the frontend at: http://localhost:5173"
    
    # Wait a moment for server to initialize
    sleep 3
else
    echo "Failed to start frontend dev server!"
    exit 1
fi