#!/bin/bash
# Start Frontend Dev Server Script
echo "============================================================"
echo "Starting Optimus Frontend Dev Server"
echo "============================================================"

# Add Node.js to PATH if it exists in the default location
if [ -d "/c/Program Files/nodejs" ]; then
    export PATH="/c/Program Files/nodejs:$PATH"
    echo "Added Node.js to PATH"
fi

# Change to frontend directory
cd "$(dirname "$0")/frontend" || exit 1

# Check if npm is available
if ! command -v npm &> /dev/null; then
    # Try with .cmd extension on Windows
    if command -v npm.cmd &> /dev/null; then
        alias npm=npm.cmd
    else
        echo "ERROR: npm is not installed or not in PATH"
        echo "Please install Node.js from https://nodejs.org/"
        echo "Node.js installation includes npm package manager"
        exit 1
    fi
fi

echo "Using npm version: $(npm --version)"

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