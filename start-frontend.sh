#!/bin/bash
# Start Frontend Dev Server Script

echo "============================================================"
echo "Starting Optimus Frontend Dev Server"
echo "============================================================"

# Change to frontend directory
cd "D:/Work/Ai Engineering/Git/Optimus/frontend"

# Check if frontend is already running
if pgrep -f "npm.*run.*dev" > /dev/null; then
    echo "Frontend dev server is already running."
    exit 0
fi

echo "Starting frontend dev server on port 5173..."
start "Optimus Frontend" /D "D:/Work/Ai Engineering/Git/Optimus/frontend" cmd /k "npm run dev"

if [ $? -eq 0 ]; then
    echo "Frontend dev server started successfully!"
    echo "Access the frontend at: http://localhost:5173"
else
    echo "Failed to start frontend dev server!"
    exit 1
fi