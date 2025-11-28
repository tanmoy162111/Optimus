#!/bin/bash
# Start Backend Server Script
echo "============================================================"
echo "Starting Optimus Backend Server"
echo "============================================================"

# Change to backend directory
cd "$(dirname "$0")/backend" || exit 1

# Check if backend is already running
if pgrep -f "python.*app.py" > /dev/null 2>&1; then
    echo "Backend server is already running."
    exit 0
fi

echo "Starting backend server on port 5000..."

# Start backend in background
if [ -f "venv/Scripts/python.exe" ]; then
    echo "Using virtual environment Python"
    ./venv/Scripts/python.exe app.py &
    BACKEND_PID=$!
elif [ -f "venv/bin/python" ]; then
    echo "Using virtual environment Python (Unix)"
    ./venv/bin/python app.py &
    BACKEND_PID=$!
else
    echo "Using system Python"
    python app.py &
    BACKEND_PID=$!
fi

if [ $? -eq 0 ]; then
    echo "Backend server started successfully! (PID: $BACKEND_PID)"
    echo "Access the API at: http://localhost:5000"
    
    # Wait a moment for server to initialize
    sleep 5
else
    echo "Failed to start backend server!"
    exit 1
fi