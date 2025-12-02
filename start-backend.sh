#!/bin/bash
# Start Backend Server Script
echo "============================================================"
echo "Starting Optimus Backend Server"
echo "============================================================"

# Change to backend directory using absolute path
cd "$(pwd)/backend" || exit 1

# Check if backend is already running
if pgrep -f "python.*app.py" > /dev/null 2>&1; then
    echo "Backend server is already running."
    exit 0
fi

echo "Starting backend server on port 5000..."

# Start backend in background
PYTHON_PATH=""
if [ -f "venv/Scripts/python.exe" ]; then
    PYTHON_PATH="./venv/Scripts/python.exe"
    echo "Using virtual environment Python: $PYTHON_PATH"
elif [ -f "/c/Users/Tanmoy\ Saha/AppData/Local/Programs/Python/Python313/python.exe" ]; then
    PYTHON_PATH="/c/Users/Tanmoy\ Saha/AppData/Local/Programs/Python/Python313/python.exe"
    echo "Using system Python 313: $PYTHON_PATH"
elif [ -f "/c/Program\ Files/Python313/python.exe" ]; then
    PYTHON_PATH="/c/Program\ Files/Python313/python.exe"
    echo "Using system Python 313: $PYTHON_PATH"
else
    # Fallback to system python
    PYTHON_PATH="python"
    echo "Using system Python command"
fi

# Start the backend with the determined Python path
"$PYTHON_PATH" app.py &
BACKEND_PID=$!

if [ $? -eq 0 ]; then
    echo "Backend server started successfully! (PID: $BACKEND_PID)"
    echo "Access the API at: http://localhost:5000"
    
    # Wait a moment for server to initialize using Windows ping
    cmd.exe //c "ping -n 6 127.0.0.1 > nul"
else
    echo "Failed to start backend server!"
    exit 1
fi