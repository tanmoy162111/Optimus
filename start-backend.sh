#!/bin/bash
# Start Backend Server Script

echo "============================================================"
echo "Starting Optimus Backend Server"
echo "============================================================"

# Change to backend directory
cd "D:/Work/Ai Engineering/Git/Optimus/backend"

# Check if backend is already running
if pgrep -f "python.*app.py" > /dev/null; then
    echo "Backend server is already running."
    exit 0
fi

echo "Starting backend server on port 5000..."

# Check if virtual environment exists
if [ -f "venv/Scripts/python.exe" ]; then
    echo "Using virtual environment Python"
    start "Optimus Backend" /D "D:/Work/Ai Engineering/Git/Optimus/backend" "venv/Scripts/python.exe" "app.py"
else
    echo "Using system Python"
    start "Optimus Backend" /D "D:/Work/Ai Engineering/Git/Optimus/backend" python "app.py"
fi

if [ $? -eq 0 ]; then
    echo "Backend server started successfully!"
    echo "Access the API at: http://localhost:5000"
else
    echo "Failed to start backend server!"
    exit 1
fi