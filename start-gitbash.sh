#!/bin/bash

echo "============================================================"
echo "Starting Optimus"
echo "============================================================"

# Set VirtualBox path
VBOX_PATH="/d/Virtualbox/VBoxManage.exe"

# Start Kali VM if not running
echo ""
echo "[1/3] Checking Kali VM status..."
if "$VBOX_PATH" list runningvms | grep -q "kali"; then
    echo "Kali VM already running."
else
    echo "Kali VM not running. Starting Kali VM..."
    "$VBOX_PATH" startvm "kali" --type headless &
    echo "Waiting for Kali VM to boot and SSH service to start..."
    sleep 60
    echo "Kali VM started successfully!"
fi

# Start Backend
echo ""
echo "[2/3] Starting Backend Server (Port 5000)..."
if [ -f "./backend/venv/Scripts/python.exe" ]; then
    echo "Using virtual environment Python"
    cd ./backend && ./venv/Scripts/python.exe app.py &
elif [ -f "/c/Program Files/Python313/python.exe" ]; then
    echo "Using system Python 313"
    cd ./backend && "/c/Program Files/Python313/python.exe" app.py &
elif [ -f "/c/Users/Tanmoy Saha/AppData/Local/Programs/Python/Python313/python.exe" ]; then
    echo "Using system Python 313 (AppData)"
    cd ./backend && "/c/Users/Tanmoy Saha/AppData/Local/Programs/Python/Python313/python.exe" app.py &
else
    echo "Trying system Python command..."
    cd ./backend && python app.py &
fi

# Wait for backend to start
echo "Waiting for backend to initialize..."
sleep 5

# Start Frontend
echo ""
echo "[3/3] Starting Frontend Dev Server (Port 5173)..."
cd ../frontend && npm run dev &

echo ""
echo "============================================================"
echo "Optimus Started Successfully!"
echo "============================================================"
echo ""
echo "Backend:  http://localhost:5000"
echo "Frontend: http://localhost:5173"
echo "Kali VM:  127.0.0.1:2222 (SSH port forwarding)"
echo ""
echo "Press Ctrl+C to stop all services"
wait