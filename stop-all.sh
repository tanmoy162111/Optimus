#!/bin/bash
# Stop All Optimus Components Script
echo "============================================================"
echo "Stopping All Optimus Components"
echo "============================================================"

# Stop Backend (Python processes)
echo "[1/3] Stopping Backend Server..."
pkill -f "python.*app.py" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "Backend server stopped."
else
    echo "No backend server found or already stopped."
fi

# Stop Frontend (Node processes)
echo "[2/3] Stopping Frontend Dev Server..."
pkill -f "vite" 2>/dev/null
pkill -f "npm.*run.*dev" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "Frontend dev server stopped."
else
    echo "No frontend dev server found or already stopped."
fi

# Stop Kali VM
echo "[3/3] Stopping Kali VM..."
VBOX_PATH="/d/Virtualbox/VBoxManage.exe"
"$VBOX_PATH" controlvm "kali" poweroff 2>/dev/null
if [ $? -eq 0 ]; then
    echo "Kali VM powered off."
else
    echo "Failed to power off Kali VM or VM not running."
fi

echo ""
echo "============================================================"
echo "All Optimus Components Stopped!"
echo "============================================================"