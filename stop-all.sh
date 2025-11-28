#!/bin/bash
# Stop All Optimus Components Script

echo "============================================================"
echo "Stopping All Optimus Components"
echo "============================================================"

# Stop Backend (Python processes)
echo "[1/3] Stopping Backend Server..."
taskkill //F //FI "WINDOWTITLE eq Optimus Backend*" >nul 2>&1
if [ $? -eq 0 ]; then
    echo "Backend server stopped."
else
    echo "No backend server found or failed to stop."
fi

# Stop Frontend (Node processes)
echo "[2/3] Stopping Frontend Dev Server..."
taskkill //F //FI "WINDOWTITLE eq Optimus Frontend*" >nul 2>&1
if [ $? -eq 0 ]; then
    echo "Frontend dev server stopped."
else
    echo "No frontend dev server found or failed to stop."
fi

# Stop Kali VM
echo "[3/3] Stopping Kali VM..."
VBOX_PATH="D:/Virtualbox/VBoxManage.exe"
"$VBOX_PATH" controlvm "kali" poweroff >nul 2>&1
if [ $? -eq 0 ]; then
    echo "Kali VM powered off."
else
    echo "Failed to power off Kali VM or VM not running."
fi

echo ""
echo "============================================================"
echo "All Optimus Components Stopped!"
echo "============================================================"