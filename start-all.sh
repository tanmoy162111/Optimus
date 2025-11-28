#!/bin/bash
# Start All Optimus Components Script
echo "============================================================"
echo "Starting All Optimus Components"
echo "============================================================"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Start Kali VM
echo "[1/3] Starting Kali VM..."
"$SCRIPT_DIR/start-kali.sh"
if [ $? -ne 0 ]; then
    echo "Failed to start Kali VM!"
    exit 1
fi

echo ""

# Start Backend
echo "[2/3] Starting Backend Server..."
"$SCRIPT_DIR/start-backend.sh"
if [ $? -ne 0 ]; then
    echo "Failed to start Backend Server!"
    exit 1
fi

echo ""

# Wait a moment for backend to fully initialize
sleep 5

# Start Frontend
echo "[3/3] Starting Frontend Dev Server..."
"$SCRIPT_DIR/start-frontend.sh"
if [ $? -ne 0 ]; then
    echo "Failed to start Frontend Dev Server!"
    exit 1
fi

echo ""

echo "============================================================"
echo "All Optimus Components Started Successfully!"
echo "============================================================"
echo "Kali VM:     Running in headless mode"
echo "Backend:     http://localhost:5000"
echo "Frontend:    http://localhost:5173"
echo "SSH Access:  127.0.0.1:2222 (kali/kali)"
echo ""
echo "Press Ctrl+C to stop all services..."
echo ""

# Keep script running
wait