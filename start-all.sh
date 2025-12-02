#!/bin/bash
# Start All Optimus Components Script
echo "============================================================"
echo "Starting All Optimus Components"
echo "============================================================"

# Get script directory using a more compatible approach
SCRIPT_DIR="$(pwd)"
echo "Script directory: $SCRIPT_DIR"

# Check if required scripts exist
if [ ! -f "$SCRIPT_DIR/start-kali.sh" ]; then
    echo "ERROR: start-kali.sh not found in $SCRIPT_DIR"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/start-backend.sh" ]; then
    echo "ERROR: start-backend.sh not found in $SCRIPT_DIR"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/start-frontend.sh" ]; then
    echo "ERROR: start-frontend.sh not found in $SCRIPT_DIR"
    exit 1
fi

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
# Use Windows ping as a substitute for sleep
cmd.exe //c "ping -n 6 127.0.0.1 > nul"

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
# Use read instead of wait for better compatibility
read -p "Press Enter to stop all services..."