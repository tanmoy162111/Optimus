#!/bin/bash
# Start Kali VM Script
echo "============================================================"
echo "Starting Kali VM"
echo "============================================================"
VBOX_PATH="/d/Virtualbox/VBoxManage.exe"

# Check if VBoxManage exists
if [ ! -f "$VBOX_PATH" ]; then
    echo "ERROR: VirtualBox not found at $VBOX_PATH"
    echo "Please check your VirtualBox installation path."
    exit 1
fi

# Check if Kali VM is already running (using Windows findstr)
if cmd.exe //c "$VBOX_PATH list runningvms | findstr kali" > /dev/null 2>&1; then
    echo "Kali VM is already running."
    exit 0
fi

echo "Starting Kali VM in headless mode..."
"$VBOX_PATH" startvm "kali" --type headless
if [ $? -eq 0 ]; then
    echo "Kali VM started successfully!"
    echo "Waiting 60 seconds for Kali VM to boot and SSH service to start..."
    # Use Windows ping as a substitute for sleep
    cmd.exe //c "ping -n 61 127.0.0.1 > nul"
    echo "Kali VM is ready!"
else
    echo "Failed to start Kali VM!"
    exit 1
fi