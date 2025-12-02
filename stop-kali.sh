#!/bin/bash
# Stop Kali VM Script
echo "============================================================"
echo "Stopping Kali VM"
echo "============================================================"
VBOX_PATH="/d/Virtualbox/VBoxManage.exe"

# Check if VBoxManage exists
if [ ! -f "$VBOX_PATH" ]; then
    echo "ERROR: VirtualBox not found at $VBOX_PATH"
    echo "Please check your VirtualBox installation path."
    exit 1
fi

# Check if Kali VM is running
if cmd.exe //c "$VBOX_PATH list runningvms | findstr kali" > /dev/null 2>&1; then
    echo "Kali VM is running. Stopping it..."
    "$VBOX_PATH" controlvm "kali" poweroff
    if [ $? -eq 0 ]; then
        echo "Kali VM stopped successfully!"
        # Wait a moment for the VM to fully shut down
        cmd.exe //c "ping -n 11 127.0.0.1 > nul"
    else
        echo "Failed to stop Kali VM!"
        exit 1
    fi
else
    echo "Kali VM is not running."
fi