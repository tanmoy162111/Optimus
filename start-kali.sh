#!/bin/bash
# Start Kali VM Script

echo "============================================================"
echo "Starting Kali VM"
echo "============================================================"

VBOX_PATH="D:/Virtualbox/VBoxManage.exe"

# Check if Kali VM is already running
if "$VBOX_PATH" list runningvms | grep -q "kali"; then
    echo "Kali VM is already running."
    exit 0
fi

echo "Starting Kali VM in headless mode..."
"$VBOX_PATH" startvm "kali" --type headless

if [ $? -eq 0 ]; then
    echo "Kali VM started successfully!"
    echo "Waiting 60 seconds for Kali VM to boot and SSH service to start..."
    sleep 60
    echo "Kali VM is ready!"
else
    echo "Failed to start Kali VM!"
    exit 1
fi