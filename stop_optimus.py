#!/usr/bin/env python3
"""
Stop Optimus Components Script

This script stops all Optimus components (Kali VM, Backend, Frontend).
"""

import os
import sys
import subprocess
import time
import psutil

def check_virtualbox():
    """Check if VirtualBox is installed and accessible"""
    vbox_path = r"D:\Virtualbox\VBoxManage.exe"
    if not os.path.exists(vbox_path):
        print("ERROR: VirtualBox not found at", vbox_path)
        print("Please check your VirtualBox installation path.")
        return None
    return vbox_path

def is_kali_running(vbox_path):
    """Check if Kali VM is already running"""
    try:
        result = subprocess.run([vbox_path, "list", "runningvms"], 
                              capture_output=True, text=True, timeout=10)
        return "kali" in result.stdout.lower()
    except Exception as e:
        print(f"Warning: Could not check Kali VM status: {e}")
        return False

def stop_kali_vm(vbox_path):
    """Stop Kali VM if running"""
    print("Checking Kali VM status...")
    
    if not is_kali_running(vbox_path):
        print("Kali VM is not running.")
        return True
    
    try:
        print("Stopping Kali VM...")
        result = subprocess.run([vbox_path, "controlvm", "kali", "poweroff"],
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("Kali VM stopped successfully!")
            # Wait for VM to fully shut down
            time.sleep(10)
            return True
        else:
            print(f"Failed to stop Kali VM: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error stopping Kali VM: {e}")
        return False

def kill_processes_by_name(name):
    """Kill all processes with the given name"""
    killed = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] and name.lower() in proc.info['name'].lower():
                # Check if it's related to our app
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                if 'app.py' in cmdline or 'optimus' in cmdline.lower() or 'vite' in cmdline.lower() or 'node' in cmdline.lower():
                    print(f"Terminating process {proc.info['name']} (PID: {proc.info['pid']})")
                    proc.kill()
                    killed = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return killed

def stop_backend():
    """Stop Backend Server"""
    print("Stopping Backend Server...")
    
    # Try to kill Python processes running app.py
    if kill_processes_by_name("python"):
        print("Backend server stopped.")
    else:
        print("No backend server processes found.")

def stop_frontend():
    """Stop Frontend Dev Server"""
    print("Stopping Frontend Dev Server...")
    
    # Try to kill Node.js processes related to Vite/dev server
    killed_node = kill_processes_by_name("node")
    killed_npm = kill_processes_by_name("npm")
    
    if killed_node or killed_npm:
        print("Frontend dev server stopped.")
    else:
        print("No frontend dev server processes found.")

def main():
    """Main function to stop all Optimus components"""
    print("=" * 60)
    print("Stopping Optimus Components")
    print("=" * 60)
    
    # Check VirtualBox installation
    vbox_path = check_virtualbox()
    if not vbox_path:
        # Continue anyway to stop other components
        pass
    
    # Stop Kali VM
    if vbox_path:
        stop_kali_vm(vbox_path)
    
    # Stop Backend
    stop_backend()
    
    # Stop Frontend
    stop_frontend()
    
    print("\n" + "=" * 60)
    print("All Optimus Components Stopped!")
    print("=" * 60)

if __name__ == "__main__":
    main()