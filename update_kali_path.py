#!/usr/bin/env python3
"""
Script to permanently add Go bin directories to PATH on Kali VM
"""

import paramiko
import os
import sys
import inspect

# Add the parent directory to the path to import config
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from backend.config import Config

def connect_to_kali():
    """Connect to the Kali VM via SSH"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Use password authentication
        ssh.connect(
            Config.KALI_HOST,
            port=Config.KALI_PORT,
            username=Config.KALI_USER,
            password=Config.KALI_PASSWORD,
            timeout=Config.KALI_CONNECT_TIMEOUT
        )
        
        return ssh
    except Exception as e:
        print(f"Failed to connect to Kali VM: {e}")
        return None

def add_go_bin_to_path(ssh):
    """Add Go bin directories to PATH in .bashrc"""
    try:
        # Check if the PATH entries already exist in .bashrc
        stdin, stdout, stderr = ssh.exec_command("grep -q '/home/kali/go/bin' ~/.bashrc && echo 'exists' || echo 'not found'")
        result = stdout.read().decode().strip()
        
        if result == 'exists':
            print("Go bin directories already added to PATH")
            return True
        
        # Add Go bin directories to PATH
        add_path_cmd = "echo 'export PATH=$PATH:/home/kali/go/bin:/root/go/bin' >> ~/.bashrc"
        stdin, stdout, stderr = ssh.exec_command(add_path_cmd)
        
        # Check for errors
        error = stderr.read().decode().strip()
        if error:
            print(f"Error adding PATH: {error}")
            return False
        
        print("Successfully added Go bin directories to PATH")
        return True
    except Exception as e:
        print(f"Error adding Go bin to PATH: {e}")
        return False

def reload_bashrc(ssh):
    """Reload .bashrc to apply changes"""
    try:
        stdin, stdout, stderr = ssh.exec_command("source ~/.bashrc")
        # Note: This won't persist in subsequent commands, but it's good to try
        print("Reloaded .bashrc")
        return True
    except Exception as e:
        print(f"Error reloading .bashrc: {e}")
        return False

def verify_path_update(ssh):
    """Verify that PATH has been updated"""
    try:
        stdin, stdout, stderr = ssh.exec_command("echo $PATH")
        path = stdout.read().decode().strip()
        
        if '/home/kali/go/bin' in path:
            print("✅ PATH successfully updated")
            return True
        else:
            print("❌ PATH not updated")
            return False
    except Exception as e:
        print(f"Error verifying PATH update: {e}")
        return False

def main():
    print("Updating PATH on Kali VM...")
    print(f"Connecting to {Config.KALI_HOST}:{Config.KALI_PORT} as {Config.KALI_USER}\n")
    
    # Connect to Kali VM
    ssh = connect_to_kali()
    if not ssh:
        print("❌ Failed to connect to Kali VM")
        return
    
    # Add Go bin directories to PATH
    print("Adding Go bin directories to PATH...")
    if add_go_bin_to_path(ssh):
        print("✅ Successfully added Go bin directories to PATH")
        
        # Try to reload .bashrc
        print("Reloading .bashrc...")
        reload_bashrc(ssh)
        
        # Verify the update
        print("Verifying PATH update...")
        verify_path_update(ssh)
        
        print("\n📝 Instructions:")
        print("  To make the PATH changes permanent for all future sessions,")
        print("  please log out and log back in to the Kali VM, or restart the VM.")
        print("  Alternatively, you can run 'source ~/.bashrc' in any new terminal session.")
    else:
        print("❌ Failed to add Go bin directories to PATH")
    
    ssh.close()

if __name__ == "__main__":
    main()