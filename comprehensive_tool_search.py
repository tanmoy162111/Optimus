#!/usr/bin/env python3
"""
Script to comprehensively search for tools in all directories on Kali VM
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

def search_all_directories(ssh):
    """Search for tools in all directories on Kali VM"""
    tools = ['arjun', 'dalfox', 'gospider', 'httprobe', 'katana', 'netlas', 'nuclei', 'onyphe', 'subfinder', 'xsser']
    print("Searching for tools in all directories on Kali VM...")
    print("This may take a few minutes...\n")
    
    # Common search paths
    search_paths = [
        '/usr/bin',
        '/usr/local/bin',
        '/opt',
        '/home/kali/go/bin',
        '/root/go/bin',
        '/usr/share',
        '/snap/bin'
    ]
    
    found_tools = {}
    
    for tool in tools:
        print(f"Searching for {tool}...")
        found_locations = []
        
        # Search in common paths first
        for path in search_paths:
            stdin, stdout, stderr = ssh.exec_command(f'find {path} -name "{tool}" -type f 2>/dev/null')
            result = stdout.read().decode().strip()
            if result:
                found_locations.extend(result.split('\n'))
        
        # If not found in common paths, search everywhere (this will take longer)
        if not found_locations:
            stdin, stdout, stderr = ssh.exec_command(f'find / -name "{tool}" -type f 2>/dev/null | head -5')
            result = stdout.read().decode().strip()
            if result:
                found_locations.extend(result.split('\n'))
        
        # Filter out empty strings
        found_locations = [loc for loc in found_locations if loc]
        
        if found_locations:
            found_tools[tool] = found_locations
            print(f"  ✅ {tool}:")
            for loc in found_locations[:3]:  # Show only first 3 locations
                print(f"    - {loc}")
            if len(found_locations) > 3:
                print(f"    ... and {len(found_locations) - 3} more")
        else:
            print(f"  ❌ {tool}: not found")
        print()
    
    return found_tools

def main():
    print("Comprehensive tool search on Kali VM...")
    print(f"Connecting to {Config.KALI_HOST}:{Config.KALI_PORT} as {Config.KALI_USER}\n")
    
    # Connect to Kali VM
    ssh = connect_to_kali()
    if not ssh:
        print("❌ Failed to connect to Kali VM")
        return
    
    # Search all directories
    found_tools = search_all_directories(ssh)
    
    # Summary
    print("📊 Summary:")
    print(f"  Tools searched: 10")
    print(f"  Tools found: {len(found_tools)}")
    if found_tools:
        print("  Found tools:")
        for tool, locations in found_tools.items():
            print(f"    - {tool}: {len(locations)} location(s)")
    
    ssh.close()

if __name__ == "__main__":
    main()