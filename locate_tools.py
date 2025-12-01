#!/usr/bin/env python3
"""
Script to help locate tools on the Kali VM by searching in common directories
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

def search_for_tool(ssh, tool_name):
    """Search for a tool in common directories"""
    try:
        # Search in common directories
        search_paths = [
            "/usr/bin",
            "/usr/local/bin",
            "/opt",
            "/home/kali/go/bin",  # Go tools often installed here
            "/root/go/bin"
        ]
        
        for path in search_paths:
            stdin, stdout, stderr = ssh.exec_command(f"find {path} -name '{tool_name}' -type f 2>/dev/null")
            result = stdout.read().decode().strip()
            if result:
                return result.split('\n')
        
        # If not found in common paths, search everywhere (this might take a while)
        stdin, stdout, stderr = ssh.exec_command(f"find / -name '{tool_name}' -type f 2>/dev/null | head -5")
        result = stdout.read().decode().strip()
        if result:
            return result.split('\n')
            
        return []
    except Exception as e:
        print(f"Error searching for {tool_name}: {e}")
        return []

def check_if_executable(ssh, file_path):
    """Check if a file is executable"""
    try:
        stdin, stdout, stderr = ssh.exec_command(f"test -x '{file_path}' && echo 'executable' || echo 'not executable'")
        result = stdout.read().decode().strip()
        return result == 'executable'
    except Exception as e:
        print(f"Error checking if {file_path} is executable: {e}")
        return False

def main():
    print("Searching for tools on Kali VM...")
    print(f"Connecting to {Config.KALI_HOST}:{Config.KALI_PORT} as {Config.KALI_USER}\n")
    
    # Connect to Kali VM
    ssh = connect_to_kali()
    if not ssh:
        print("❌ Failed to connect to Kali VM")
        return
    
    # List of tools to search for
    tools_to_search = [
        'dalfox', 'xsser', 'nuclei', 'subfinder', 
        'gospider', 'katana', 'arjun', 'httprobe', 
        'netlas', 'onyphe'
    ]
    
    print(f"Searching for {len(tools_to_search)} tools in common directories...\n")
    
    found_tools = {}
    
    # Search for each tool
    for tool in tools_to_search:
        print(f"Searching for {tool}...")
        paths = search_for_tool(ssh, tool)
        if paths and paths != ['']:
            found_tools[tool] = paths
            print(f"  Found {len(paths)} instances:")
            for path in paths:
                if path:  # Skip empty strings
                    is_executable = check_if_executable(ssh, path)
                    exec_status = "✅ executable" if is_executable else "❌ not executable"
                    print(f"    {path} ({exec_status})")
        else:
            print(f"  Not found")
        print()
    
    # Summary
    print("📊 Summary:")
    print(f"  Tools searched: {len(tools_to_search)}")
    print(f"  Tools found: {len(found_tools)}")
    
    if found_tools:
        print("\n📁 Found tools and their locations:")
        for tool, paths in found_tools.items():
            print(f"  {tool}:")
            for path in paths:
                if path:  # Skip empty strings
                    is_executable = check_if_executable(ssh, path)
                    exec_status = "✅" if is_executable else "❌"
                    print(f"    {exec_status} {path}")
    
    ssh.close()

if __name__ == "__main__":
    main()