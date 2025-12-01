#!/usr/bin/env python3
"""
Script to check what tools are currently installed on the Kali VM
and compare them with what the agent expects
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
from inference.dynamic_tool_database import DynamicToolDatabase

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

def check_tool_installed(ssh, tool_name):
    """Check if a tool is installed on the Kali VM"""
    try:
        # For tools that might be in different locations, check multiple paths
        commands = [
            f"which {tool_name}",
            f"command -v {tool_name}",
            f"ls /usr/bin/{tool_name} 2>/dev/null",
            f"ls /usr/sbin/{tool_name} 2>/dev/null"
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            if output and "not found" not in output and output != "":
                return True, output
        
        return False, ""
    except Exception as e:
        return False, str(e)

def get_installed_tools(ssh, tool_list):
    """Get list of installed tools"""
    installed = []
    missing = []
    
    for tool in tool_list:
        is_installed, path = check_tool_installed(ssh, tool)
        if is_installed:
            installed.append((tool, path))
        else:
            missing.append(tool)
    
    return installed, missing

def main():
    print("Checking tools installed on Kali VM...")
    print(f"Connecting to {Config.KALI_HOST}:{Config.KALI_PORT} as {Config.KALI_USER}")
    
    # Connect to Kali VM
    ssh = connect_to_kali()
    if not ssh:
        print("Cannot connect to Kali VM. Please make sure it's running and accessible.")
        return
    
    try:
        # Get list of tools from the database
        tool_db = DynamicToolDatabase()
        expected_tools = list(tool_db.tools.keys())
        
        print(f"\nChecking {len(expected_tools)} tools...")
        
        # Check which tools are installed
        installed, missing = get_installed_tools(ssh, expected_tools)
        
        print(f"\n✓ Installed tools ({len(installed)}):")
        for tool, path in installed:
            print(f"  - {tool}: {path}")
        
        if missing:
            print(f"\n✗ Missing tools ({len(missing)}):")
            for tool in missing:
                print(f"  - {tool}")
        else:
            print(f"\n🎉 All {len(expected_tools)} tools are installed!")
        
        # Show tools by category
        print(f"\n📊 Tool Categories:")
        categories = {}
        for tool_name, tool_info in tool_db.tools.items():
            category = tool_info.get('category', 'unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(tool_name)
        
        for category, tools in categories.items():
            installed_count = sum(1 for tool in tools if tool in [t[0] for t in installed])
            print(f"  {category}: {installed_count}/{len(tools)} tools installed")
            
        # Summary
        print(f"\n📊 Summary:")
        print(f"  Total tools expected: {len(expected_tools)}")
        print(f"  Tools installed: {len(installed)}")
        print(f"  Tools missing: {len(missing)}")
        if len(missing) > 0:
            print(f"  Installation progress: {len(installed)}/{len(expected_tools)} ({100*len(installed)/len(expected_tools):.1f}%)")
        else:
            print(f"  Installation progress: 100% - All tools available!")
            
    finally:
        ssh.close()

if __name__ == "__main__":
    main()