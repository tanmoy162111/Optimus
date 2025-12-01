#!/usr/bin/env python3
"""Script to count total tools installed on Kali VM"""

import paramiko
from backend.config import Config

def main():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        Config.KALI_HOST,
        port=Config.KALI_PORT,
        username=Config.KALI_USER,
        password=Config.KALI_PASSWORD
    )
    
    # Directories to check for tools
    directories = [
        '/usr/bin',
        '/usr/sbin',
        '/usr/local/bin',
        '/usr/local/sbin'
    ]
    
    total_tools = 0
    print("Counting tools installed on Kali VM...")
    
    for directory in directories:
        try:
            stdin, stdout, stderr = ssh.exec_command(f'ls {directory} 2>/dev/null | wc -l')
            count = int(stdout.read().decode().strip())
            print(f'{directory}: {count} tools')
            total_tools += count
        except Exception as e:
            print(f'Error counting tools in {directory}: {str(e)}')
    
    # Also check Go bin and local bin directories
    extra_directories = [
        '/home/kali/go/bin',
        '/home/kali/.local/bin'
    ]
    
    print("\nChecking additional tool directories:")
    for directory in extra_directories:
        try:
            stdin, stdout, stderr = ssh.exec_command(f'ls {directory} 2>/dev/null | wc -l')
            count = int(stdout.read().decode().strip())
            print(f'{directory}: {count} tools')
            total_tools += count
        except Exception as e:
            print(f'{directory}: 0 tools (directory not found or inaccessible)')
    
    print(f"\nEstimated total tools installed on Kali VM: {total_tools}")
    
    # Try to get a more accurate count using the standard Kali tools approach
    print("\nGetting count of Kali-specific tools...")
    try:
        stdin, stdout, stderr = ssh.exec_command('which apt >/dev/null && apt list --installed 2>/dev/null | grep kali | wc -l')
        kali_packages = stdout.read().decode().strip()
        if kali_packages and kali_packages != '0':
            print(f'Kali-specific packages installed: {kali_packages}')
        else:
            print('Unable to determine Kali-specific package count')
    except Exception as e:
        print(f'Error getting Kali package count: {str(e)}')
    
    ssh.close()

if __name__ == "__main__":
    main()