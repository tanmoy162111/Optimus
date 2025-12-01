#!/usr/bin/env python3
"""
Simple script to check tools installed on Kali VM
"""

import paramiko
from backend.config import Config

def main():
    # Connect to Kali VM
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        Config.KALI_HOST,
        port=Config.KALI_PORT,
        username=Config.KALI_USER,
        password=Config.KALI_PASSWORD,
        timeout=Config.KALI_CONNECT_TIMEOUT
    )
    
    # Check tools in /usr/bin
    print("Tools in /usr/bin:")
    stdin, stdout, stderr = ssh.exec_command('ls /usr/bin | grep -E "(arjun|dalfox|gospider|httprobe|katana|netlas|nuclei|onyphe|subfinder|xsser)"')
    result = stdout.read().decode().strip()
    print(result if result else "None found")
    
    print("\nTools in /home/kali/go/bin:")
    stdin, stdout, stderr = ssh.exec_command('ls /home/kali/go/bin')
    result = stdout.read().decode().strip()
    print(result if result else "None found")
    
    print("\nTools in /home/kali/.local/share/pipx/venvs:")
    stdin, stdout, stderr = ssh.exec_command('ls /home/kali/.local/share/pipx/venvs')
    result = stdout.read().decode().strip()
    print(result if result else "None found")
    
    ssh.close()

if __name__ == "__main__":
    main()