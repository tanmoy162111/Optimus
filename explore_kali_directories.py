#!/usr/bin/env python3
"""Script to explore Kali VM directories and locate tool installations"""

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
    
    print("Exploring Kali VM directory structure to locate tool installations...")
    
    # Check common directories where tools are installed
    directories = [
        '/usr/bin',
        '/usr/sbin', 
        '/usr/local/bin',
        '/usr/local/sbin',
        '/home/kali/go/bin',
        '/home/kali/.local/bin',
        '/home/kali/.local/share/pipx/venvs',
        '/opt',
        '/usr/share',
        '/usr/lib'
    ]
    
    for directory in directories:
        try:
            stdin, stdout, stderr = ssh.exec_command(f'ls {directory} 2>/dev/null | head -10')
            files = stdout.read().decode().strip()
            if files:
                print(f"\n📁 {directory}:")
                file_list = files.split('\n')
                for file in file_list[:10]:  # Show first 10 files
                    if file:
                        print(f"  📄 {file}")
                if len(file_list) > 10:
                    print(f"  ... and {len(file_list) - 10} more files")
            else:
                print(f"\n📁 {directory}: (empty or inaccessible)")
        except Exception as e:
            print(f"\n📁 {directory}: Error accessing directory - {str(e)}")
    
    # Check specific security tool directories
    security_dirs = [
        '/usr/share/nmap',
        '/usr/share/dirb',
        '/usr/share/seclists',
        '/usr/share/wordlists',
        '/usr/share/metasploit-framework',
        '/usr/share/sqlmap',
        '/usr/share/nikto',
        '/usr/share/wpscan',
        '/usr/share/peass'
    ]
    
    print("\n\n🔍 Checking security tool specific directories:")
    for directory in security_dirs:
        try:
            stdin, stdout, stderr = ssh.exec_command(f'ls {directory} 2>/dev/null | head -5')
            files = stdout.read().decode().strip()
            if files:
                print(f"\n🛠️ {directory}:")
                file_list = files.split('\n')
                for file in file_list[:5]:  # Show first 5 files
                    if file:
                        print(f"  📄 {file}")
                if len(file_list) > 5:
                    print(f"  ... and {len(file_list) - 5} more files")
        except Exception as e:
            print(f"  {directory}: Not found or inaccessible")
    
    ssh.close()
    print("\n✅ Directory exploration complete.")

if __name__ == "__main__":
    main()