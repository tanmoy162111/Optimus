"""
Test Kali VM SSH Connection
"""
from execution.ssh_client import KaliSSHClient
from config import Config

def test_connection():
    print("=" * 60)
    print("Testing Kali VM Connection")
    print("=" * 60)
    print(f"\nHost: {Config.KALI_HOST}")
    print(f"Port: {Config.KALI_PORT}")
    print(f"User: {Config.KALI_USER}")
    
    ssh = KaliSSHClient()
    
    print("\n[1] Testing SSH connection...")
    result = ssh.connect()
    
    if result:
        print("  [SUCCESS] Connected to Kali VM!")
        
        print("\n[2] Testing tool execution (whoami)...")
        cmd_result = ssh.execute_command('whoami')
        if cmd_result['success']:
            print(f"  [SUCCESS] User: {cmd_result['stdout'].strip()}")
        else:
            print(f"  [ERROR] {cmd_result.get('error', 'Unknown error')}")
        
        print("\n[3] Checking installed tools...")
        tools = ['nmap', 'nikto', 'sqlmap', 'metasploit']
        for tool in tools:
            check = ssh.execute_command(f'which {tool}', timeout=5)
            status = "[OK]" if check['success'] and check['stdout'].strip() else "[NOT FOUND]"
            print(f"  {status} {tool}")
        
        ssh.disconnect()
        print("\n[SUCCESS] All tests passed!")
        return True
    else:
        print(f"  [ERROR] Failed to connect")
        return False

if __name__ == "__main__":
    test_connection()