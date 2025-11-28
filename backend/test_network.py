"""Network Diagnostic Script
Tests connectivity between Windows host and Kali VM
"""
import socket
import paramiko
import time
from config import Config

def test_tcp_connection():
    """Test raw TCP connection to Kali SSH port"""
    print("\n" + "="*60)
    print("TEST 1: TCP Connection to Kali VM")
    print("="*60)
    
    try:
        print(f"Attempting TCP connection to {Config.KALI_HOST}:{Config.KALI_PORT}...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        start_time = time.time()
        result = sock.connect_ex((Config.KALI_HOST, Config.KALI_PORT))
        elapsed = time.time() - start_time
        
        if result == 0:
            print(f"✅ TCP connection successful ({elapsed:.2f}s)")
            sock.close()
            return True
        else:
            print(f"❌ TCP connection failed with error code: {result}")
            return False
            
    except socket.timeout:
        print(f"❌ TCP connection timeout after 10 seconds")
        return False
    except Exception as e:
        print(f"❌ TCP connection error: {e}")
        return False

def test_ssh_banner():
    """Test SSH banner exchange"""
    print("\n" + "="*60)
    print("TEST 2: SSH Banner Exchange")
    print("="*60)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((Config.KALI_HOST, Config.KALI_PORT))
        
        # Read SSH banner
        banner = sock.recv(1024).decode('utf-8').strip()
        print(f"✅ SSH banner received: {banner}")
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ SSH banner exchange failed: {e}")
        return False

def test_ssh_authentication():
    """Test SSH authentication"""
    print("\n" + "="*60)
    print("TEST 3: SSH Authentication")
    print("="*60)
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"Connecting to {Config.KALI_USER}@{Config.KALI_HOST}...")
        
        start_time = time.time()
        client.connect(
            hostname=Config.KALI_HOST,
            port=Config.KALI_PORT,
            username=Config.KALI_USER,
            password=Config.KALI_PASSWORD,
            timeout=30,
            look_for_keys=False,
            allow_agent=False
        )
        elapsed = time.time() - start_time
        
        print(f"✅ SSH authentication successful ({elapsed:.2f}s)")
        client.close()
        return True
        
    except paramiko.AuthenticationException as e:
        print(f"❌ SSH authentication failed: {e}")
        print(f"   Username: {Config.KALI_USER}")
        print(f"   Check password in .env file")
        return False
    except Exception as e:
        print(f"❌ SSH connection error: {e}")
        return False

def test_command_execution():
    """Test command execution"""
    print("\n" + "="*60)
    print("TEST 4: Command Execution")
    print("="*60)
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            hostname=Config.KALI_HOST,
            port=Config.KALI_PORT,
            username=Config.KALI_USER,
            password=Config.KALI_PASSWORD,
            timeout=30
        )
        
        # Test simple command
        stdin, stdout, stderr = client.exec_command('whoami', timeout=10)
        output = stdout.read().decode().strip()
        
        print(f"✅ Command execution successful")
        print(f"   User: {output}")
        
        # Test tool availability
        tools = ['nmap', 'nikto', 'sqlmap']
        for tool in tools:
            stdin, stdout, stderr = client.exec_command(f'which {tool}', timeout=10)
            path = stdout.read().decode().strip()
            if path:
                print(f"   ✅ {tool}: {path}")
            else:
                print(f"   ⚠️  {tool}: NOT FOUND")
        
        client.close()
        return True
        
    except Exception as e:
        print(f"❌ Command execution failed: {e}")
        return False

def test_firewall_rules():
    """Check for common firewall issues"""
    print("\n" + "="*60)
    print("TEST 5: Firewall Check")
    print("="*60)
    
    print("Common Windows Firewall issues:")
    print("  1. Windows Firewall blocking outbound SSH (port 22)")
    print("  2. VirtualBox network adapter not configured")
    print("  3. Kali VM network mode incorrect (should be Bridged or NAT)")
    print("")
    print("Recommendations:")
    print("  • Add firewall rule: netsh advfirewall firewall add rule name=\"SSH to Kali\" dir=out action=allow protocol=TCP localport=22")
    print("  • Check VirtualBox network: Bridged Adapter or NAT with port forwarding")
    print("  • Verify Kali VM IP: ip addr show")
    print("  • Test from Kali: ping <windows-host-ip>")

def main():
    """Run all diagnostic tests"""
    print("\n" + "="*70)
    print("NETWORK DIAGNOSTIC TOOL - Windows to Kali VM")
    print("="*70)
    print(f"Target: {Config.KALI_USER}@{Config.KALI_HOST}:{Config.KALI_PORT}")
    
    results = {
        'TCP Connection': test_tcp_connection(),
        'SSH Banner': test_ssh_banner(),
        'SSH Authentication': test_ssh_authentication(),
        'Command Execution': test_command_execution()
    }
    
    test_firewall_rules()
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:25s}: {status}")
    
    passed = sum(results.values())
    total = len(results)
    
    print(f"\nTests passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ All tests passed! Network connectivity is good.")
    else:
        print("\n❌ Some tests failed. Check the errors above.")
        
        print("\nTroubleshooting steps:")
        print("1. Verify Kali VM is running: VirtualBox Manager")
        print("2. Check Kali IP: Run 'ip addr show' in Kali VM")
        print("3. Test ping from Windows: ping <kali-ip>")
        print("4. Check Windows Firewall rules")
        print("5. Verify VirtualBox network adapter settings")

if __name__ == '__main__':
    main()