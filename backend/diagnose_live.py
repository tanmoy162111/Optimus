#!/usr/bin/env python3
"""
Quick diagnostic script to test Optimus scan components
Run from backend directory: python diagnose_live.py
"""

import sys
import os
from pathlib import Path

# Add backend to path
BACKEND_DIR = Path(__file__).parent
if BACKEND_DIR.name != 'backend':
    BACKEND_DIR = BACKEND_DIR / 'backend'
sys.path.insert(0, str(BACKEND_DIR))

def test_kali_connection():
    """Test SSH connection to Kali VM"""
    print("\n" + "="*60)
    print("TEST: Kali VM SSH Connection")
    print("="*60)
    
    try:
        from config import Config
        print(f"  Kali Host: {Config.KALI_HOST}")
        print(f"  Kali Port: {Config.KALI_PORT}")
        print(f"  Kali User: {Config.KALI_USER}")
        print(f"  Connect Timeout: {Config.KALI_CONNECT_TIMEOUT}s")
        
        import paramiko
        import socket
        
        # Quick socket test first
        print(f"\n  Testing TCP connection to {Config.KALI_HOST}:{Config.KALI_PORT}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            result = sock.connect_ex((Config.KALI_HOST, Config.KALI_PORT))
            if result == 0:
                print(f"  ✅ TCP port {Config.KALI_PORT} is OPEN")
            else:
                print(f"  ❌ TCP port {Config.KALI_PORT} is CLOSED (error {result})")
                print(f"     Is your Kali VM running? Is SSH enabled?")
                return False
        finally:
            sock.close()
        
        # Now test SSH
        print(f"\n  Testing SSH authentication...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                hostname=Config.KALI_HOST,
                port=Config.KALI_PORT,
                username=Config.KALI_USER,
                password=Config.KALI_PASSWORD,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            print(f"  ✅ SSH connection SUCCESSFUL!")
            
            # Test command execution
            print(f"\n  Testing command execution...")
            stdin, stdout, stderr = client.exec_command('whoami', timeout=5)
            output = stdout.read().decode().strip()
            print(f"  ✅ Command executed! whoami = '{output}'")
            
            # Test tool availability
            print(f"\n  Testing tool availability...")
            stdin, stdout, stderr = client.exec_command('which nmap', timeout=5)
            nmap_path = stdout.read().decode().strip()
            if nmap_path:
                print(f"  ✅ nmap found at: {nmap_path}")
            else:
                print(f"  ⚠️ nmap not found in PATH")
            
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            print(f"  ❌ SSH authentication FAILED!")
            print(f"     Check username/password in .env file")
            return False
        except paramiko.SSHException as e:
            print(f"  ❌ SSH error: {e}")
            return False
        except socket.timeout:
            print(f"  ❌ SSH connection TIMEOUT!")
            print(f"     The Kali VM is not responding to SSH")
            return False
            
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scan_manager():
    """Test scan manager initialization"""
    print("\n" + "="*60)
    print("TEST: Scan Manager")
    print("="*60)
    
    try:
        from core.scan_engine import ScanManager
        
        # Create with None socketio for testing
        manager = ScanManager(socketio=None, active_scans_ref={})
        
        print(f"  ✅ ScanManager created")
        print(f"     tool_manager: {manager.tool_manager is not None}")
        print(f"     agent_class: {manager.agent_class is not None}")
        
        if manager.agent_class is None:
            print(f"  ❌ Agent class not loaded - check imports")
            return False
            
        return True
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_agent_creation():
    """Test autonomous agent creation"""
    print("\n" + "="*60)
    print("TEST: Autonomous Agent Creation")
    print("="*60)
    
    try:
        from inference.autonomous_agent import AutonomousPentestAgent
        
        print("  Creating agent (this may take a moment)...")
        agent = AutonomousPentestAgent(socketio=None)
        
        print(f"  ✅ Agent created successfully")
        print(f"     tool_manager: {agent.tool_manager is not None}")
        print(f"     tool_selector: {agent.tool_selector is not None}")
        print(f"     phase_controller: {agent.phase_controller is not None}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tool_execution():
    """Test a simple tool execution (if Kali is available)"""
    print("\n" + "="*60)
    print("TEST: Tool Execution (nmap quick scan)")
    print("="*60)
    
    try:
        from inference.tool_manager import ToolManager
        
        print("  Creating ToolManager...")
        tm = ToolManager(socketio=None)
        
        print("  Connecting to Kali VM...")
        tm.connect_ssh()
        
        print("  ✅ SSH connected!")
        print("  Executing: nmap --version")
        
        # Just test nmap version
        stdin, stdout, stderr = tm.ssh_client.exec_command('nmap --version', timeout=10)
        output = stdout.read().decode()
        
        if 'Nmap' in output:
            version_line = output.split('\n')[0]
            print(f"  ✅ nmap available: {version_line}")
            return True
        else:
            print(f"  ⚠️ nmap output unexpected: {output[:100]}")
            return False
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("\n" + "="*60)
    print("OPTIMUS LIVE DIAGNOSTIC")
    print("="*60)
    print("This will test your current setup...")
    
    results = {}
    
    # Test 1: Kali Connection (most important)
    results['Kali SSH'] = test_kali_connection()
    
    # Test 2: Scan Manager
    results['Scan Manager'] = test_scan_manager()
    
    # Test 3: Agent Creation
    results['Agent Creation'] = test_agent_creation()
    
    # Test 4: Tool Execution (only if SSH works)
    if results.get('Kali SSH'):
        results['Tool Execution'] = test_tool_execution()
    else:
        print("\n⚠️ Skipping tool execution test (Kali SSH failed)")
        results['Tool Execution'] = False
    
    # Summary
    print("\n" + "="*60)
    print("DIAGNOSTIC SUMMARY")
    print("="*60)
    
    for test, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {test}")
    
    failed = [k for k, v in results.items() if not v]
    
    if failed:
        print(f"\n❌ {len(failed)} test(s) failed: {', '.join(failed)}")
        
        if 'Kali SSH' in failed:
            print("\n⚠️ CRITICAL: Kali VM connection failed!")
            print("   This is why your scans aren't working.")
            print("   Fix suggestions:")
            print("   1. Make sure Kali VM is running")
            print("   2. Check SSH service: sudo service ssh status")
            print("   3. Verify port forwarding (2222 -> 22)")
            print("   4. Check .env file has correct credentials")
    else:
        print("\n🎉 All tests passed! Your setup looks good.")
    
    return 0 if not failed else 1


if __name__ == '__main__':
    sys.exit(main())
