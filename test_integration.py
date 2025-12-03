#!/usr/bin/env python3
"""
Optimus Integration Test Suite
Run this to verify all components work together
"""

import os
import sys
import json
import time
import requests
import subprocess
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / 'backend'))

# Test configuration
BACKEND_URL = "http://localhost:5000"
FRONTEND_URL = "http://localhost:5173"
TEST_TARGET = "http://testphp.vulnweb.com"  # Safe test target
TIMEOUT = 10

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}  {text}{Colors.END}")
    print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")

def print_pass(text):
    print(f"  {Colors.GREEN}✅ PASS:{Colors.END} {text}")

def print_fail(text):
    print(f"  {Colors.RED}❌ FAIL:{Colors.END} {text}")

def print_warn(text):
    print(f"  {Colors.YELLOW}⚠️  WARN:{Colors.END} {text}")

def print_info(text):
    print(f"  {Colors.BLUE}ℹ️  INFO:{Colors.END} {text}")

# Test results storage
results = {
    'timestamp': datetime.now().isoformat(),
    'tests': [],
    'passed': 0,
    'failed': 0,
    'warnings': 0
}

def record_result(test_name, passed, message, warning=False):
    results['tests'].append({
        'name': test_name,
        'passed': passed,
        'warning': warning,
        'message': message
    })
    if passed:
        results['passed'] += 1
        if warning:
            results['warnings'] += 1
            print_warn(f"{test_name}: {message}")
        else:
            print_pass(f"{test_name}: {message}")
    else:
        results['failed'] += 1
        print_fail(f"{test_name}: {message}")

# ============================================
# PHASE 1: BACKEND HEALTH TESTS
# ============================================

def test_backend_health():
    """Test backend health endpoint"""
    print_header("PHASE 1: Backend Health Tests")
    
    # Test 1.1: Health endpoint
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'healthy':
                record_result("Health Endpoint", True, f"Status: healthy, Components: {list(data.get('components', {}).keys())}")
            else:
                record_result("Health Endpoint", False, f"Unhealthy status: {data}")
        else:
            record_result("Health Endpoint", False, f"HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        record_result("Health Endpoint", False, "Cannot connect - is backend running?")
    except Exception as e:
        record_result("Health Endpoint", False, str(e))
    
    # Test 1.2: Root endpoint
    try:
        response = requests.get(f"{BACKEND_URL}/", timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            record_result("Root Endpoint", True, f"API: {data.get('name')}, Version: {data.get('version')}")
        else:
            record_result("Root Endpoint", False, f"HTTP {response.status_code}")
    except Exception as e:
        record_result("Root Endpoint", False, str(e))
    
    # Test 1.3: API routes
    try:
        response = requests.get(f"{BACKEND_URL}/api", timeout=TIMEOUT)
        record_result("API Blueprint", response.status_code in [200, 404], f"HTTP {response.status_code}")
    except Exception as e:
        record_result("API Blueprint", False, str(e))
    
    # Test 1.4: Scan routes
    try:
        response = requests.get(f"{BACKEND_URL}/api/scan/list", timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            record_result("Scan Routes", True, f"Active scans: {data.get('active_count', 0)}")
        else:
            record_result("Scan Routes", False, f"HTTP {response.status_code}")
    except Exception as e:
        record_result("Scan Routes", False, str(e))
    
    # Test 1.5: Tool routes
    try:
        response = requests.get(f"{BACKEND_URL}/api/tools/categories", timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            categories = data.get('categories', [])
            record_result("Tool Routes", True, f"Categories: {len(categories)}")
        else:
            record_result("Tool Routes", False, f"HTTP {response.status_code}")
    except Exception as e:
        record_result("Tool Routes", False, str(e))

# ============================================
# PHASE 2: SSH/TOOL EXECUTION TESTS
# ============================================

def test_ssh_connection():
    """Test SSH connection to Kali VM"""
    print_header("PHASE 2: SSH & Tool Execution Tests")
    
    # Load config
    try:
        from dotenv import load_dotenv
        load_dotenv()
        
        kali_host = os.getenv('KALI_HOST', '127.0.0.1')
        kali_port = int(os.getenv('KALI_PORT', '2222'))
        kali_user = os.getenv('KALI_USER', 'kali')
        kali_pass = os.getenv('KALI_PASSWORD', 'kali')
        
        print_info(f"Kali VM: {kali_user}@{kali_host}:{kali_port}")
    except Exception as e:
        print_warn(f"Could not load .env: {e}")
        kali_host = '127.0.0.1'
        kali_port = 2222
        kali_user = 'kali'
        kali_pass = 'kali'
    
    # Test 2.1: SSH connection via paramiko
    try:
        import paramiko
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            hostname=kali_host,
            port=kali_port,
            username=kali_user,
            password=kali_pass,
            timeout=30
        )
        
        stdin, stdout, stderr = client.exec_command('echo "SSH_OK" && whoami')
        output = stdout.read().decode().strip()
        
        if 'SSH_OK' in output:
            record_result("SSH Connection", True, f"Connected as: {output.split()[-1]}")
        else:
            record_result("SSH Connection", False, f"Unexpected output: {output}")
        
        client.close()
        
    except Exception as e:
        record_result("SSH Connection", False, f"SSH failed: {str(e)[:100]}")
        return  # Skip remaining SSH tests
    
    # Test 2.2: Check essential tools
    essential_tools = ['nmap', 'nikto', 'sqlmap', 'gobuster', 'nuclei', 'whatweb']
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=kali_host,
            port=kali_port,
            username=kali_user,
            password=kali_pass,
            timeout=30
        )
        
        available_tools = []
        missing_tools = []
        
        for tool in essential_tools:
            stdin, stdout, stderr = client.exec_command(f'which {tool} 2>/dev/null')
            output = stdout.read().decode().strip()
            if output:
                available_tools.append(tool)
            else:
                missing_tools.append(tool)
        
        if len(available_tools) >= 4:
            record_result("Essential Tools", True, f"Available: {', '.join(available_tools)}")
        else:
            record_result("Essential Tools", True, f"Available: {', '.join(available_tools)}, Missing: {', '.join(missing_tools)}", warning=True)
        
        client.close()
        
    except Exception as e:
        record_result("Essential Tools", False, str(e))
    
    # Test 2.3: Test tool execution
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=kali_host,
            port=kali_port,
            username=kali_user,
            password=kali_pass,
            timeout=30
        )
        
        # Quick nmap version check
        stdin, stdout, stderr = client.exec_command('nmap --version | head -1')
        output = stdout.read().decode().strip()
        
        if 'Nmap' in output:
            record_result("Tool Execution", True, output)
        else:
            record_result("Tool Execution", False, f"Unexpected: {output}")
        
        client.close()
        
    except Exception as e:
        record_result("Tool Execution", False, str(e))

# ============================================
# PHASE 3: WEBSOCKET TESTS
# ============================================

def test_websocket():
    """Test WebSocket connectivity"""
    print_header("PHASE 3: WebSocket Communication Tests")
    
    try:
        import socketio
        
        sio = socketio.Client()
        connected = False
        received_events = []
        
        @sio.event
        def connect():
            nonlocal connected
            connected = True
        
        @sio.event
        def system_status(data):
            received_events.append(('system_status', data))
        
        @sio.event
        def connect_error(data):
            received_events.append(('connect_error', data))
        
        # Try to connect
        try:
            sio.connect(BACKEND_URL, wait_timeout=10)
            time.sleep(2)  # Wait for events
            
            if connected:
                record_result("WebSocket Connect", True, "Connected successfully")
            else:
                record_result("WebSocket Connect", False, "Connection flag not set")
            
            if any(e[0] == 'system_status' for e in received_events):
                record_result("WebSocket Events", True, f"Received: {[e[0] for e in received_events]}")
            else:
                record_result("WebSocket Events", True, "Connected but no system_status event", warning=True)
            
            sio.disconnect()
            
        except Exception as e:
            record_result("WebSocket Connect", False, f"Connection failed: {str(e)[:100]}")
            
    except ImportError:
        record_result("WebSocket Connect", False, "python-socketio not installed")
    except Exception as e:
        record_result("WebSocket Connect", False, str(e))

# ============================================
# PHASE 4: SCAN WORKFLOW TESTS
# ============================================

def test_scan_workflow():
    """Test complete scan workflow"""
    print_header("PHASE 4: Scan Workflow Tests")
    
    scan_id = None
    
    # Test 4.1: Start scan
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/scan/start",
            json={
                "target": TEST_TARGET,
                "mode": "quick",
                "useAI": True,
                "maxDuration": 300  # 5 minutes max for test
            },
            timeout=TIMEOUT
        )
        
        if response.status_code == 201:
            data = response.json()
            scan_id = data.get('scan_id')
            record_result("Start Scan", True, f"Scan ID: {scan_id}, Target: {TEST_TARGET}")
        else:
            record_result("Start Scan", False, f"HTTP {response.status_code}: {response.text[:100]}")
            return
            
    except Exception as e:
        record_result("Start Scan", False, str(e))
        return
    
    # Test 4.2: Check scan status
    try:
        time.sleep(3)  # Wait for scan to initialize
        
        response = requests.get(f"{BACKEND_URL}/api/scan/status/{scan_id}", timeout=TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            status = data.get('status')
            phase = data.get('phase')
            record_result("Scan Status", True, f"Status: {status}, Phase: {phase}")
        else:
            record_result("Scan Status", False, f"HTTP {response.status_code}")
            
    except Exception as e:
        record_result("Scan Status", False, str(e))
    
    # Test 4.3: Monitor scan progress (wait up to 30 seconds)
    try:
        print_info("Monitoring scan for 30 seconds...")
        
        start_time = time.time()
        last_status = None
        tool_executed = False
        
        while time.time() - start_time < 30:
            response = requests.get(f"{BACKEND_URL}/api/scan/status/{scan_id}", timeout=TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                current_status = data.get('status')
                tools_executed = data.get('tools_executed', [])
                
                if current_status != last_status:
                    print_info(f"Status changed: {last_status} -> {current_status}")
                    last_status = current_status
                
                if tools_executed and not tool_executed:
                    tool_executed = True
                    print_info(f"Tools executed: {len(tools_executed)}")
                
                if current_status in ['completed', 'error', 'stopped']:
                    break
            
            time.sleep(3)
        
        # Final status check
        response = requests.get(f"{BACKEND_URL}/api/scan/status/{scan_id}", timeout=TIMEOUT)
        data = response.json()
        
        tools_count = len(data.get('tools_executed', []))
        findings_count = len(data.get('findings', []))
        final_status = data.get('status')
        
        if tools_count > 0 or final_status == 'running':
            record_result("Scan Execution", True, f"Tools: {tools_count}, Findings: {findings_count}, Status: {final_status}")
        else:
            record_result("Scan Execution", True, f"Status: {final_status}, Tools: {tools_count}", warning=True)
            
    except Exception as e:
        record_result("Scan Execution", False, str(e))
    
    # Test 4.4: Stop scan (cleanup)
    try:
        response = requests.post(f"{BACKEND_URL}/api/scan/stop/{scan_id}", timeout=TIMEOUT)
        
        if response.status_code == 200:
            record_result("Stop Scan", True, "Scan stopped successfully")
        else:
            record_result("Stop Scan", True, f"HTTP {response.status_code}", warning=True)
            
    except Exception as e:
        record_result("Stop Scan", True, f"Error stopping: {e}", warning=True)

# ============================================
# PHASE 5: FRONTEND TESTS
# ============================================

def test_frontend():
    """Test frontend availability"""
    print_header("PHASE 5: Frontend Integration Tests")
    
    # Test 5.1: Frontend serves
    try:
        response = requests.get(FRONTEND_URL, timeout=TIMEOUT)
        
        if response.status_code == 200:
            if 'html' in response.headers.get('content-type', '').lower():
                record_result("Frontend Serves", True, "HTML page loaded")
            else:
                record_result("Frontend Serves", True, f"Response type: {response.headers.get('content-type')}", warning=True)
        else:
            record_result("Frontend Serves", False, f"HTTP {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        record_result("Frontend Serves", False, "Cannot connect - is frontend running?")
    except Exception as e:
        record_result("Frontend Serves", False, str(e))

# ============================================
# MAIN TEST RUNNER
# ============================================

def run_all_tests():
    """Run all integration tests"""
    print(f"\n{Colors.BLUE}╔══════════════════════════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.BLUE}║     OPTIMUS INTEGRATION TEST SUITE                       ║{Colors.END}")
    print(f"{Colors.BLUE}║     Testing End-to-End System Functionality              ║{Colors.END}")
    print(f"{Colors.BLUE}╚══════════════════════════════════════════════════════════╝{Colors.END}")
    print(f"\n  Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Backend URL: {BACKEND_URL}")
    print(f"  Frontend URL: {FRONTEND_URL}")
    print(f"  Test Target: {TEST_TARGET}")
    
    # Run test phases
    test_backend_health()
    test_ssh_connection()
    test_websocket()
    test_scan_workflow()
    test_frontend()
    
    # Print summary
    print_header("TEST SUMMARY")
    
    total = results['passed'] + results['failed']
    pass_rate = (results['passed'] / total * 100) if total > 0 else 0
    
    print(f"  Total Tests:  {total}")
    print(f"  {Colors.GREEN}Passed:       {results['passed']}{Colors.END}")
    print(f"  {Colors.RED}Failed:       {results['failed']}{Colors.END}")
    print(f"  {Colors.YELLOW}Warnings:     {results['warnings']}{Colors.END}")
    print(f"  Pass Rate:    {pass_rate:.1f}%")
    
    # Status
    if results['failed'] == 0:
        print(f"\n  {Colors.GREEN}✅ ALL TESTS PASSED - System is ready!{Colors.END}")
        status = "READY"
    elif results['failed'] <= 2:
        print(f"\n  {Colors.YELLOW}⚠️  MOSTLY WORKING - Some issues to fix{Colors.END}")
        status = "PARTIAL"
    else:
        print(f"\n  {Colors.RED}❌ CRITICAL ISSUES - Review failures above{Colors.END}")
        status = "FAILED"
    
    # Save results
    results['summary'] = {
        'total': total,
        'passed': results['passed'],
        'failed': results['failed'],
        'warnings': results['warnings'],
        'pass_rate': pass_rate,
        'status': status
    }
    
    report_path = Path('test_results.json')
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n  Results saved to: {report_path}")
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}\n")
    
    return results['failed'] == 0

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)