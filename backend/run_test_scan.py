#!/usr/bin/env python3
"""
Test script to run a scan directly from the backend
"""

import sys
import os
import json
import requests
import time
from datetime import datetime

# Add backend to path
backend_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, backend_dir)

def run_test_scan():
    """Run a test scan directly from the backend"""
    print("=" * 60)
    print("OPTIMUS TEST SCAN")
    print("=" * 60)
    
    # Target URL
    target = "https://www.bugbountytraining.com/challenges/challenge-1.php"
    print(f"Target: {target}")
    
    # Scan configuration
    scan_config = {
        "mode": "standard",
        "enableExploitation": True,
        "useAI": True,
        "maxDuration": 300,  # 5 minutes
        "excludePaths": ""
    }
    
    print(f"Configuration: {scan_config}")
    
    # API endpoint
    api_url = "http://localhost:5000/api/scan/start"
    print(f"API Endpoint: {api_url}")
    
    # Prepare payload
    payload = {
        "target": target,
        "mode": scan_config["mode"],
        "enableExploitation": scan_config["enableExploitation"],
        "useAI": scan_config["useAI"],
        "maxDuration": scan_config["maxDuration"],
        "excludePaths": scan_config["excludePaths"]
    }
    
    print(f"Payload: {payload}")
    
    try:
        # Send POST request to start scan
        print("\nSending scan request...")
        response = requests.post(api_url, json=payload)
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 201:
            result = response.json()
            print(f"Scan started successfully!")
            print(f"Response: {json.dumps(result, indent=2)}")
            
            scan_id = result.get('scan_id')
            if scan_id:
                print(f"\nMonitoring scan {scan_id}...")
                monitor_scan(scan_id)
            else:
                print("ERROR: No scan_id in response")
        else:
            print(f"ERROR: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"CONNECTION ERROR: Could not connect to backend")
        print(f"Make sure the backend is running on http://localhost:5000")
        print(f"Error: {e}")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

def monitor_scan(scan_id):
    """Monitor scan progress"""
    api_url = f"http://localhost:5000/api/scan/status/{scan_id}"
    
    print(f"Monitoring scan at: {api_url}")
    
    # Monitor for up to 10 minutes
    start_time = time.time()
    timeout = 600  # 10 minutes
    
    last_status = None
    last_progress = None
    
    while time.time() - start_time < timeout:
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                scan_data = response.json()
                status = scan_data.get('status', 'unknown')
                phase = scan_data.get('phase', 'unknown')
                tools_executed = len(scan_data.get('tools_executed', []))
                findings = len(scan_data.get('findings', []))
                
                # Print status if it changed
                progress_info = f"Phase: {phase} | Status: {status} | Tools: {tools_executed} | Findings: {findings}"
                if status != last_status or progress_info != last_progress:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"[{timestamp}] {progress_info}")
                    last_status = status
                    last_progress = progress_info
                
                # Check if scan is complete
                if status in ['completed', 'stopped', 'error']:
                    print(f"\nScan {status}!")
                    print(f"Final data: {json.dumps(scan_data, indent=2)}")
                    break
                    
            else:
                print(f"Error getting scan status: {response.status_code}")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"Error monitoring scan: {e}")
            
        # Wait before next check
        time.sleep(5)
    else:
        print("Timeout reached - stopping monitoring")

if __name__ == "__main__":
    run_test_scan()