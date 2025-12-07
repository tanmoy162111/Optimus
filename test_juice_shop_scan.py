#!/usr/bin/env python3
"""
Test script to run a scan on OWASP Juice Shop
"""

import requests
import json
import time

def start_scan():
    """Start a scan on OWASP Juice Shop"""
    # Assuming Juice Shop is running on localhost:3000
    target_url = "http://localhost:3000"
    
    # Scan configuration
    scan_config = {
        "target": target_url,
        "profile": "full",  # or "fast", "stealth", etc.
        "self_directed": True  # Use autonomous mode
    }
    
    # API endpoint to start scan
    api_url = "http://localhost:5000/api/scan/start"
    
    try:
        print(f"Starting scan on {target_url}...")
        response = requests.post(api_url, json=scan_config)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get("scan_id")
            print(f"Scan started successfully with ID: {scan_id}")
            return scan_id
        else:
            print(f"Failed to start scan. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"Error starting scan: {e}")
        return None

def check_scan_status(scan_id):
    """Check the status of a running scan"""
    if not scan_id:
        return None
        
    status_url = f"http://localhost:5000/api/scan/{scan_id}/status"
    
    try:
        response = requests.get(status_url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to get scan status. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error checking scan status: {e}")
        return None

def main():
    """Main function to run the test scan"""
    print("Initiating OWASP Juice Shop scan test...")
    
    # Start the scan
    scan_id = start_scan()
    
    if not scan_id:
        print("Failed to start scan. Exiting.")
        return
    
    # Monitor the scan for a while
    print("Monitoring scan progress...")
    for i in range(30):  # Check for 5 minutes (10 seconds * 30)
        time.sleep(10)
        status = check_scan_status(scan_id)
        
        if status:
            scan_status = status.get("status", "unknown")
            print(f"Scan status: {scan_status}")
            
            if scan_status in ["completed", "failed", "cancelled"]:
                print("Scan finished.")
                print(json.dumps(status, indent=2))
                break
        else:
            print("Failed to get scan status.")
            
    print("Test completed.")

if __name__ == "__main__":
    main()