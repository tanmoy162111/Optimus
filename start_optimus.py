#!/usr/bin/env python3
"""
Optimus Startup Script
Starts the Optimus platform including backend, frontend, and Kali VM
"""

import os
import sys
import subprocess
import time
import argparse

def check_python():
    """Check if Python is available and return the path"""
    python_paths = [
        r"C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe",
        r"C:\Program Files\Python313\python.exe",
        r"C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python314\python.exe",
        r"C:\Program Files\Python314\python.exe"
    ]
    
    # Check for specific Python installations
    for path in python_paths:
        if os.path.exists(path):
            return path
    
    # Fallback to system python
    return "python"

def check_virtualbox():
    """Check if VirtualBox is installed"""
    vbox_paths = [
        r"D:\Virtualbox\VBoxManage.exe",
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
    ]
    
    for path in vbox_paths:
        if os.path.exists(path):
            return path
    
    return None

def start_kali_vm(vbox_path):
    """Start the Kali VM if it's not already running"""
    try:
        # Check if Kali VM is already running
        result = subprocess.run([vbox_path, "list", "runningvms"], 
                              capture_output=True, text=True, timeout=30)
        
        if "kali" in result.stdout.lower():
            print("✅ Kali VM is already running")
            return True
            
        print("🔄 Starting Kali VM...")
        # Start Kali VM in headless mode
        result = subprocess.run([vbox_path, "startvm", "kali", "--type", "headless"], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("⏳ Waiting for Kali VM to boot (60 seconds)...")
            time.sleep(60)  # Wait for VM to fully boot
            print("✅ Kali VM started successfully")
            return True
        else:
            print(f"❌ Failed to start Kali VM: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Timeout while checking/starting Kali VM")
        return False
    except Exception as e:
        print(f"❌ Error managing Kali VM: {e}")
        return False

def start_backend(python_path):
    """Start the backend server"""
    try:
        backend_dir = os.path.join(os.getcwd(), "backend")
        if not os.path.exists(backend_dir):
            print("❌ Backend directory not found")
            return False
            
        print("🔄 Starting Backend Server...")
        # Start backend in a new process
        backend_process = subprocess.Popen([
            python_path, "app.py"
        ], cwd=backend_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print("⏳ Waiting for backend to initialize (10 seconds)...")
        time.sleep(10)
        
        # Check if backend is still running
        if backend_process.poll() is None:
            print("✅ Backend Server started successfully")
            return True
        else:
            stdout, stderr = backend_process.communicate()
            print(f"❌ Backend Server failed to start: {stderr.decode()}")
            return False
            
    except Exception as e:
        print(f"❌ Error starting backend: {e}")
        return False

def start_frontend():
    """Start the frontend development server"""
    try:
        frontend_dir = os.path.join(os.getcwd(), "frontend")
        if not os.path.exists(frontend_dir):
            print("❌ Frontend directory not found")
            return False
            
        print("🔄 Starting Frontend Development Server...")
        # Start frontend in a new process
        frontend_process = subprocess.Popen([
            "npm", "run", "dev"
        ], cwd=frontend_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print("⏳ Waiting for frontend to initialize (10 seconds)...")
        time.sleep(10)
        
        # Check if frontend is still running
        if frontend_process.poll() is None:
            print("✅ Frontend Development Server started successfully")
            return True
        else:
            stdout, stderr = frontend_process.communicate()
            print(f"❌ Frontend Development Server failed to start: {stderr.decode()}")
            return False
            
    except Exception as e:
        print(f"❌ Error starting frontend: {e}")
        return False

def main():
    """Main function to start Optimus platform"""
    print("🚀 Starting Optimus Platform...")
    print("=" * 50)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Start Optimus Platform")
    parser.add_argument("--skip-vm", action="store_true", 
                       help="Skip starting the Kali VM")
    parser.add_argument("--skip-backend", action="store_true", 
                       help="Skip starting the backend server")
    parser.add_argument("--skip-frontend", action="store_true", 
                       help="Skip starting the frontend server")
    
    args = parser.parse_args()
    
    # Check dependencies
    python_path = check_python()
    print(f"🐍 Python Path: {python_path}")
    
    vbox_path = check_virtualbox()
    if vbox_path:
        print(f"📦 VirtualBox Path: {vbox_path}")
    else:
        print("⚠️  VirtualBox not found")
    
    # Start components based on arguments
    success = True
    
    # Start Kali VM
    if not args.skip_vm and vbox_path:
        if not start_kali_vm(vbox_path):
            success = False
            print("⚠️  Continuing without Kali VM...")
    else:
        print("⏭️  Skipping Kali VM start")
    
    # Start Backend
    if not args.skip_backend:
        if not start_backend(python_path):
            success = False
    else:
        print("⏭️  Skipping Backend start")
    
    # Start Frontend
    if not args.skip_frontend:
        if not start_frontend():
            success = False
    else:
        print("⏭️  Skipping Frontend start")
    
    # Final status
    print("=" * 50)
    if success:
        print("🎉 Optimus Platform Started Successfully!")
        print("\n🔗 Access Points:")
        print("   Backend API:  http://localhost:5000")
        print("   Frontend UI:  http://localhost:5173")
        if not args.skip_vm and vbox_path:
            print("   Kali VM SSH:  127.0.0.1:2222")
        print("\n⏹️  To stop the platform, run: python stop_optimus.py")
    else:
        print("❌ Some components failed to start. Check the logs above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())