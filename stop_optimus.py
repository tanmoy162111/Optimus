#!/usr/bin/env python3
"""
Optimus Stop Script
Stops the Optimus platform including backend, frontend, and Kali VM
"""

import os
import sys
import subprocess
import time
import argparse
import psutil

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

def stop_kali_vm(vbox_path):
    """Stop the Kali VM"""
    try:
        print("🔄 Stopping Kali VM...")
        # Power off Kali VM
        result = subprocess.run([vbox_path, "controlvm", "kali", "poweroff"], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Kali VM powered off successfully")
            return True
        else:
            print(f"⚠️  Failed to power off Kali VM: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Timeout while stopping Kali VM")
        return False
    except Exception as e:
        print(f"❌ Error stopping Kali VM: {e}")
        return False

def stop_backend():
    """Stop the backend server"""
    try:
        print("🔄 Stopping Backend Server...")
        stopped = False
        
        # Find and kill Python processes running app.py
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] and 'python' in proc.info['name'].lower():
                    if proc.info['cmdline'] and 'app.py' in ' '.join(proc.info['cmdline']):
                        proc.kill()
                        print(f"✅ Backend Server (PID {proc.info['pid']}) stopped")
                        stopped = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if not stopped:
            print("⚠️  No Backend Server process found")
        
        return True
            
    except Exception as e:
        print(f"❌ Error stopping backend: {e}")
        return False

def stop_frontend():
    """Stop the frontend development server"""
    try:
        print("🔄 Stopping Frontend Development Server...")
        stopped = False
        
        # Find and kill Node.js processes running Vite
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] and ('node' in proc.info['name'].lower() or 'npm' in proc.info['name'].lower()):
                    if proc.info['cmdline'] and ('vite' in ' '.join(proc.info['cmdline']) or 'dev' in ' '.join(proc.info['cmdline'])):
                        proc.kill()
                        print(f"✅ Frontend Development Server (PID {proc.info['pid']}) stopped")
                        stopped = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if not stopped:
            print("⚠️  No Frontend Development Server process found")
        
        return True
            
    except Exception as e:
        print(f"❌ Error stopping frontend: {e}")
        return False

def kill_processes_on_ports(ports):
    """Kill processes running on specific ports"""
    try:
        for port in ports:
            print(f"🔄 Killing processes on port {port}...")
            # Find processes using the port
            result = subprocess.run(['netstat', '-ano', '|', 'findstr', f':{port}'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            pid = parts[-1]
                            try:
                                proc = psutil.Process(int(pid))
                                proc.kill()
                                print(f"✅ Process on port {port} (PID {pid}) killed")
                            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                                print(f"⚠️  Could not kill process {pid} on port {port}")
            else:
                print(f"⚠️  No processes found on port {port}")
                
        return True
        
    except Exception as e:
        print(f"❌ Error killing processes on ports: {e}")
        return False

def main():
    """Main function to stop Optimus platform"""
    print("🛑 Stopping Optimus Platform...")
    print("=" * 50)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Stop Optimus Platform")
    parser.add_argument("--skip-vm", action="store_true", 
                       help="Skip stopping the Kali VM")
    parser.add_argument("--skip-backend", action="store_true", 
                       help="Skip stopping the backend server")
    parser.add_argument("--skip-frontend", action="store_true", 
                       help="Skip stopping the frontend server")
    parser.add_argument("--force-ports", action="store_true",
                       help="Force kill processes on standard ports (5000, 5173)")
    
    args = parser.parse_args()
    
    # Check for VirtualBox
    vbox_path = check_virtualbox()
    if vbox_path:
        print(f"📦 VirtualBox Path: {vbox_path}")
    else:
        print("⚠️  VirtualBox not found")
    
    success = True
    
    # Stop components based on arguments
    # Stop Kali VM
    if not args.skip_vm and vbox_path:
        if not stop_kali_vm(vbox_path):
            success = False
    else:
        print("⏭️  Skipping Kali VM stop")
    
    # Stop Backend
    if not args.skip_backend:
        if not stop_backend():
            success = False
    else:
        print("⏭️  Skipping Backend stop")
    
    # Stop Frontend
    if not args.skip_frontend:
        if not stop_frontend():
            success = False
    else:
        print("⏭️  Skipping Frontend stop")
    
    # Force kill processes on ports if requested
    if args.force_ports:
        print("🔄 Force killing processes on standard ports...")
        kill_processes_on_ports([5000, 5173])
    
    # Final status
    print("=" * 50)
    if success:
        print("🎉 Optimus Platform Stopped Successfully!")
    else:
        print("⚠️  Some components may not have stopped properly.")
        return 1
    
    return 0

if __name__ == "__main__":
    # Install psutil if not available
    try:
        import psutil
    except ImportError:
        print("🔄 Installing required dependency 'psutil'...")
        subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], 
                      check=True, capture_output=True)
        import psutil
    
    sys.exit(main())