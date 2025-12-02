#!/usr/bin/env python3
"""
Start Optimus Components Script

This script starts all Optimus components (Kali VM, Backend, Frontend) 
without requiring batch or shell files, avoiding input redirection issues.
"""

import os
import sys
import subprocess
import time
import platform

def check_virtualbox():
    """Check if VirtualBox is installed and accessible"""
    vbox_path = r"D:\Virtualbox\VBoxManage.exe"
    if not os.path.exists(vbox_path):
        print("ERROR: VirtualBox not found at", vbox_path)
        print("Please check your VirtualBox installation path.")
        return None
    return vbox_path

def is_kali_running(vbox_path):
    """Check if Kali VM is already running"""
    try:
        result = subprocess.run([vbox_path, "list", "runningvms"], 
                              capture_output=True, text=True, timeout=10)
        return "kali" in result.stdout.lower()
    except Exception as e:
        print(f"Warning: Could not check Kali VM status: {e}")
        return False

def start_kali_vm(vbox_path):
    """Start Kali VM in headless mode"""
    print("[1/3] Starting Kali VM...")
    
    if is_kali_running(vbox_path):
        print("Kali VM is already running.")
        return True
    
    try:
        print("Starting Kali VM in headless mode...")
        result = subprocess.run([vbox_path, "startvm", "kali", "--type", "headless"],
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("Kali VM started successfully!")
            print("Waiting 60 seconds for Kali VM to boot and SSH service to start...")
            # Show progress during wait
            for i in range(60):
                time.sleep(1)
                if (i + 1) % 10 == 0:
                    print(f"  {i + 1} seconds elapsed...")
            print("Kali VM is ready!")
            return True
        else:
            print(f"Failed to start Kali VM: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error starting Kali VM: {e}")
        return False

def find_python_executable():
    """Find the appropriate Python executable"""
    # Priority order for Python paths
    python_paths = [
        r"C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe",
        r"C:\Program Files\Python313\python.exe",
        r"C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python314\python.exe",
        r"C:\Program Files\Python314\python.exe",
        "python"  # Fallback to system python
    ]
    
    # Check for virtual environment first
    venv_path = os.path.join("backend", "venv", "Scripts", "python.exe")
    if os.path.exists(venv_path):
        return venv_path
    
    # Check other paths
    for path in python_paths:
        if path == "python" or os.path.exists(path):
            return path
    
    return "python"  # Final fallback

def start_backend():
    """Start Backend Server"""
    print("\n[2/3] Starting Backend Server...")
    
    # Change to backend directory
    backend_dir = os.path.join(os.getcwd(), "backend")
    if not os.path.exists(backend_dir):
        print("ERROR: Backend directory not found!")
        return False
    
    # Find Python executable
    python_exe = find_python_executable()
    print(f"Using Python: {python_exe}")
    
    try:
        # Start backend in background
        backend_process = subprocess.Popen(
            [python_exe, "app.py"],
            cwd=backend_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        print(f"Backend server started successfully! (PID: {backend_process.pid})")
        print("Access the API at: http://localhost:5000")
        
        # Wait a moment for server to initialize
        time.sleep(5)
        return True
        
    except Exception as e:
        print(f"Failed to start backend server: {e}")
        return False

def check_node_npm():
    """Check if Node.js and npm are installed"""
    # Add Node.js to PATH if it exists in default location
    nodejs_path = r"C:\Program Files\nodejs"
    if os.path.exists(nodejs_path):
        # Add to PATH for this session
        current_path = os.environ.get('PATH', '')
        if nodejs_path not in current_path:
            os.environ['PATH'] = current_path + os.pathsep + nodejs_path
            print(f"Added Node.js to PATH: {nodejs_path}")
    
    try:
        # Try to run node
        result = subprocess.run(["node", "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"Node.js version: {result.stdout.strip()}")
        else:
            print(f"Node.js error: {result.stderr}")
            return False
            
        # Try to run npm (both with and without .cmd extension)
        npm_commands = ["npm", "npm.cmd"]
        npm_found = False
        npm_version = ""
        
        for npm_cmd in npm_commands:
            try:
                result = subprocess.run([npm_cmd, "--version"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    npm_version = result.stdout.strip()
                    npm_found = True
                    print(f"npm version: {npm_version}")
                    break
                else:
                    print(f"npm ({npm_cmd}) error: {result.stderr}")
            except FileNotFoundError:
                continue
        
        if not npm_found:
            print("ERROR: npm not found!")
            print("Please ensure npm is properly installed with Node.js")
            return False
            
        return True
    except Exception as e:
        print(f"Error checking Node.js/npm: {e}")
        return False

def install_frontend_dependencies():
    """Install frontend dependencies if needed"""
    frontend_dir = os.path.join(os.getcwd(), "frontend")
    node_modules_dir = os.path.join(frontend_dir, "node_modules")
    
    if not os.path.exists(node_modules_dir):
        print("Installing frontend dependencies...")
        try:
            # Add Node.js to PATH if needed
            nodejs_path = r"C:\Program Files\nodejs"
            if os.path.exists(nodejs_path):
                env = os.environ.copy()
                current_path = env.get('PATH', '')
                if nodejs_path not in current_path:
                    env['PATH'] = current_path + os.pathsep + nodejs_path
            else:
                env = None
                
            # Try npm with both .exe and .cmd extensions
            npm_commands = ["npm", "npm.cmd"]
            install_success = False
            
            for npm_cmd in npm_commands:
                try:
                    result = subprocess.run([npm_cmd, "install"], 
                                          cwd=frontend_dir,
                                          env=env,
                                          capture_output=True, 
                                          text=True, 
                                          timeout=300)
                    if result.returncode == 0:
                        print("Dependencies installed successfully!")
                        install_success = True
                        break
                    else:
                        print(f"npm ({npm_cmd}) install error: {result.stderr}")
                except FileNotFoundError:
                    continue
                    
            if not install_success:
                print("Failed to install dependencies with any npm command")
                return False
                
        except Exception as e:
            print(f"Error installing dependencies: {e}")
            return False
    
    return True

def start_frontend():
    """Start Frontend Dev Server"""
    print("\n[3/3] Starting Frontend Dev Server...")
    
    # Check if Node.js and npm are available
    if not check_node_npm():
        return False
    
    # Change to frontend directory
    frontend_dir = os.path.join(os.getcwd(), "frontend")
    if not os.path.exists(frontend_dir):
        print("ERROR: Frontend directory not found!")
        return False
    
    # Install dependencies if needed
    if not install_frontend_dependencies():
        return False
    
    try:
        # Add Node.js to PATH if needed
        nodejs_path = r"C:\Program Files\nodejs"
        if os.path.exists(nodejs_path):
            env = os.environ.copy()
            current_path = env.get('PATH', '')
            if nodejs_path not in current_path:
                env['PATH'] = current_path + os.pathsep + nodejs_path
        else:
            env = None
            
        # Start frontend in background (try both npm and npm.cmd)
        npm_commands = ["npm", "npm.cmd"]
        frontend_process = None
        start_success = False
        
        for npm_cmd in npm_commands:
            try:
                frontend_process = subprocess.Popen(
                    [npm_cmd, "run", "dev"],
                    cwd=frontend_dir,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print(f"Frontend dev server started successfully! (PID: {frontend_process.pid})")
                print("Access the frontend at: http://localhost:5173")
                start_success = True
                break
            except FileNotFoundError:
                continue
                
        if not start_success:
            print("Failed to start frontend dev server with any npm command")
            return False
        
        # Wait a moment for server to initialize
        time.sleep(3)
        return True
        
    except Exception as e:
        print(f"Failed to start frontend dev server: {e}")
        return False

def stop_kali_vm(vbox_path):
    """Stop Kali VM if running"""
    if is_kali_running(vbox_path):
        print("Stopping Kali VM...")
        try:
            subprocess.run([vbox_path, "controlvm", "kali", "poweroff"],
                          capture_output=True, timeout=30)
            print("Kali VM stopped successfully!")
            # Wait for VM to fully shut down
            time.sleep(10)
        except Exception as e:
            print(f"Warning: Could not stop Kali VM: {e}")

def main():
    """Main function to start all Optimus components"""
    print("=" * 60)
    print("Starting Optimus Components")
    print("=" * 60)
    
    # Check VirtualBox installation
    vbox_path = check_virtualbox()
    if not vbox_path:
        sys.exit(1)
    
    # Start Kali VM
    if not start_kali_vm(vbox_path):
        print("Failed to start Kali VM!")
        sys.exit(1)
    
    # Start Backend
    if not start_backend():
        print("Failed to start Backend Server!")
        # Stop Kali VM since we couldn't start backend
        stop_kali_vm(vbox_path)
        sys.exit(1)
    
    # Start Frontend
    if not start_frontend():
        print("Failed to start Frontend Dev Server!")
        # Note: Don't stop backend or Kali VM as they might still be useful
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("All Optimus Components Started Successfully!")
    print("=" * 60)
    print("Kali VM:     Running in headless mode")
    print("Backend:     http://localhost:5000")
    print("Frontend:    http://localhost:5173")
    print("SSH Access:  127.0.0.1:2222 (kali/kali)")
    print("\nPress Ctrl+C to stop all services...")
    
    try:
        # Keep script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping all services...")
        stop_kali_vm(vbox_path)
        print("All services stopped. Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()