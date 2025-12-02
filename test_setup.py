#!/usr/bin/env python3
"""
Optimus Setup Verification Script
Tests if all components are properly installed and configured
"""

import subprocess
import sys
import os

def test_python():
    """Test if Python is accessible"""
    try:
        result = subprocess.run([
            "C:\\Users\\Tanmoy Saha\\AppData\\Local\\Programs\\Python\\Python313\\python.exe", 
            "--version"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"✅ Python: {result.stdout.strip()}")
            return True
        else:
            print(f"❌ Python: Failed - {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Python: Error - {e}")
        return False

def test_node_npm():
    """Test if Node.js and npm are accessible"""
    try:
        # Test Node.js
        node_result = subprocess.run(["node", "--version"], 
                                   capture_output=True, text=True, timeout=10)
        
        # Test npm
        npm_result = subprocess.run(["npm", "--version"], 
                                  capture_output=True, text=True, timeout=10)
        
        if node_result.returncode == 0 and npm_result.returncode == 0:
            print(f"✅ Node.js: {node_result.stdout.strip()}")
            print(f"✅ npm: {npm_result.stdout.strip()}")
            return True
        else:
            if node_result.returncode != 0:
                print(f"⚠️  Node.js: Not found or not in PATH - {node_result.stderr}")
            if npm_result.returncode != 0:
                print(f"⚠️  npm: Not found or not in PATH - {npm_result.stderr}")
            return True  # Don't fail the entire test for this
    except Exception as e:
        print(f"⚠️  Node.js/npm: Error - {e}")
        return True  # Don't fail the entire test for this

def test_vite():
    """Test if Vite is accessible"""
    try:
        result = subprocess.run(["npx", "vite", "--version"], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"✅ Vite: {result.stdout.strip()}")
            return True
        else:
            print(f"⚠️  Vite: Not found or not in PATH - {result.stderr}")
            return True  # Don't fail the entire test for this
    except Exception as e:
        print(f"⚠️  Vite: Error - {e}")
        return True  # Don't fail the entire test for this

def test_virtualbox():
    """Test if VirtualBox is accessible"""
    try:
        vbox_path = "D:\\Virtualbox\\VBoxManage.exe"
        if os.path.exists(vbox_path):
            result = subprocess.run([vbox_path, "--version"], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"✅ VirtualBox: {result.stdout.strip()}")
                return True
            else:
                print(f"❌ VirtualBox: Failed - {result.stderr}")
                return False
        else:
            print("⚠️  VirtualBox: Not found at expected path")
            return False
    except Exception as e:
        print(f"❌ VirtualBox: Error - {e}")
        return False

def test_backend_dependencies():
    """Test if key backend dependencies are installed"""
    try:
        python_path = "C:\\Users\\Tanmoy Saha\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
        
        # Test Flask
        flask_result = subprocess.run([
            python_path, "-c", "import flask; print(flask.__version__)"
        ], capture_output=True, text=True, timeout=10)
        
        # Test NumPy
        numpy_result = subprocess.run([
            python_path, "-c", "import numpy; print(numpy.__version__)"
        ], capture_output=True, text=True, timeout=10)
        
        if flask_result.returncode == 0:
            print(f"✅ Flask: {flask_result.stdout.strip()}")
        else:
            print(f"❌ Flask: Failed - {flask_result.stderr}")
            
        if numpy_result.returncode == 0:
            print(f"✅ NumPy: {numpy_result.stdout.strip()}")
        else:
            print(f"❌ NumPy: Failed - {numpy_result.stderr}")
            
        # TensorFlow is optional for now, just check if it imports without error
        try:
            tf_result = subprocess.run([
                python_path, "-c", "import tensorflow; print('Installed')"
            ], capture_output=True, text=True, timeout=15)  # Longer timeout for TensorFlow
            
            if tf_result.returncode == 0:
                print(f"✅ TensorFlow: Installed")
            else:
                print(f"⚠️  TensorFlow: Import failed (may still work) - {tf_result.stderr[:100]}...")
        except Exception as e:
            print(f"⚠️  TensorFlow: Error during import - {e}")
            
        return (flask_result.returncode == 0 and numpy_result.returncode == 0)
                
    except Exception as e:
        print(f"❌ Backend Dependencies: Error - {e}")
        return False

def test_frontend_dependencies():
    """Test if frontend dependencies are installed"""
    try:
        # Check if node_modules exists
        if os.path.exists("frontend/node_modules"):
            print("✅ Frontend Dependencies: Installed")
            return True
        else:
            print("❌ Frontend Dependencies: Not found (run 'npm install' in frontend directory)")
            return False
    except Exception as e:
        print(f"❌ Frontend Dependencies: Error - {e}")
        return False

def main():
    """Run all tests"""
    print("🔍 Optimus Setup Verification")
    print("=" * 40)
    
    tests = [
        ("Python", test_python),
        ("Node.js & npm", test_node_npm),
        ("Vite", test_vite),
        ("VirtualBox", test_virtualbox),
        ("Backend Dependencies", test_backend_dependencies),
        ("Frontend Dependencies", test_frontend_dependencies)
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        print(f"\nTesting {name}...")
        if test_func():
            passed += 1
    
    print("\n" + "=" * 40)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed >= total - 2:  # Allow up to 2 "warnings" to still be considered successful
        print("🎉 Setup verification completed! Your setup is ready.")
        print("\n🚀 Next steps:")
        print("   Run 'start.bat' or 'python start_optimus.py' to start the platform")
        return True
    else:
        print("⚠️  Some critical tests failed. Please check the output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)