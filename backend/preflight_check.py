#!/usr/bin/env python3
"""
Preflight check script to test importing core modules and dependencies.
Prints ASCII-only status indicators and exits with appropriate code.
"""
import sys
import os
import importlib
import subprocess
import logging

# Add the backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def check_import(module_path, name):
    """Test import of a module and return success status"""
    try:
        importlib.import_module(module_path)
        print(f"OK  - {name} ({module_path})")
        return True
    except ImportError as e:
        print(f"FAIL - {name} ({module_path}): {e}")
        return False

def check_optional_import(module_path, name):
    """Test import of an optional module and warn if missing"""
    try:
        importlib.import_module(module_path)
        print(f"OK  - {name} ({module_path}) [optional]")
        return True
    except ImportError as e:
        print(f"WARN - {name} ({module_path}) [optional]: {e}")
        return False

def main():
    all_passed = True
    
    print("Running preflight checks...")
    print("=" * 50)
    
    # Required imports
    required_checks = [
        ("backend.inference.tool_manager", "Tool Manager"),
        ("backend.inference.autonomous_agent", "Autonomous Agent"),
        ("backend.inference.tool_selector", "Tool Selector"),
        ("backend.inference.intelligent_selector", "Intelligent Selector"),
        ("backend.training_environment.newbie_to_pro_training", "Newbie to Pro Training"),
        ("backend.training.deep_rl_agent", "Deep RL Agent"),
        ("backend.training.rl_trainer", "RL Trainer"),
        ("backend.execution.ssh_client", "SSH Client"),
    ]
    
    for module_path, name in required_checks:
        if not check_import(module_path, name):
            all_passed = False
    
    print("-" * 30)
    print("Optional dependencies:")
    
    # Optional imports
    optional_checks = [
        ("tensorflow", "TensorFlow"),
        ("flask_socketio", "Flask-SocketIO"),
        ("msgpack", "MessagePack"),
        ("requests", "Requests (for MSF RPC)"),
    ]
    
    for module_path, name in optional_checks:
        check_optional_import(module_path, name)
    
    print("=" * 50)
    if all_passed:
        print("RESULT: All required modules imported successfully")
        return 0
    else:
        print("RESULT: Some required modules failed to import")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)