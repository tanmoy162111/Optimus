#!/usr/bin/env python3
"""
Diagnostic script to identify scan engine issues
Run this from your backend directory: python diagnose_scan.py
"""

import sys
import os
from pathlib import Path

# Add backend to path
BACKEND_DIR = Path(__file__).parent
sys.path.insert(0, str(BACKEND_DIR))

print("=" * 60)
print("OPTIMUS SCAN ENGINE DIAGNOSTIC")
print("=" * 60)

errors = []
warnings = []

# Test 1: Check imports
print("\n[1/6] Checking core imports...")
try:
    from flask import Flask
    from flask_socketio import SocketIO
    print("  ✅ Flask and SocketIO imported")
except ImportError as e:
    errors.append(f"Flask/SocketIO import: {e}")
    print(f"  ❌ Import error: {e}")

# Test 2: Check config
print("\n[2/6] Checking configuration...")
try:
    from config import Config
    print(f"  ✅ Config loaded")
    print(f"     KALI_HOST: {Config.KALI_HOST}")
    print(f"     KALI_PORT: {Config.KALI_PORT}")
except ImportError as e:
    errors.append(f"Config import: {e}")
    print(f"  ❌ Config error: {e}")

# Test 3: Check inference modules
print("\n[3/6] Checking inference modules...")
try:
    from inference.tool_manager import ToolManager
    print("  ✅ ToolManager imported")
except ImportError as e:
    errors.append(f"ToolManager import: {e}")
    print(f"  ❌ ToolManager error: {e}")

try:
    from inference.autonomous_agent import AutonomousPentestAgent
    print("  ✅ AutonomousPentestAgent imported")
except ImportError as e:
    errors.append(f"AutonomousPentestAgent import: {e}")
    print(f"  ❌ AutonomousPentestAgent error: {e}")

try:
    from inference.phase_controller import PhaseController
    print("  ✅ PhaseController imported")
except ImportError as e:
    warnings.append(f"PhaseController import: {e}")
    print(f"  ⚠️  PhaseController warning: {e}")

try:
    from inference.tool_selector import PhaseAwareToolSelector
    print("  ✅ PhaseAwareToolSelector imported")
except ImportError as e:
    warnings.append(f"PhaseAwareToolSelector import: {e}")
    print(f"  ⚠️  PhaseAwareToolSelector warning: {e}")

# Test 4: Check intelligence modules
print("\n[4/6] Checking intelligence modules...")
try:
    from intelligence import get_optimus_brain
    brain = get_optimus_brain()
    print("  ✅ Intelligence module loaded")
except ImportError as e:
    warnings.append(f"Intelligence import: {e}")
    print(f"  ⚠️  Intelligence warning: {e}")
except Exception as e:
    warnings.append(f"Intelligence init: {e}")
    print(f"  ⚠️  Intelligence init warning: {e}")

# Test 5: Check tools module
print("\n[5/6] Checking tools module...")
try:
    from tools import get_hybrid_tool_system
    tools = get_hybrid_tool_system()
    print("  ✅ Hybrid tool system loaded")
except ImportError as e:
    warnings.append(f"Tools import: {e}")
    print(f"  ⚠️  Tools warning: {e}")
except Exception as e:
    warnings.append(f"Tools init: {e}")
    print(f"  ⚠️  Tools init warning: {e}")

# Test 6: Check scan engine
print("\n[6/6] Checking scan engine...")
try:
    # Create minimal app for testing
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test'
    socketio = SocketIO(app, async_mode='threading')
    
    # Simulate what app.py does
    active_scans = {}
    scan_history = []
    
    # Now try to import and create scan manager
    print("  Attempting to import scan_engine...")
    
    # First, check if the file exists
    scan_engine_path = BACKEND_DIR / 'core' / 'scan_engine.py'
    if not scan_engine_path.exists():
        errors.append("core/scan_engine.py does not exist!")
        print(f"  ❌ File not found: {scan_engine_path}")
    else:
        print(f"  ✅ scan_engine.py exists")
        
        # Try to read and check for common issues
        with open(scan_engine_path) as f:
            content = f.read()
            
        if 'class ScanManager' in content:
            print("  ✅ ScanManager class found")
        else:
            warnings.append("ScanManager class not found in scan_engine.py")
            print("  ⚠️  ScanManager class not found")
        
        if 'def start_scan' in content:
            print("  ✅ start_scan method found")
        else:
            errors.append("start_scan method not found")
            print("  ❌ start_scan method not found")
        
        if 'pass' in content and content.count('pass') > 5:
            warnings.append("Multiple 'pass' statements - might be stub implementation")
            print("  ⚠️  Multiple 'pass' statements detected")
    
    # Try actual import
    try:
        from core.scan_engine import get_scan_manager
        print("  ✅ get_scan_manager imported")
        
        # This is where it might fail - inject our test socketio
        import core.scan_engine as se_module
        
        # Check if it's trying to import from app
        print("  Checking for circular import issues...")
        
    except ImportError as e:
        errors.append(f"scan_engine import: {e}")
        print(f"  ❌ Import error: {e}")
    except Exception as e:
        errors.append(f"scan_engine error: {e}")
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()

except Exception as e:
    errors.append(f"Scan engine check failed: {e}")
    print(f"  ❌ Check failed: {e}")
    import traceback
    traceback.print_exc()

# Test 7: Try to simulate a scan start
print("\n[BONUS] Simulating scan start...")
try:
    from flask import Flask
    from flask_socketio import SocketIO
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test'
    socketio = SocketIO(app, async_mode='threading')
    
    # Create test context
    with app.app_context():
        # Import within context
        print("  Creating scan manager...")
        
        # Manually create what scan_engine should create
        from inference.autonomous_agent import AutonomousPentestAgent
        from inference.tool_manager import ToolManager
        
        tool_manager = ToolManager(socketio)
        print("  ✅ ToolManager created")
        
        agent = AutonomousPentestAgent(socketio=socketio)
        print("  ✅ AutonomousPentestAgent created")
        
        # Check if agent has run_autonomous_scan
        if hasattr(agent, 'run_autonomous_scan'):
            print("  ✅ run_autonomous_scan method exists")
        else:
            errors.append("run_autonomous_scan method missing from agent")
            print("  ❌ run_autonomous_scan method missing")

except Exception as e:
    errors.append(f"Simulation failed: {e}")
    print(f"  ❌ Simulation failed: {e}")
    import traceback
    traceback.print_exc()

# Summary
print("\n" + "=" * 60)
print("DIAGNOSTIC SUMMARY")
print("=" * 60)

if errors:
    print(f"\n❌ ERRORS ({len(errors)}):")
    for e in errors:
        print(f"   • {e}")
else:
    print("\n✅ No critical errors found")

if warnings:
    print(f"\n⚠️  WARNINGS ({len(warnings)}):")
    for w in warnings:
        print(f"   • {w}")

if not errors:
    print("\n✅ All core components can be imported!")
    print("   The 500 error might be in the route handler or request processing.")
    print("\n   Next step: Check backend logs for the actual traceback")
    print("   Run: tail -100 ../logs/backend.log")
else:
    print("\n❌ Fix the errors above before the scan will work")

print("\n" + "=" * 60)