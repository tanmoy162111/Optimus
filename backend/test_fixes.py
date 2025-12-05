#!/usr/bin/env python3
"""
Test script to verify all Optimus integration fixes are working.
Run from the project root: python test_fixes.py
"""

import sys
import os
from pathlib import Path

# Add backend to path
BACKEND_DIR = Path(__file__).parent / 'backend'
sys.path.insert(0, str(BACKEND_DIR))

def test_config_import():
    """Test 1: Config import (fixes config/ folder shadow issue)"""
    print("\n" + "="*60)
    print("TEST 1: Config Import")
    print("="*60)
    try:
        from config import Config
        print(f"  ✅ Config imported successfully")
        print(f"     KALI_HOST: {Config.KALI_HOST}")
        print(f"     KALI_PORT: {Config.KALI_PORT}")
        return True
    except ImportError as e:
        print(f"  ❌ Config import FAILED: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Config access error: {e}")
        return False

def test_hybrid_tool_system():
    """Test 2: Hybrid tool system import and initialization"""
    print("\n" + "="*60)
    print("TEST 2: Hybrid Tool System")
    print("="*60)
    try:
        from tools.hybrid_tool_system import (
            get_hybrid_tool_system,
            ResolutionStatus,
            ToolSource,
            HybridToolSystem
        )
        print(f"  ✅ Imports successful")
        
        # Test enum values
        print(f"     ResolutionStatus.RESOLVED = {ResolutionStatus.RESOLVED}")
        print(f"     ResolutionStatus.PARTIAL = {ResolutionStatus.PARTIAL}")
        print(f"     ToolSource.KNOWLEDGE_BASE = {ToolSource.KNOWLEDGE_BASE}")
        
        # Test singleton
        system = get_hybrid_tool_system()
        print(f"  ✅ Hybrid tool system instance created")
        print(f"     Stats: {system.get_statistics()}")
        
        return True
    except ImportError as e:
        print(f"  ❌ Import FAILED: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Initialization error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_tool_manager():
    """Test 3: Tool manager import with fixed hybrid system path"""
    print("\n" + "="*60)
    print("TEST 3: Tool Manager Import")
    print("="*60)
    try:
        from inference.tool_manager import ToolManager, HYBRID_SYSTEM_AVAILABLE
        print(f"  ✅ ToolManager imported")
        print(f"     HYBRID_SYSTEM_AVAILABLE: {HYBRID_SYSTEM_AVAILABLE}")
        
        # Check if ResolutionStatus was imported
        from inference.tool_manager import ResolutionStatus as TM_ResolutionStatus
        if TM_ResolutionStatus:
            print(f"  ✅ ResolutionStatus enum available in tool_manager")
        else:
            print(f"  ⚠️ ResolutionStatus is None (hybrid system not available)")
        
        return True
    except ImportError as e:
        print(f"  ❌ Import FAILED: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_output_parser():
    """Test 4: Output parser functionality"""
    print("\n" + "="*60)
    print("TEST 4: Output Parser")
    print("="*60)
    try:
        from inference.output_parser import OutputParser
        parser = OutputParser()
        print(f"  ✅ OutputParser created")
        
        # Test nmap parsing
        test_output = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for example.com
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9
80/tcp   open  http    Apache httpd 2.4
443/tcp  open  https   nginx 1.18
        """
        result = parser.parse_tool_output('nmap', test_output, '')
        vulns = result.get('vulnerabilities', [])
        services = result.get('services', [])
        print(f"  ✅ Parsed nmap output:")
        print(f"     Vulnerabilities found: {len(vulns)}")
        print(f"     Services found: {len(services)}")
        
        return True
    except ImportError as e:
        print(f"  ❌ Import FAILED: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Parser error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_autonomous_agent():
    """Test 5: Autonomous agent import"""
    print("\n" + "="*60)
    print("TEST 5: Autonomous Agent")
    print("="*60)
    try:
        from inference.autonomous_agent import AutonomousPentestAgent
        print(f"  ✅ AutonomousPentestAgent imported")
        
        # Test instantiation (without socketio)
        agent = AutonomousPentestAgent(socketio=None)
        print(f"  ✅ Agent instance created")
        print(f"     Has tool_selector: {hasattr(agent, 'tool_selector')}")
        print(f"     Has phase_controller: {hasattr(agent, 'phase_controller')}")
        print(f"     Has tool_manager: {hasattr(agent, 'tool_manager')}")
        
        return True
    except ImportError as e:
        print(f"  ❌ Import FAILED: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Instantiation error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_scan_engine():
    """Test 6: Scan engine import"""
    print("\n" + "="*60)
    print("TEST 6: Scan Engine")
    print("="*60)
    try:
        from core.scan_engine import ScanManager, get_scan_manager
        print(f"  ✅ ScanManager imported")
        
        # Create with empty refs (test mode)
        manager = ScanManager(socketio=None, active_scans_ref={})
        print(f"  ✅ ScanManager instance created")
        print(f"     Has tool_manager: {manager.tool_manager is not None}")
        print(f"     Has agent_class: {manager.agent_class is not None}")
        
        return True
    except ImportError as e:
        print(f"  ❌ Import FAILED: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Instantiation error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_intelligence_module():
    """Test 7: Intelligence module import"""
    print("\n" + "="*60)
    print("TEST 7: Intelligence Module")
    print("="*60)
    try:
        from intelligence import get_optimus_brain, OptimusBrain
        print(f"  ✅ Intelligence module imported")
        
        # Note: Full instantiation requires more setup
        print(f"     OptimusBrain class available: {OptimusBrain is not None}")
        
        return True
    except ImportError as e:
        print(f"  ⚠️ Import issue (may need aiohttp): {e}")
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("OPTIMUS INTEGRATION FIX VERIFICATION")
    print("="*60)
    
    results = {
        'Config Import': test_config_import(),
        'Hybrid Tool System': test_hybrid_tool_system(),
        'Tool Manager': test_tool_manager(),
        'Output Parser': test_output_parser(),
        'Autonomous Agent': test_autonomous_agent(),
        'Scan Engine': test_scan_engine(),
        'Intelligence Module': test_intelligence_module(),
    }
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    
    for test_name, passed_test in results.items():
        status = "✅ PASS" if passed_test else "❌ FAIL"
        print(f"  {status}: {test_name}")
    
    print(f"\nTotal: {passed} passed, {failed} failed out of {len(results)}")
    
    if failed > 0:
        print("\n⚠️ Some tests failed. Check the detailed output above.")
        print("   Common fixes:")
        print("   - Install missing deps: pip install aiohttp threadpoolctl")
        print("   - Ensure config/__init__.py exists")
        return 1
    else:
        print("\n🎉 All tests passed! The integration fixes are working.")
        return 0

if __name__ == '__main__':
    sys.exit(main())
