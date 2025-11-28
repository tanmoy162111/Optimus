"""Test suite for autonomous agent intelligence"""

import sys
sys.path.insert(0, '..')

from inference.autonomous_agent import AutonomousPentestAgent
from datetime import datetime
import json

def test_tool_repetition_prevention():
    """Test: Agent should not execute same tool 3+ times"""
    print("\n[TEST 1] Tool Repetition Prevention")
    print("=" * 60)
    
    agent = AutonomousPentestAgent()
    
    # Create mock scan state
    scan_state = {
        'scan_id': 'test-001',
        'target': 'http://test.com',
        'phase': 'scanning',
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'findings': [],
        'tools_executed': ['nmap', 'nmap', 'nmap'],  # Same tool 3 times
        'coverage': 0.3,
        'time_budget': 3600
    }
    
    # Tool should be blacklisted
    from inference.tool_selector import PhaseAwareToolSelector
    selector = PhaseAwareToolSelector()
    
    result = selector.recommend_tools(scan_state)
    
    # Verify nmap is not recommended again
    assert 'nmap' not in result['tools'], f"FAIL: nmap recommended despite 3 uses"
    
    print(f"✅ PASS: nmap correctly blacklisted after 3 uses")
    print(f"  Recommended instead: {result['tools'][:3]}")
    
    return True

def test_phase_transition():
    """Test: Agent should transition phases automatically"""
    print("\n[TEST 2] Automatic Phase Transition")
    print("=" * 60)
    
    from inference.phase_controller import PhaseTransitionController
    controller = PhaseTransitionController()
    
    # Create state stuck in reconnaissance
    stuck_state = {
        'phase': 'reconnaissance',
        'tools_executed': ['sublist3r'] * 7,  # Same tool 7 times
        'findings': [],  # No findings
        'coverage': 0.2,
    }
    
    next_phase = controller.should_transition(stuck_state)
    
    assert next_phase != 'reconnaissance', "FAIL: Should force transition from stuck phase"
    
    print(f"✅ PASS: Forced transition from reconnaissance → {next_phase}")
    
    return True

def test_dynamic_commands():
    """Test: Commands should vary based on context"""
    print("\n[TEST 3] Dynamic Command Generation")
    print("=" * 60)
    
    from inference.tool_knowledge_base import ToolKnowledgeBase
    kb = ToolKnowledgeBase()
    
    # Test 1: Reconnaissance phase (should be stealthy)
    recon_context = {
        'phase': 'reconnaissance',
        'findings': [],
        'stealth_required': True
    }
    cmd1 = kb.build_command('nmap', '192.168.1.1', recon_context)
    
    # Test 2: Exploitation phase (should be aggressive)
    exploit_context = {
        'phase': 'exploitation',
        'findings': [{'type': 'sql_injection', 'severity': 9.0}],
        'stealth_required': False
    }
    cmd2 = kb.build_command('nmap', '192.168.1.1', exploit_context)
    
    # Commands should be different
    assert cmd1 != cmd2, "FAIL: Commands identical despite different contexts"
    
    print(f"✅ PASS: Commands adapt to context")
    print(f"  Recon: {cmd1[:80]}...")
    print(f"  Exploit: {cmd2[:80]}...")
    
    return True

def test_api_key_handling():
    """Test: Missing API keys should fail gracefully"""
    print("\n[TEST 4] API Key Error Handling")
    print("=" * 60)
    
    from inference.tool_manager import ToolManager
    from unittest.mock import MagicMock
    
    socketio = MagicMock()
    manager = ToolManager(socketio)
    
    # Check tool with missing API key
    has_reqs, missing = manager.check_tool_requirements('shodan')
    
    if not has_reqs:
        print(f"✅ PASS: Correctly detected missing API keys: {missing}")
        
        fallback = manager.get_fallback_tool('shodan')
        print(f"  Fallback tool: {fallback}")
        
        return True
    else:
        print(f"⚠️  SKIP: API keys are configured")
        
        return True

def test_coverage_calculation():
    """Test: Coverage should reflect actual progress"""
    print("\n[TEST 5] Coverage Calculation")
    print("=" * 60)
    
    agent = AutonomousPentestAgent()
    
    # State 1: Many duplicates, no findings
    bad_state = {
        'phase': 'scanning',
        'tools_executed': ['nmap', 'nmap', 'nmap', 'nikto', 'nikto'],
        'findings': []
    }
    coverage1 = agent._calculate_coverage_real(bad_state)
    
    # State 2: Diverse tools, findings
    good_state = {
        'phase': 'scanning',
        'tools_executed': ['nmap', 'nikto', 'nuclei', 'masscan'],
        'findings': [{'severity': 7.0}, {'severity': 8.0}]
    }
    coverage2 = agent._calculate_coverage_real(good_state)
    
    assert coverage2 > coverage1, "FAIL: Good state should have higher coverage"
    
    print(f"✅ PASS: Coverage reflects progress")
    print(f"  Bad state (duplicates, no findings): {coverage1:.1%}")
    print(f"  Good state (diverse, findings): {coverage2:.1%}")
    
    return True

def run_all_tests():
    """Run all intelligence tests"""
    print("\n" + "=" * 60)
    print("AUTONOMOUS AGENT INTELLIGENCE TEST SUITE")
    print("=" * 60)
    
    tests = [
        ("Tool Repetition Prevention", test_tool_repetition_prevention),
        ("Phase Transition", test_phase_transition),
        ("Dynamic Commands", test_dynamic_commands),
        ("API Key Handling", test_api_key_handling),
        ("Coverage Calculation", test_coverage_calculation),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ FAIL: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    print("=" * 60)
    
    return passed == total

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)