"""
Test Phase-Aware Inference Components
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from inference.phase_controller import PhaseTransitionController
from inference.tool_selector import PhaseAwareToolSelector
from training.rl_state import RLStateEncoder
from training.rl_trainer import EnhancedRLAgent

def test_inference_components():
    """Test phase controller and tool selector"""
    print("\n" + "="*70)
    print("TESTING PHASE-AWARE INFERENCE COMPONENTS")
    print("="*70)
    
    # Test 1: Phase Transition Controller
    print("\n[Test 1] Phase Transition Logic...")
    try:
        controller = PhaseTransitionController()
        
        # Test reconnaissance -> scanning transition
        recon_state = {
            'phase': 'reconnaissance',
            'coverage': 0.7,
            'findings': [],
            'phase_data': {
                'subdomains': 6,
                'technologies': 4
            },
            'time_elapsed': 300
        }
        
        next_phase = controller.should_transition(recon_state)
        assert next_phase == 'scanning', f"Should transition to scanning, got {next_phase}"
        
        print(f"  ✓ Reconnaissance -> Scanning transition works")
        
        # Test scanning -> exploitation transition
        scan_state = {
            'phase': 'scanning',
            'coverage': 0.75,
            'findings': [
                {'severity': 9.0, 'type': 'sql_injection'},
                {'severity': 7.5, 'type': 'xss'},
                {'severity': 6.0, 'type': 'lfi'}
            ],
            'phase_data': {},
            'time_elapsed': 600
        }
        
        next_phase = controller.should_transition(scan_state)
        assert next_phase == 'exploitation', f"Should transition to exploitation, got {next_phase}"
        
        print(f"  ✓ Scanning -> Exploitation transition works")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 2: Phase Completion Criteria
    print("\n[Test 2] Phase Completion Criteria...")
    try:
        # Test incomplete reconnaissance
        incomplete_recon = {
            'phase': 'reconnaissance',
            'coverage': 0.3,
            'findings': [],
            'phase_data': {'subdomains': 2, 'technologies': 1},
            'time_elapsed': 100
        }
        
        next_phase = controller.should_transition(incomplete_recon)
        assert next_phase == 'reconnaissance', "Should stay in reconnaissance"
        
        print(f"  ✓ Stays in reconnaissance when incomplete")
        
        # Test exploitation with access gained
        exploit_state = {
            'phase': 'exploitation',
            'coverage': 0.6,
            'findings': [{'severity': 9.0}],
            'phase_data': {
                'access_gained': True,
                'shells_obtained': 1
            },
            'time_elapsed': 900
        }
        
        next_phase = controller.should_transition(exploit_state)
        assert next_phase == 'post_exploitation', f"Should move to post_exploitation, got {next_phase}"
        
        print(f"  ✓ Exploitation -> Post-exploitation with access")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 3: Tool Selector
    print("\n[Test 3] Tool Selection...")
    try:
        selector = PhaseAwareToolSelector()
        
        # Test reconnaissance phase tools
        recon_scan = {
            'phase': 'reconnaissance',
            'target_type': 'web_app',
            'coverage': 0.4,
            'findings': [],
            'tools_executed': [],
            'phase_data': {'technologies': 0},
            'time_elapsed': 50
        }
        
        recommendation = selector.recommend_tools(recon_scan)
        
        assert 'tools' in recommendation
        assert len(recommendation['tools']) > 0
        assert recommendation['phase'] == 'reconnaissance'
        assert 'sublist3r' in recommendation['tools'], "Should recommend sublist3r for recon"
        
        print(f"  ✓ Reconnaissance tools: {recommendation['tools']}")
        print(f"    Reasoning: {recommendation['reasoning']}")
        
        # Test scanning phase tools
        scan_scan = {
            'phase': 'scanning',
            'target_type': 'web_app',
            'coverage': 0.6,
            'findings': [],
            'tools_executed': [],
            'phase_data': {},
            'time_elapsed': 200
        }
        
        recommendation = selector.recommend_tools(scan_scan)
        
        assert 'nmap' in recommendation['tools'], "Should recommend nmap for scanning"
        
        print(f"  ✓ Scanning tools: {recommendation['tools']}")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 4: Rule-based Tool Selection
    print("\n[Test 4] Rule-based Tool Selection...")
    try:
        # Test SQL injection triggers sqlmap
        exploit_scan = {
            'phase': 'exploitation',
            'target_type': 'web_app',
            'coverage': 0.7,
            'findings': [
                {'type': 'sql_injection', 'severity': 9.0}
            ],
            'tools_executed': [],
            'phase_data': {},
            'time_elapsed': 600
        }
        
        recommendation = selector.recommend_tools(exploit_scan)
        
        assert 'sqlmap' in recommendation['tools'], "Should recommend sqlmap for SQL injection"
        
        print(f"  ✓ SQL injection triggers sqlmap")
        
        # Test XSS triggers dalfox
        xss_scan = {
            'phase': 'exploitation',
            'target_type': 'web_app',
            'coverage': 0.7,
            'findings': [
                {'type': 'xss', 'severity': 7.5}
            ],
            'tools_executed': [],
            'phase_data': {},
            'time_elapsed': 600
        }
        
        recommendation = selector.recommend_tools(xss_scan)
        
        assert 'dalfox' in recommendation['tools'], "Should recommend dalfox for XSS"
        
        print(f"  ✓ XSS triggers dalfox")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 5: Integration with RL
    print("\n[Test 5] RL Integration...")
    try:
        # Initialize RL components
        encoder = RLStateEncoder()
        agent = EnhancedRLAgent(state_dim=23, num_actions=20)
        
        # Set RL components in selector
        selector.set_rl_agent(agent, encoder)
        
        # Test with RL
        test_scan = {
            'phase': 'scanning',
            'target_type': 'web_app',
            'coverage': 0.6,
            'findings': [{'severity': 7.0}],
            'tools_executed': ['nmap'],
            'phase_data': {},
            'time_elapsed': 300,
            'time_budget': 3600,
            'ml_confidence': 0.8
        }
        
        recommendation = selector.recommend_tools(test_scan)
        
        assert 'rl_selected' in recommendation
        assert recommendation['rl_selected'] is not None
        
        print(f"  ✓ RL agent selected: {recommendation['rl_selected']}")
        print(f"  ✓ Final tools: {recommendation['tools']}")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 6: Transition History
    print("\n[Test 6] Transition History Tracking...")
    try:
        history = controller.get_transition_history()
        
        assert isinstance(history, list)
        assert len(history) >= 2, f"Should have at least 2 transitions, got {len(history)}"
        
        print(f"  ✓ Transition history: {len(history)} transitions")
        for i, trans in enumerate(history[:3]):
            print(f"    {i+1}. {trans['from']} -> {trans['to']} "
                  f"(findings: {trans['findings']}, coverage: {trans['coverage']:.2f})")
        
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "="*70)
    print("ALL INFERENCE TESTS PASSED ✓")
    print("="*70)
    
    return True

if __name__ == "__main__":
    try:
        success = test_inference_components()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Inference test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
