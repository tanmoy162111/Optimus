"""
Test RL components
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from training.rl_state import RLStateEncoder
from training.rl_trainer import EnhancedRLAgent
import numpy as np

def test_rl_components():
    """Test RL state encoding and agent"""
    print("\n" + "="*70)
    print("TESTING RL COMPONENTS")
    print("="*70)
    
    # Test 1: State Encoding
    print("\n[Test 1] RL State Encoding...")
    try:
        encoder = RLStateEncoder()
        
        # Create sample scan context
        scan_context = {
            'target_type': 'web_app',
            'target_complexity': 0.7,
            'phase': 'scanning',
            'findings': [
                {'type': 'sql_injection', 'severity': 9.0, 'exploitable': True},
                {'type': 'xss', 'severity': 7.5, 'exploitable': False}
            ],
            'time_elapsed': 300,
            'time_budget': 3600,
            'tools_executed': ['nmap', 'nikto'],
            'ml_confidence': 0.85,
            'coverage': 0.65
        }
        
        # Encode state
        state_dict = encoder.encode_state(scan_context)
        state_vector = encoder.state_to_vector(state_dict)
        
        assert len(state_vector) == 23, f"State vector should be 23 dims, got {len(state_vector)}"
        assert state_vector.dtype == np.float32
        assert np.all(state_vector >= 0) and np.all(state_vector <= 1.0), "Values should be normalized"
        
        print(f"  ✓ State encoded: {len(state_vector)} dimensions")
        print(f"    - Highest severity: {state_dict['highest_severity']}")
        print(f"    - Has critical vuln: {state_dict['has_critical_vuln']}")
        print(f"    - SQL detected: {state_dict['sql_detected']}")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 2: RL Agent Initialization
    print("\n[Test 2] RL Agent Initialization...")
    try:
        agent = EnhancedRLAgent(state_dim=23, num_actions=20)
        
        assert agent.q_network is not None
        assert agent.target_network is not None
        assert agent.state_dim == 23
        assert agent.num_actions == 20
        
        print(f"  ✓ Agent initialized")
        print(f"    - State dim: {agent.state_dim}")
        print(f"    - Num actions: {agent.num_actions}")
        print(f"    - Epsilon: {agent.epsilon}")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 3: Action Selection
    print("\n[Test 3] Action Selection...")
    try:
        available_tools = ['nmap', 'nikto', 'sqlmap', 'metasploit', 'burpsuite']
        
        # Select action
        action = agent.select_action(state_vector, available_tools, epsilon=0.5)
        
        assert action in available_tools, f"Selected action {action} not in available tools"
        
        print(f"  ✓ Action selected: {action}")
        print(f"    - Available tools: {len(available_tools)}")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 4: Reward Calculation
    print("\n[Test 4] Reward Calculation...")
    try:
        # Good result
        good_result = {
            'new_vulns': [
                {'severity': 9.0, 'exploitable': True},
                {'severity': 7.5, 'exploitable': False}
            ],
            'execution_time': 10,
            'false_positives': 0,
            'phase': 'scanning',
            'detection_triggered': False
        }
        
        reward_good = agent.calculate_reward(good_result)
        
        # Bad result
        bad_result = {
            'new_vulns': [],
            'execution_time': 120,
            'false_positives': 3,
            'phase': 'reconnaissance',
            'detection_triggered': True
        }
        
        reward_bad = agent.calculate_reward(bad_result)
        
        assert reward_good > reward_bad, "Good result should have higher reward than bad result"
        
        print(f"  ✓ Reward (good result): {reward_good:.2f}")
        print(f"  ✓ Reward (bad result): {reward_bad:.2f}")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 5: Experience Update
    print("\n[Test 5] Experience Update & Training...")
    try:
        # Create synthetic experiences
        for i in range(50):
            state = np.random.rand(23).astype(np.float32)
            action = available_tools[i % len(available_tools)]
            reward = np.random.uniform(-10, 30)
            next_state = np.random.rand(23).astype(np.float32)
            done = (i % 10 == 9)
            
            agent.update(state, action, reward, next_state, done)
        
        assert len(agent.memory) > 0, "Memory should contain experiences"
        
        print(f"  ✓ Stored {len(agent.memory)} experiences")
        print(f"  ✓ Epsilon decayed to: {agent.epsilon:.3f}")
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 6: Model Save/Load
    print("\n[Test 6] Model Persistence...")
    try:
        # Save
        model_path = './models/test_rl_agent.weights.h5'
        agent.save_model(model_path)
        
        # Create new agent and load
        new_agent = EnhancedRLAgent(state_dim=23, num_actions=20)
        new_agent.load_model(model_path)
        
        # Verify weights are same
        original_weights = agent.q_network.get_weights()[0]
        loaded_weights = new_agent.q_network.get_weights()[0]
        
        assert np.allclose(original_weights, loaded_weights), "Loaded weights should match saved weights"
        
        print(f"  ✓ Test passed")
        
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "="*70)
    print("ALL RL TESTS PASSED ✓")
    print("="*70)
    
    return True

if __name__ == "__main__":
    try:
        success = test_rl_components()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ RL test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
