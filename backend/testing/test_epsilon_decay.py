"""Test epsilon decay functionality"""
import sys
import os
sys.path.append('..')
import numpy as np
from training.rl_trainer import EnhancedRLAgent

def test_epsilon_decay():
    """
    Verify epsilon decays from 1.0 to ~0.05 over 200 episodes
    """
    print("="*80)
    print("TESTING: Epsilon Decay Mechanism")
    print("="*80)
    
    agent = EnhancedRLAgent()
    
    print(f"\nInitial epsilon: {agent.epsilon:.4f}")
    
    # Simulate 200 episodes
    for episode in range(200):
        # Simulate episode steps
        for step in range(10):
            state = np.random.randn(23)
            next_state = np.random.randn(23)
            reward = np.random.uniform(-10, 10)
            
            # Update agent (done=False for intermediate steps)
            done = (step == 9)  # Last step
            agent.update(state, 'nmap', reward, next_state, done)
    
    print(f"\nFinal epsilon: {agent.epsilon:.4f}")
    
    # Verify decay worked
    assert agent.epsilon < 0.15, f"❌ Epsilon too high: {agent.epsilon:.4f} >= 0.15"
    assert agent.epsilon >= 0.04, f"❌ Epsilon too low: {agent.epsilon:.4f} < 0.04"
    assert len(agent.epsilon_history) > 0, "❌ Epsilon history not tracked"
    
    print("\n✅ EPSILON DECAY TEST PASSED")
    print(f"   Epsilon decreased from 1.0 → {agent.epsilon:.4f}")
    print(f"   Episodes tracked: {len(agent.epsilon_history)}")
    
    # Test save/load
    print("\nTesting save/load functionality...")
    test_path = 'test_epsilon_model.pkl'
    agent.save_model(test_path)
    
    new_agent = EnhancedRLAgent()
    new_agent.load_model(test_path)
    
    assert abs(new_agent.epsilon - agent.epsilon) < 0.001, "❌ Epsilon not preserved in save/load"
    print(f"\n✅ Save/load preserves epsilon: {new_agent.epsilon:.4f}")
    
    # Cleanup
    if os.path.exists(test_path):
        os.remove(test_path)
    
    print("\n" + "="*80)
    print("ALL TESTS PASSED ✅")
    print("="*80)

if __name__ == '__main__':
    test_epsilon_decay()
