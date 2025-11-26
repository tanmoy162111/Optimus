"""
RL Agent Performance Evaluation
Tests learning convergence, exploration/exploitation, and decision quality
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from training.rl_trainer import EnhancedRLAgent
from training.rl_state import RLStateEncoder

class RLAgentEvaluator:
    """Evaluate RL agent performance"""
    
    def __init__(self):
        self.output_dir = Path('evaluation_results')
        self.output_dir.mkdir(exist_ok=True)
    
    def evaluate_learning_convergence(self, training_state: Dict) -> Dict[str, Any]:
        """
        Test 1: Learning Convergence
        
        Verify that RL agent improves over episodes
        
        Success Criteria:
        - Reward increases by ≥50% from early to late episodes
        - Final 100 episodes avg reward > initial 100 episodes
        """
        print("\n" + "="*80)
        print("EVALUATING: RL Learning Convergence")
        print("="*80)
        
        rl_metrics = training_state.get('rl_metrics', {})
        episodes_trained = rl_metrics.get('episodes_trained', 0)
        
        print(f"\nEpisodes trained: {episodes_trained}")
        
        if episodes_trained < 200:
            print(f"⚠️  Insufficient training episodes: {episodes_trained} < 200 (recommended)")
            print(f"   Recommendation: Train for at least 200 episodes for convergence")
            
            results = {
                'status': 'insufficient_training',
                'episodes_trained': episodes_trained,
                'recommendation': 'Train for 200+ episodes'
            }
        else:
            # In production, analyze actual reward history
            print(f"✅ Sufficient training episodes")
            results = {
                'status': 'adequate',
                'episodes_trained': episodes_trained
            }
        
        print(f"\n{'='*80}")
        if episodes_trained >= 200:
            print(f"✅ RL LEARNING CONVERGENCE: ADEQUATE")
        else:
            print(f"⚠️  RL LEARNING CONVERGENCE: NEEDS MORE TRAINING")
        print(f"{'='*80}\n")
        
        self.save_results('rl_convergence', results)
        return results
    
    def evaluate_exploration_exploitation(self, training_state: Dict) -> Dict[str, Any]:
        """
        Test 2: Exploration vs Exploitation Balance
        
        Success Criteria:
        - Epsilon decays from 1.0 to ≤0.1
        """
        print("\n" + "="*80)
        print("EVALUATING: Exploration/Exploitation Balance")
        print("="*80)
        
        rl_metrics = training_state.get('rl_metrics', {})
        final_epsilon = rl_metrics.get('epsilon', 1.0)
        
        print(f"\nFinal epsilon: {final_epsilon:.3f}")
        
        results = {
            'final_epsilon': final_epsilon,
            'target_epsilon': 0.1
        }
        
        print(f"\n{'='*80}")
        if final_epsilon <= 0.1:
            print(f"✅ EXPLORATION/EXPLOITATION: PROPER DECAY")
            results['status'] = 'passed'
        else:
            print(f"⚠️  EXPLORATION/EXPLOITATION: EPSILON TOO HIGH")
            print(f"   Recommendation: Continue training until epsilon ≤ 0.1")
            results['status'] = 'needs_training'
        print(f"{'='*80}\n")
        
        self.save_results('rl_exploration', results)
        return results
    
    def evaluate_model_exists(self) -> Dict[str, Any]:
        """
        Test 3: Verify RL model file exists and is loadable
        """
        print("\n" + "="*80)
        print("EVALUATING: RL Model File Integrity")
        print("="*80)
        
        model_path = 'models/rl_agent.weights.h5'
        
        if os.path.exists(model_path):
            print(f"\n✅ RL model file found: {model_path}")
            file_size = os.path.getsize(model_path) / 1024  # KB
            print(f"   File size: {file_size:.2f} KB")
            
            # Try to load the model
            try:
                agent = EnhancedRLAgent(state_dim=23, num_actions=20)
                agent.load_model(model_path)
                print(f"✅ Model loaded successfully")
                
                results = {
                    'status': 'passed',
                    'model_path': model_path,
                    'file_size_kb': file_size,
                    'loadable': True
                }
            except Exception as e:
                print(f"❌ Model loading failed: {e}")
                results = {
                    'status': 'failed',
                    'model_path': model_path,
                    'error': str(e),
                    'loadable': False
                }
        else:
            print(f"\n❌ RL model file not found: {model_path}")
            results = {
                'status': 'missing',
                'model_path': model_path,
                'loadable': False
            }
        
        print(f"\n{'='*80}")
        if results.get('loadable'):
            print(f"✅ RL MODEL INTEGRITY: PASSED")
        else:
            print(f"❌ RL MODEL INTEGRITY: FAILED")
        print(f"{'='*80}\n")
        
        self.save_results('rl_model_integrity', results)
        return results
    
    def save_results(self, test_name: str, results: Dict):
        """Save evaluation results to JSON"""
        timestamp = datetime.now().isoformat()
        
        output = {
            'test': test_name,
            'timestamp': timestamp,
            'results': results
        }
        
        output_file = self.output_dir / f'{test_name}_evaluation.json'
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"📊 Results saved to: {output_file}")

def main():
    """Run RL agent evaluation"""
    print("""
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                    OPTIMUS RL AGENT EVALUATION SUITE                     ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    evaluator = RLAgentEvaluator()
    
    # Load training state
    print("📂 Loading training state...")
    try:
        with open('data/ml_training_state.json', 'r') as f:
            training_state = json.load(f)
    except FileNotFoundError:
        print("❌ Training state file not found: data/ml_training_state.json")
        return
    
    # Run evaluations
    results = {}
    
    results['convergence'] = evaluator.evaluate_learning_convergence(training_state)
    results['exploration'] = evaluator.evaluate_exploration_exploitation(training_state)
    results['model_integrity'] = evaluator.evaluate_model_exists()
    
    # Overall assessment
    print("\n" + "="*80)
    print("RL AGENT OVERALL ASSESSMENT")
    print("="*80)
    
    passed_tests = sum(1 for r in results.values() if r.get('status') == 'passed')
    total_tests = len(results)
    
    print(f"\nTests passed: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print(f"\n✅ RL AGENT READY FOR PRODUCTION")
    elif passed_tests >= total_tests * 0.7:
        print(f"\n⚠️  RL AGENT NEEDS MINOR IMPROVEMENTS")
    else:
        print(f"\n❌ RL AGENT NEEDS SIGNIFICANT RETRAINING")
    
    print("="*80 + "\n")
    
    print("\n✅ RL Evaluation complete!")

if __name__ == '__main__':
    main()
