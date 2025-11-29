"""
Training Session 1: Reconnaissance & Scanning phases
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from training.production_data_collector import get_collector
from inference.autonomous_agent import AutonomousPentestAgent
import json

def training_session_1():
    """Focus: Reconnaissance and Scanning phases"""
    
    # Enable production logging
    collector = get_collector()
    
    # Load targets
    with open('testing/data/training_targets.json') as f:
        targets = json.load(f)['targets']
    
    agent = AutonomousPentestAgent()
    
    for target in targets[:2]:  # Start with first 2 targets
        print(f"\n{'='*80}")
        print(f"Training Session 1: {target['name']}")
        print(f"Focus: Reconnaissance & Scanning")
        print(f"{'='*80}\n")
        
        config = {
            'max_time': 1800,  # 30 minutes per target
            'depth': 'normal',
            'stealth': False,
            'aggressive': False,  # Conservative for learning
            'target_type': target['type'],
            'stop_at_phase': 'scanning'  # Only recon + scanning
        }
        
        try:
            result = agent.run_autonomous_scan(target['url'], config)
            
            # Analyze results
            print(f"\n{'='*80}")
            print(f"Session 1 Results: {target['name']}")
            print(f"{'='*80}")
            print(f"Tools executed: {len(result.get('tools_executed', []))}")
            print(f"Findings: {len(result.get('findings', []))}")
            print(f"Coverage: {result.get('coverage', 0):.1%}")
            print(f"Phase reached: {result.get('phase', 'unknown')}")
            
            # Save detailed log
            filename = f"testing/data/session1_{target['name'].replace(' ', '_')}.json"
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
                
        except Exception as e:
            print(f"Error scanning {target['name']}: {e}")
            # Save error result
            error_result = {
                'error': str(e),
                'target': target['url'],
                'tools_executed': [],
                'findings': [],
                'coverage': 0
            }
            filename = f"testing/data/session1_{target['name'].replace(' ', '_')}_error.json"
            with open(filename, 'w') as f:
                json.dump(error_result, f, indent=2)
    
    # Flush production data
    collector.flush_all()
    
    print("\n✅ Training Session 1 Complete")
    print("📊 Check: data/production_logs/ for logged executions")

if __name__ == '__main__':
    training_session_1()