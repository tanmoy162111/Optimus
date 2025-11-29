#!/usr/bin/env python3
"""
Comprehensive Agent Training Script

Trains autonomous penetration testing agent on practice VMs

Usage:
    python train_agent_on_vms.py --targets http://target1.local http://target2.local \
                                  --episodes 100 \
                                  --learning-mode exploration

Features:
- Multi-episode training sessions
- Live tool execution and feedback
- Continuous learning and model updates
- Comprehensive metrics tracking
- Automated reporting
"""
import argparse
import sys
import os
from pathlib import Path
from typing import List, Dict, Any
import json
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from training_environment.session_manager import TrainingSessionManager

class AgentTrainingOrchestrator:
    """
    Orchestrates comprehensive agent training on practice VMs
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize training orchestrator

        Args:
            config: Training configuration including:
                - targets: List of practice VM URLs
                - num_episodes: Number of training episodes
                - tools_available: Tools agent can use
                - learning_mode: 'exploration' or 'exploitation'
                - update_frequency: How often to retrain models
                - max_duration: Maximum training duration
                - checkpoint_interval: Save progress interval
        """
        self.config = config
        self.targets = config['targets']
        self.num_episodes = config.get('num_episodes', 50)
        self.learning_mode = config.get('learning_mode', 'exploration')
        
        # Training state
        self.episode_history = []
        self.current_episode = 0
        
        # Setup output directory
        self.output_dir = Path(config.get('output_dir', 'training_output'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[AgentTraining] Initialized with {len(self.targets)} targets")
        print(f"[AgentTraining] Training for {self.num_episodes} episodes")
        print(f"[AgentTraining] Learning mode: {self.learning_mode}")

    def run_training(self) -> Dict[str, Any]:
        """
        Execute complete training workflow

        Returns:
            Training results and metrics
        """
        print("\n" + "="*80)
        print("AGENT TRAINING SESSION START")
        print("="*80)
        
        training_start = datetime.now()
        
        try:
            # Initialize training session manager
            session_config = {
                'num_episodes': self.num_episodes,
                'learning_mode': self.learning_mode,
                'output_dir': str(self.output_dir),
                'feedback_frequency': 5
            }
            
            session_manager = TrainingSessionManager(self.targets, session_config)
            
            # Run training session
            results = session_manager.run_training_session()
            
            # Print summary
            self._print_training_summary(results)
            
            return results
                
        except KeyboardInterrupt:
            print("\n[AgentTraining] Training interrupted by user")
            return self._save_checkpoint()
        except Exception as e:
            print(f"\n[AgentTraining] Training failed: {e}")
            import traceback
            traceback.print_exc()
            return {'error': str(e)}

    def _save_checkpoint(self) -> Dict:
        """Save training checkpoint"""
        checkpoint = {
            'current_episode': self.current_episode,
            'episode_history': self.episode_history,
            'timestamp': datetime.now().isoformat()
        }
        
        checkpoint_file = self.output_dir / 'training_checkpoint.json'
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2, default=str)
        
        print(f"[Checkpoint] Saved to {checkpoint_file}")
        return checkpoint

    def _print_training_summary(self, results: Dict):
        """Print comprehensive training summary"""
        print("\n" + "="*80)
        print("TRAINING SESSION COMPLETE")
        print("="*80)
        
        print(f"\nTraining ID: {results['training_id']}")
        print(f"Duration: {results['duration_seconds']:.1f} seconds")
        print(f"Total Episodes: {results['total_episodes']}")
        print(f"Targets Trained: {results['targets_trained']}")
        
        # Episode statistics
        episode_history = results.get('episode_history', [])
        successful_episodes = [e for e in episode_history if e.get('success')]
        failed_episodes = [e for e in episode_history if not e.get('success')]
        
        print(f"\nEpisodes:")
        print(f"  Successful: {len(successful_episodes)}")
        print(f"  Failed: {len(failed_episodes)}")
        
        if successful_episodes:
            total_findings = sum(len(e.get('findings', [])) for e in successful_episodes)
            avg_findings = total_findings / len(successful_episodes) if successful_episodes else 0
            print(f"  Average Findings per Episode: {avg_findings:.2f}")
            
            total_tools = sum(len(e.get('tools_used', [])) for e in successful_episodes)
            avg_tools = total_tools / len(successful_episodes) if successful_episodes else 0
            print(f"  Average Tools per Episode: {avg_tools:.2f}")
        
        # Strategy performance
        strategy_report = results.get('final_strategy_report', {})
        if strategy_report.get('best_overall'):
            print(f"\nBest Overall Strategy: {strategy_report['best_overall']}")
        
        print("\n" + "="*80)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Train autonomous penetration testing agent on practice VMs'
    )
    
    parser.add_argument(
        '--targets',
        nargs='+',
        required=True,
        help='Target practice VM URLs/IPs')
    parser.add_argument(
        '--episodes',
        type=int,
        default=50,
        help='Number of training episodes (default: 50)')
    parser.add_argument(
        '--learning-mode',
        choices=['exploration', 'exploitation', 'mixed'],
        default='mixed',
        help='Learning mode (default: mixed)')
    parser.add_argument(
        '--output-dir',
        default='training_output',
        help='Output directory for results (default: training_output)')
    parser.add_argument(
        '--max-duration',
        type=int,
        default=36000,
        help='Maximum training duration in seconds (default: 36000 = 10 hours)')
    
    args = parser.parse_args()
    
    # Build configuration
    config = {
        'targets': args.targets,
        'num_episodes': args.episodes,
        'learning_mode': args.learning_mode,
        'output_dir': args.output_dir,
        'max_duration': args.max_duration,
        'tools_available': [
            'nmap', 'nikto', 'sqlmap', 'nuclei', 'gobuster', 'ffuf',
            'dalfox', 'commix', 'whatweb', 'wpscan', 'hydra'
        ]
    }
    
    print("="*80)
    print("AUTONOMOUS AGENT TRAINING SYSTEM")
    print("="*80)
    print(f"\nConfiguration:")
    print(f"  Targets: {len(config['targets'])}")
    print(f"  Episodes: {config['num_episodes']}")
    print(f"  Learning Mode: {config['learning_mode']}")
    print(f"  Output: {config['output_dir']}")
    
    # Initialize and run training
    orchestrator = AgentTrainingOrchestrator(config)
    results = orchestrator.run_training()
    
    if results.get('error'):
        print(f"\n❌ Training failed: {results['error']}")
        return 1
    else:
        print("\n✅ Training completed successfully!")
        return 0

if __name__ == '__main__':
    sys.exit(main())