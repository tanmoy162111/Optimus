#!/usr/bin/env python3
"""
Fully Autonomous Training Script

This script trains the agent with full autonomy - the agent makes all decisions based on 
tool outputs and findings without predefined phases or fixed tool selections.

Features:
- Agent decides which tools to use based on previous findings
- Agent selects approaches and attacking patterns from its knowledge
- Agent executes commands with appropriate parameters
- No predefined phases - agent determines workflow dynamically
- Fully adaptive decision making based on real-time results
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
from inference.autonomous_agent import AutonomousPentestAgent
from inference.learning_module import RealTimeLearningModule
from inference.strategy_selector import StrategySelector

class FullyAutonomousTrainer:
    """
    Trainer for fully autonomous agent operation
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize fully autonomous trainer
        
        Args:
            config: Training configuration
        """
        self.config = config
        self.targets = config['targets']
        self.max_episodes = config.get('max_episodes', 10)
        self.max_time_per_episode = config.get('max_time_per_episode', 3600)  # 1 hour default
        self.output_dir = Path(config.get('output_dir', 'training_output/fully_autonomous'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[FullyAutonomousTrainer] Initialized with {len(self.targets)} targets")
        print(f"[FullyAutonomousTrainer] Max episodes: {self.max_episodes}")
        print(f"[FullyAutonomousTrainer] Max time per episode: {self.max_time_per_episode}s")
        
    def run_fully_autonomous_training(self) -> Dict[str, Any]:
        """
        Run fully autonomous training where agent makes all decisions
        
        Returns:
            Training results
        """
        print("\n" + "="*80)
        print("FULLY AUTONOMOUS TRAINING SESSION START")
        print("="*80)
        
        training_start = datetime.now()
        episode_results = []
        
        try:
            # Run episodes
            for episode_num in range(self.max_episodes):
                target = self.targets[episode_num % len(self.targets)]
                
                print(f"\n[Episode {episode_num + 1}/{self.max_episodes}] Target: {target}")
                
                # Run fully autonomous episode
                episode_result = self._run_fully_autonomous_episode(
                    target=target,
                    episode_num=episode_num
                )
                
                episode_results.append(episode_result)
                
                # Save checkpoint
                if (episode_num + 1) % 2 == 0:
                    self._save_checkpoint(episode_results)
            
            # Generate final report
            training_end = datetime.now()
            duration = (training_end - training_start).total_seconds()
            
            results = {
                'training_id': f"fully_autonomous_{training_start.strftime('%Y%m%d_%H%M%S')}",
                'duration_seconds': duration,
                'total_episodes': self.max_episodes,
                'targets_trained': len(self.targets),
                'episode_results': episode_results,
                'tools_executed': self._collect_all_tools(episode_results),
                'total_findings': self._count_total_findings(episode_results)
            }
            
            # Save results
            self._save_results(results)
            self._print_final_summary(results)
            
            return results
            
        except KeyboardInterrupt:
            print("\n[Training] Interrupted by user")
            return self._save_checkpoint(episode_results)
        except Exception as e:
            print(f"\n[Training] Error: {e}")
            import traceback
            traceback.print_exc()
            return {'error': str(e)}
    
    def _run_fully_autonomous_episode(self, target: str, episode_num: int) -> Dict:
        """
        Run a fully autonomous episode where agent makes all decisions
        
        Args:
            target: Target URL/IP
            episode_num: Episode number
            
        Returns:
            Episode results
        """
        episode_start = datetime.now()
        
        # Configure for fully autonomous mode
        scan_config = {
            'max_time': self.max_time_per_episode,
            'mode': 'fully_autonomous',
            'learning_enabled': True,
            'adaptive_tool_selection': True,
            'dynamic_workflow': True,
            'self_directed': True
        }
        
        try:
            # Initialize autonomous agent
            agent = AutonomousPentestAgent()
            
            # Run fully autonomous scan
            print(f"  [Episode] Starting fully autonomous scan...")
            scan_result = agent.run_autonomous_scan(target, scan_config)
            
            episode_end = datetime.now()
            duration = (episode_end - episode_start).total_seconds()
            
            # Compile episode data
            episode_data = {
                'episode_num': episode_num,
                'target': target,
                'duration': duration,
                'tools_used': scan_result.get('tools_executed', []),
                'findings': scan_result.get('findings', []),
                'coverage': scan_result.get('coverage', 0.0),
                'strategy_used': scan_result.get('strategy', 'adaptive'),
                'success': True,
                'timestamp': episode_start.isoformat(),
                'decision_points': scan_result.get('decision_log', []),
                'adaptive_choices': scan_result.get('adaptive_choices', [])
            }
            
            tools_count = len(episode_data['tools_used'])
            findings_count = len(episode_data['findings'])
            
            print(f"  [Episode] Completed: {findings_count} findings, "
                  f"{tools_count} tools, {duration:.1f}s")
            
            return episode_data
            
        except Exception as e:
            print(f"  [Episode] Failed: {e}")
            episode_data = {
                'episode_num': episode_num,
                'target': target,
                'success': False,
                'error': str(e),
                'timestamp': episode_start.isoformat()
            }
            return episode_data
    
    def _collect_all_tools(self, episode_results: List[Dict]) -> Dict[str, int]:
        """
        Collect all tools used across episodes
        
        Args:
            episode_results: List of episode results
            
        Returns:
            Dictionary with tool counts
        """
        tool_counts = {}
        
        for episode in episode_results:
            if episode.get('success') and 'tools_used' in episode:
                tools_used = episode['tools_used']
                for tool_entry in tools_used:
                    if isinstance(tool_entry, dict):
                        tool_name = tool_entry.get('tool', 'unknown')
                    else:
                        tool_name = tool_entry
                    
                    tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
        
        return tool_counts
    
    def _count_total_findings(self, episode_results: List[Dict]) -> int:
        """
        Count total findings across all episodes
        
        Args:
            episode_results: List of episode results
            
        Returns:
            Total findings count
        """
        total_findings = 0
        
        for episode in episode_results:
            if episode.get('success') and 'findings' in episode:
                total_findings += len(episode['findings'])
        
        return total_findings
    
    def _save_checkpoint(self, episode_results: List[Dict]) -> Dict:
        """
        Save training checkpoint
        
        Args:
            episode_results: Current episode results
            
        Returns:
            Checkpoint data
        """
        checkpoint = {
            'current_episode': len(episode_results),
            'episode_results': episode_results,
            'timestamp': datetime.now().isoformat()
        }
        
        checkpoint_file = self.output_dir / 'autonomous_checkpoint.json'
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2, default=str)
        
        print(f"[Checkpoint] Saved to {checkpoint_file}")
        return checkpoint
    
    def _save_results(self, results: Dict):
        """
        Save training results
        
        Args:
            results: Training results
        """
        output_file = self.output_dir / f"autonomous_training_results_{results['training_id']}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n[Results] Saved to {output_file}")
    
    def _print_final_summary(self, results: Dict):
        """
        Print final training summary
        
        Args:
            results: Training results
        """
        print("\n" + "="*80)
        print("FULLY AUTONOMOUS TRAINING SESSION COMPLETE")
        print("="*80)
        
        print(f"\nTraining ID: {results['training_id']}")
        print(f"Duration: {results['duration_seconds']:.1f} seconds")
        print(f"Total Episodes: {results['total_episodes']}")
        print(f"Targets Trained: {results['targets_trained']}")
        print(f"Total Findings: {results['total_findings']}")
        
        # Episode statistics
        successful_episodes = [e for e in results['episode_results'] if e.get('success')]
        failed_episodes = [e for e in results['episode_results'] if not e.get('success')]
        
        print(f"\nEpisodes:")
        print(f"  Successful: {len(successful_episodes)}")
        print(f"  Failed: {len(failed_episodes)}")
        
        if successful_episodes:
            total_findings = sum(len(e.get('findings', [])) for e in successful_episodes)
            avg_findings = total_findings / len(successful_episodes) if successful_episodes else 0
            
            total_tools = sum(len(e.get('tools_used', [])) for e in successful_episodes)
            avg_tools = total_tools / len(successful_episodes) if successful_episodes else 0
            
            total_time = sum(e.get('duration', 0) for e in successful_episodes)
            avg_time = total_time / len(successful_episodes) if successful_episodes else 0
            
            print(f"  Average Findings per Episode: {avg_findings:.2f}")
            print(f"  Average Tools per Episode: {avg_tools:.2f}")
            print(f"  Average Duration: {avg_time:.1f}s")
        
        # Tools used
        if 'tools_executed' in results:
            print(f"\nTools Executed:")
            for tool, count in sorted(results['tools_executed'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {tool}: {count}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Fully Autonomous Agent Training - Agent makes all decisions based on tool outputs'
    )
    
    parser.add_argument(
        '--targets',
        nargs='+',
        required=True,
        help='Target URLs/IPs')
    parser.add_argument(
        '--max-episodes',
        type=int,
        default=5,
        help='Maximum number of episodes (default: 5)')
    parser.add_argument(
        '--max-time-per-episode',
        type=int,
        default=3600,
        help='Maximum time per episode in seconds (default: 3600 = 1 hour)')
    parser.add_argument(
        '--output-dir',
        default='training_output/fully_autonomous',
        help='Output directory for results')
    
    args = parser.parse_args()
    
    # Build configuration
    config = {
        'targets': args.targets,
        'max_episodes': args.max_episodes,
        'max_time_per_episode': args.max_time_per_episode,
        'output_dir': args.output_dir
    }
    
    print("="*80)
    print("FULLY AUTONOMOUS AGENT TRAINING SYSTEM")
    print("="*80)
    print(f"\nConfiguration:")
    print(f"  Targets: {len(config['targets'])}")
    print(f"  Max Episodes: {config['max_episodes']}")
    print(f"  Max Time per Episode: {config['max_time_per_episode']}s")
    print(f"  Output: {config['output_dir']}")
    
    # Initialize and run training
    trainer = FullyAutonomousTrainer(config)
    results = trainer.run_fully_autonomous_training()
    
    if results.get('error'):
        print(f"\n❌ Training failed: {results['error']}")
        return 1
    else:
        print("\n✅ Fully autonomous training completed successfully!")
        return 0

if __name__ == '__main__':
    sys.exit(main())