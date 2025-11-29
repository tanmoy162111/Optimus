"""
Training Session Manager - Orchestrates agent learning from live VM execution

Features:
1. Manages training sessions with multiple target VMs
2. Coordinates agent execution, tool selection, and learning
3. Collects comprehensive training data
4. Implements feedback loops for continuous improvement
5. Tracks performance metrics across sessions
"""
from typing import List, Dict, Any
from datetime import datetime
import logging
import json
from pathlib import Path

# Add backend to path
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from inference.autonomous_agent import AutonomousPentestAgent
from inference.learning_module import RealTimeLearningModule
from inference.strategy_selector import StrategySelector

logger = logging.getLogger(__name__)

class TrainingSessionManager:
    """
    Manages end-to-end training sessions for the autonomous agent

    Responsibilities:
    - Initialize training environment
    - Execute scans against practice VMs
    - Collect execution data (tool outputs, timings, findings)
    - Feed results back to learning modules
    - Update models based on performance
    - Generate training reports
    """

    def __init__(self, target_vms: List[str], session_config: Dict):
        """
        Initialize training session

        Args:
            target_vms: List of practice VM URLs/IPs
            session_config: Configuration including:
                - num_episodes: Number of training episodes
                - tools_available: List of tools to practice
                - learning_mode: 'exploration' or 'exploitation'
                - feedback_frequency: How often to update models
                - metrics_to_track: Performance metrics
        """
        self.target_vms = target_vms
        self.session_config = session_config
        self.num_episodes = session_config.get('num_episodes', 10)
        self.learning_mode = session_config.get('learning_mode', 'exploration')
        self.feedback_frequency = session_config.get('feedback_frequency', 5)
        
        # Initialize components
        self.agent = AutonomousPentestAgent()
        self.learning_module = RealTimeLearningModule()
        self.strategy_selector = StrategySelector()
        
        # Training state
        self.episode_history = []
        self.current_episode = 0
        
        # Setup output directory
        self.output_dir = Path(session_config.get('output_dir', 'training_output'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"TrainingSessionManager initialized with {len(target_vms)} targets")
        logger.info(f"Training for {self.num_episodes} episodes")
        logger.info(f"Learning mode: {self.learning_mode}")

    def run_training_session(self) -> Dict[str, Any]:
        """
        Execute complete training session

        Flow:
        1. For each episode:
            a. Select target VM
            b. Initialize scan state
            c. Agent selects tools based on current strategy
            d. Execute tools via ToolManager
            e. Parse outputs and extract findings
            f. Calculate rewards based on results
            g. Update agent's learning modules
            h. Adjust strategy if needed
        2. After N episodes, retrain models
        3. Generate comprehensive report

        Returns:
            Session results with metrics and learned patterns
        """
        logger.info("="*80)
        logger.info("TRAINING SESSION START")
        logger.info("="*80)
        
        training_start = datetime.now()
        
        try:
            # Run all episodes
            for episode_num in range(self.num_episodes):
                self.current_episode = episode_num
                target = self.target_vms[episode_num % len(self.target_vms)]
                
                logger.info(f"\n[Episode {episode_num + 1}/{self.num_episodes}] Target: {target}")
                
                # Run single episode
                episode_result = self.execute_training_episode(target, episode_num)
                
                # Store episode result
                self.episode_history.append(episode_result)
                
                # Update learning modules periodically
                if (episode_num + 1) % self.feedback_frequency == 0:
                    self.update_agent_learning(episode_result)
                    
                # Save checkpoint periodically
                if (episode_num + 1) % 10 == 0:
                    self._save_checkpoint()
            
            # Generate final report
            training_end = datetime.now()
            duration = (training_end - training_start).total_seconds()
            
            results = {
                'training_id': f"training_{training_start.strftime('%Y%m%d_%H%M%S')}",
                'duration_seconds': duration,
                'total_episodes': self.num_episodes,
                'targets_trained': len(self.target_vms),
                'episode_history': self.episode_history,
                'final_strategy_report': self.strategy_selector.get_strategy_report()
            }
            
            # Save results
            self._save_training_results(results)
            
            # Print summary
            self._print_training_summary(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Training session failed: {e}")
            import traceback
            traceback.print_exc()
            return {'error': str(e)}

    def execute_training_episode(self, target: str, episode_num: int) -> Dict:
        """
        Single training episode against one target

        Steps:
        1. Initialize episode state
        2. Agent reconnaissance phase
        3. Agent scanning phase
        4. Agent exploitation phase
        5. Collect all data
        6. Calculate episode rewards
        7. Update learning modules

        Returns:
            Episode results with execution data
        """
        episode_start = datetime.now()
        
        # Configure scan based on mode
        scan_config = {
            'max_time': 1800,  # 30 minutes per episode
            'learning_mode': True,
            'aggressive': self.learning_mode == 'exploration'
        }
        
        try:
            # Run agent scan
            logger.info(f"  [Episode] Starting scan...")
            scan_result = self.agent.run_autonomous_scan(target, scan_config)
            
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
                'timestamp': episode_start.isoformat()
            }
            
            logger.info(f"  [Episode] Completed: {len(episode_data['findings'])} findings, "
                       f"{len(episode_data['tools_used'])} tools, "
                       f"{duration:.1f}s")
            
            return episode_data
            
        except Exception as e:
            logger.error(f"  [Episode] Failed: {e}")
            episode_data = {
                'episode_num': episode_num,
                'target': target,
                'success': False,
                'error': str(e),
                'timestamp': episode_start.isoformat()
            }
            return episode_data

    def collect_execution_data(self, tool_result: Dict) -> Dict:
        """
        Extract comprehensive data from tool execution

        Data collected:
        - Tool name and parameters used
        - Execution time
        - Success/failure
        - Vulnerabilities found
        - Parse quality
        - Resource usage

        Returns:
            Structured execution data for learning
        """
        # Extract metrics from tool execution result
        execution_data = {
            'tool_name': tool_result.get('tool_name', 'unknown'),
            'execution_time': tool_result.get('execution_time', 0),
            'success': tool_result.get('success', False),
            'exit_code': tool_result.get('exit_code', -1),
            'findings_count': len(tool_result.get('parsed_results', {}).get('vulnerabilities', [])),
            'stdout_length': len(tool_result.get('stdout', '')),
            'stderr_length': len(tool_result.get('stderr', '')),
            'parameters_used': tool_result.get('parameters', {}),
            'phase': tool_result.get('phase', 'unknown')
        }
        
        return execution_data

    def update_agent_learning(self, episode_data: Dict):
        """
        Feed episode results to learning modules

        Updates:
        1. RealTimeLearningModule - tool effectiveness
        2. StrategySelector - strategy performance
        3. ToolSelector - recommendation quality
        4. RL Agent - state-action-reward

        Args:
            episode_data: Complete episode execution data
        """
        # Update strategy selector with episode results
        if episode_data.get('success'):
            scan_results = {
                'findings_count': len(episode_data.get('findings', [])),
                'tools_used': episode_data.get('tools_used', []),
                'success_rate': 1.0,  # Episode succeeded
                'coverage': episode_data.get('coverage', 0.0)
            }
            strategy = episode_data.get('strategy_used', 'adaptive')
            self.strategy_selector.update_strategy_performance(strategy, scan_results)
        
        # Update learning module for each tool used
        tools_used = episode_data.get('tools_used', [])
        findings = episode_data.get('findings', [])
        
        for tool_entry in tools_used:
            if isinstance(tool_entry, dict):
                tool_name = tool_entry.get('tool')
                result = {
                    'success': tool_entry.get('success', False),
                    'execution_time': tool_entry.get('execution_time', 0),
                    'parsed_results': {
                        'vulnerabilities': [f for f in findings 
                                          if f.get('tool') == tool_name]
                    }
                }
                context = {
                    'phase': tool_entry.get('phase', 'unknown'),
                    'target_type': 'web'
                }
                self.learning_module.learn_from_execution(tool_name, result, context)

    def _save_training_results(self, results: Dict):
        """Save comprehensive training results"""
        output_file = self.output_dir / f"training_results_{results['training_id']}.json"
        
        # Convert non-serializable objects to strings
        serializable_results = self._make_serializable(results)
        
        with open(output_file, 'w') as f:
            json.dump(serializable_results, f, indent=2, default=str)
        
        logger.info(f"\n[Save] Training results saved to {output_file}")

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
        
        logger.info(f"[Checkpoint] Saved to {checkpoint_file}")
        return checkpoint

    def _make_serializable(self, obj):
        """Convert non-serializable objects to serializable formats"""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, (datetime, Path)):
            return str(obj)
        else:
            return obj

    def _print_training_summary(self, results: Dict):
        """Print comprehensive training summary"""
        logger.info("\n" + "="*80)
        logger.info("TRAINING SESSION COMPLETE")
        logger.info("="*80)
        
        logger.info(f"\nTraining ID: {results['training_id']}")
        logger.info(f"Duration: {results['duration_seconds']:.1f} seconds")
        logger.info(f"Total Episodes: {results['total_episodes']}")
        logger.info(f"Targets Trained: {results['targets_trained']}")
        
        # Episode statistics
        successful_episodes = [e for e in results.get('episode_history', []) if e.get('success')]
        failed_episodes = [e for e in results.get('episode_history', []) if not e.get('success')]
        
        logger.info(f"\nEpisodes:")
        logger.info(f"  Successful: {len(successful_episodes)}")
        logger.info(f"  Failed: {len(failed_episodes)}")
        
        if successful_episodes:
            total_findings = sum(len(e.get('findings', [])) for e in successful_episodes)
            avg_findings = total_findings / len(successful_episodes)
            logger.info(f"  Average Findings per Episode: {avg_findings:.2f}")
            
            total_tools = sum(len(e.get('tools_used', [])) for e in successful_episodes)
            avg_tools = total_tools / len(successful_episodes)
            logger.info(f"  Average Tools per Episode: {avg_tools:.2f}")
        
        # Strategy performance
        strategy_report = results.get('final_strategy_report', {})
        if strategy_report.get('best_overall'):
            logger.info(f"\nBest Overall Strategy: {strategy_report['best_overall']}")
        
        logger.info("\n" + "="*80)