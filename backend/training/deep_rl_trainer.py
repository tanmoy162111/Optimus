"""
Deep RL Trainer
Main training loop for the Dueling Double DQN agent
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import numpy as np

# Add paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from .rl_training_config import RLTrainingConfig, TrainingTarget, load_training_config
from .experience_collector import ExperienceCollector, get_experience_collector
from .reward_calculator import RewardCalculator, get_reward_calculator
from .enhanced_state_encoder import get_state_encoder
from .deep_rl_agent import get_deep_rl_agent

logger = logging.getLogger(__name__)


class DeepRLTrainer:
    """
    Main trainer class for Deep RL agent.
    Orchestrates training across multiple targets.
    """
    
    def __init__(self, config: RLTrainingConfig = None):
        self.config = config or load_training_config()
        
        # Initialize components
        self.state_encoder = get_state_encoder()
        self.rl_agent = get_deep_rl_agent()
        self.experience_collector = get_experience_collector(self.config.experience_save_dir)
        self.reward_calculator = get_reward_calculator(self.config)
        
        # Training state
        self.total_steps = 0
        self.total_episodes = 0
        self.best_avg_reward = float('-inf')
        
        # Metrics tracking
        self.episode_rewards = []
        self.episode_findings = []
        self.episode_lengths = []
        
        # Create directories
        os.makedirs(self.config.model_save_dir, exist_ok=True)
        os.makedirs(self.config.log_dir, exist_ok=True)
        
        logger.info("[DeepRLTrainer] Initialized")
    
    def train(
        self,
        targets: List[TrainingTarget] = None,
        resume_from: str = None
    ) -> Dict:
        """
        Main training loop.
        
        Args:
            targets: List of targets to train on (uses config if None)
            resume_from: Path to checkpoint to resume from
            
        Returns:
            Training summary dictionary
        """
        targets = targets or self.config.get_enabled_targets()
        
        if not targets:
            logger.error("[DeepRLTrainer] No training targets configured!")
            return {"error": "No targets"}
        
        # Resume from checkpoint if specified
        if resume_from:
            self._load_checkpoint(resume_from)
        
        logger.info(f"[DeepRLTrainer] Starting training on {len(targets)} targets")
        logger.info(f"[DeepRLTrainer] Episodes per target: {self.config.episodes_per_target}")
        
        training_start = time.time()
        
        try:
            # Train on each target
            for target in targets:
                logger.info(f"\n{'='*60}")
                logger.info(f"[DeepRLTrainer] Training on: {target.name} ({target.url})")
                logger.info(f"{'='*60}")
                
                self._train_on_target(target)
                
                # Save checkpoint after each target
                self._save_checkpoint(f"checkpoint_after_{target.name.replace(' ', '_')}.pt")
            
            # Final save
            self._save_checkpoint("final_model.pt")
            self.experience_collector.save_experiences()
            
        except KeyboardInterrupt:
            logger.info("[DeepRLTrainer] Training interrupted by user")
            self._save_checkpoint("interrupted_checkpoint.pt")
            self.experience_collector.save_experiences("interrupted_experiences.json")
        
        except Exception as e:
            logger.error(f"[DeepRLTrainer] Training error: {e}")
            import traceback
            traceback.print_exc()
            self._save_checkpoint("error_checkpoint.pt")
        
        training_time = time.time() - training_start
        
        # Generate summary
        summary = self._generate_training_summary(training_time)
        self._save_training_report(summary)
        
        return summary
    
    def _train_on_target(self, target: TrainingTarget):
        """Train on a single target for configured number of episodes"""
        from inference.autonomous_agent import AutonomousPentestAgent
        from inference.tool_manager import ToolManager
        
        # Create agent for this target
        tool_manager = ToolManager(socketio=None)
        agent = AutonomousPentestAgent(socketio=None)
        
        for episode in range(self.config.episodes_per_target):
            episode_num = self.total_episodes + episode + 1
            
            logger.info(f"\n[DeepRLTrainer] Episode {episode_num} on {target.name}")
            
            # Run episode
            episode_result = self._run_training_episode(
                agent=agent,
                tool_manager=tool_manager,
                target=target,
                episode_num=episode_num
            )
            
            # Track metrics
            self.episode_rewards.append(episode_result["total_reward"])
            self.episode_findings.append(episode_result["findings_count"])
            self.episode_lengths.append(episode_result["steps"])
            
            # Log progress
            if episode % 5 == 0:
                avg_reward = np.mean(self.episode_rewards[-10:])
                avg_findings = np.mean(self.episode_findings[-10:])
                logger.info(f"[DeepRLTrainer] Episode {episode_num}: "
                           f"reward={episode_result['total_reward']:.2f}, "
                           f"findings={episode_result['findings_count']}, "
                           f"avg_reward_10={avg_reward:.2f}, "
                           f"avg_findings_10={avg_findings:.2f}")
            
            # Periodic evaluation
            if episode % self.config.eval_freq == 0:
                self._evaluate_agent(target)
            
            # Periodic save
            if self.total_steps % self.config.save_freq == 0:
                self._save_checkpoint(f"checkpoint_step_{self.total_steps}.pt")
        
        self.total_episodes += self.config.episodes_per_target
    
    def _run_training_episode(
        self,
        agent,
        tool_manager,
        target: TrainingTarget,
        episode_num: int
    ) -> Dict:
        """Run a single training episode"""
        
        # Initialize episode
        self.experience_collector.start_episode(target.url, episode_num)
        self.reward_calculator.reset_episode()
        
        # Initialize scan state
        scan_state = {
            "scan_id": f"train_{episode_num}_{int(time.time())}",
            "target": target.url,
            "phase": "reconnaissance",
            "findings": [],
            "tools_executed": [],
            "start_time": datetime.now().isoformat(),
            "config": {
                "max_time": self.config.max_time_per_episode,
            },
            "target_type": target.target_type,
            "technologies_detected": [],
        }
        
        episode_reward = 0.0
        step = 0
        done = False
        episode_start = time.time()
        
        # Encode initial state
        state = self.state_encoder.encode(scan_state)
        
        while not done and step < self.config.max_steps_per_episode:
            step += 1
            self.total_steps += 1
            
            # Check time limit
            elapsed = time.time() - episode_start
            if elapsed >= self.config.max_time_per_episode:
                done = True
                break
            
            # Get available tools
            available_tools = self._get_available_tools(scan_state)
            if not available_tools:
                # Force phase transition or end
                next_phase = self._get_next_phase(scan_state["phase"])
                if next_phase:
                    scan_state["phase"] = next_phase
                    continue
                else:
                    done = True
                    break
            
            # Select action using RL agent
            action_idx, tool_name, confidence = self.rl_agent.select_action(
                scan_state=scan_state,
                available_tools=available_tools,
                training=True
            )
            
            # Execute tool
            findings_before = len(scan_state["findings"])
            exec_start = time.time()
            
            try:
                result = tool_manager.execute_tool(
                    tool_name=tool_name,
                    target=target.url,
                    parameters={"phase": scan_state["phase"], "timeout": 300},
                    scan_id=scan_state["scan_id"],
                    phase=scan_state["phase"]
                )
            except Exception as e:
                logger.warning(f"[DeepRLTrainer] Tool execution failed: {e}")
                result = {"success": False, "error": str(e), "parsed_results": {}}
            
            exec_time = time.time() - exec_start
            
            # Update scan state with results
            self._update_scan_state(scan_state, result)
            findings_after = len(scan_state["findings"])
            
            # Calculate reward
            reward = self.reward_calculator.calculate_reward(
                tool_name=tool_name,
                result=result,
                scan_state=scan_state,
                execution_time=exec_time
            )
            episode_reward += reward
            
            # Encode next state
            next_state = self.state_encoder.encode(scan_state)
            
            # Check if episode should end
            done = self._check_episode_done(scan_state, elapsed)
            
            # Store experience
            self.experience_collector.add_experience(
                state=state,
                action=action_idx,
                reward=reward,
                next_state=next_state,
                done=done,
                tool_name=tool_name,
                phase=scan_state["phase"],
                target=target.url,
                findings_before=findings_before,
                findings_after=findings_after,
                execution_time=exec_time,
                success=result.get("success", False)
            )
            
            # Store in RL agent's replay buffer
            self.rl_agent.store_experience(
                state=state,
                action=action_idx,
                reward=reward,
                next_state=next_state,
                done=done
            )
            
            # Train if enough experiences
            if self.total_steps > self.config.warmup_steps:
                if self.total_steps % self.config.train_freq == 0:
                    loss = self.rl_agent.train_step()
                    if loss and self.total_steps % 100 == 0:
                        logger.debug(f"[DeepRLTrainer] Step {self.total_steps}, Loss: {loss:.4f}")
            
            # Update state
            state = next_state
            
            # Phase transition check
            next_phase = self._check_phase_transition(scan_state)
            if next_phase and next_phase != scan_state["phase"]:
                scan_state["phase"] = next_phase
                logger.info(f"[DeepRLTrainer] Phase transition to {next_phase}")
        
        # Episode end reward
        end_reward = self.reward_calculator.calculate_episode_end_reward(
            scan_state=scan_state,
            completed_normally=not done,
            total_time=time.time() - episode_start,
            max_time=self.config.max_time_per_episode
        )
        episode_reward += end_reward
        
        # End episode
        summary = self.experience_collector.end_episode(scan_state["findings"])
        summary["total_reward"] = episode_reward
        
        return summary
    
    def _get_available_tools(self, scan_state: Dict) -> List[str]:
        """Get available tools for current phase"""
        phase = scan_state.get("phase", "reconnaissance")
        tools_executed = [t["tool"] if isinstance(t, dict) else t 
                        for t in scan_state.get("tools_executed", [])]
        
        phase_tools = {
            "reconnaissance": ["whatweb", "nmap", "gobuster", "amass", "dnsenum", "fierce"],
            "scanning": ["nmap", "nikto", "nuclei", "gobuster", "ffuf", "dirb", "sslscan"],
            "exploitation": ["sqlmap", "dalfox", "commix", "xsser", "hydra"],
            "post_exploitation": ["linpeas", "winpeas"],
            "covering_tracks": [],
        }
        
        available = phase_tools.get(phase, [])
        # Filter out recently used tools (allow reuse after 3 others)
        recent = tools_executed[-3:] if len(tools_executed) > 3 else tools_executed
        
        return [t for t in available if t not in recent]
    
    def _get_next_phase(self, current_phase: str) -> Optional[str]:
        """Get next phase"""
        phases = ["reconnaissance", "scanning", "exploitation", "post_exploitation", "covering_tracks"]
        try:
            idx = phases.index(current_phase)
            if idx < len(phases) - 1:
                return phases[idx + 1]
        except ValueError:
            pass
        return None
    
    def _update_scan_state(self, scan_state: Dict, result: Dict):
        """Update scan state with tool result"""
        # Add tool to executed list
        tool_name = result.get("tool_name", "unknown")
        scan_state["tools_executed"].append({
            "tool": tool_name,
            "timestamp": datetime.now().isoformat(),
            "success": result.get("success", False)
        })
        
        # Add findings
        parsed = result.get("parsed_results", {})
        new_vulns = parsed.get("vulnerabilities", [])
        scan_state["findings"].extend(new_vulns)
        
        # Update technologies
        new_techs = parsed.get("technologies", [])
        existing_techs = scan_state.get("technologies_detected", [])
        scan_state["technologies_detected"] = list(set(existing_techs + new_techs))
    
    def _check_episode_done(self, scan_state: Dict, elapsed: float) -> bool:
        """Check if episode should end"""
        # Time limit
        if elapsed >= self.config.max_time_per_episode:
            return True
        
        # Phase completion
        if scan_state["phase"] == "covering_tracks":
            return True
        
        # Enough findings (early termination with success)
        if len(scan_state["findings"]) >= 20:
            return True
        
        return False
    
    def _check_phase_transition(self, scan_state: Dict) -> Optional[str]:
        """Check if phase should transition"""
        phase = scan_state["phase"]
        tools_executed = [t["tool"] if isinstance(t, dict) else t 
                        for t in scan_state.get("tools_executed", [])]
        findings = scan_state.get("findings", [])
        
        # Simple phase transition rules
        if phase == "reconnaissance":
            recon_tools = ["whatweb", "nmap", "gobuster", "amass"]
            if sum(1 for t in tools_executed if t in recon_tools) >= 3:
                return "scanning"
        
        elif phase == "scanning":
            scan_tools = ["nmap", "nikto", "nuclei", "gobuster"]
            if sum(1 for t in tools_executed if t in scan_tools) >= 4:
                return "exploitation"
        
        elif phase == "exploitation":
            if len(findings) >= 5 or len(tools_executed) >= 15:
                return "post_exploitation"
        
        elif phase == "post_exploitation":
            return "covering_tracks"
        
        return None
    
    def _evaluate_agent(self, target: TrainingTarget):
        """Evaluate agent performance"""
        if len(self.episode_rewards) < 10:
            return
        
        avg_reward = np.mean(self.episode_rewards[-10:])
        avg_findings = np.mean(self.episode_findings[-10:])
        
        logger.info(f"[DeepRLTrainer] Evaluation: avg_reward={avg_reward:.2f}, avg_findings={avg_findings:.2f}")
        
        # Save best model
        if avg_reward > self.best_avg_reward:
            self.best_avg_reward = avg_reward
            self._save_checkpoint("best_model.pt")
            logger.info(f"[DeepRLTrainer] New best model saved! avg_reward={avg_reward:.2f}")
    
    def _save_checkpoint(self, filename: str):
        """Save training checkpoint"""
        filepath = os.path.join(self.config.model_save_dir, filename)
        
        checkpoint = {
            "total_steps": self.total_steps,
            "total_episodes": self.total_episodes,
            "best_avg_reward": self.best_avg_reward,
            "episode_rewards": self.episode_rewards[-100:],
            "episode_findings": self.episode_findings[-100:],
            "config": self.config.to_dict(),
        }
        
        # Save RL agent weights
        self.rl_agent.save(filepath.replace(".pt", "_agent.pt"))
        
        # Save checkpoint metadata
        with open(filepath.replace(".pt", "_meta.json"), 'w') as f:
            json.dump(checkpoint, f, indent=2)
        
        logger.info(f"[DeepRLTrainer] Checkpoint saved: {filepath}")
    
    def _load_checkpoint(self, filepath: str):
        """Load training checkpoint"""
        meta_path = filepath.replace(".pt", "_meta.json")
        agent_path = filepath.replace(".pt", "_agent.pt")
        
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                checkpoint = json.load(f)
            
            self.total_steps = checkpoint.get("total_steps", 0)
            self.total_episodes = checkpoint.get("total_episodes", 0)
            self.best_avg_reward = checkpoint.get("best_avg_reward", float('-inf'))
            self.episode_rewards = checkpoint.get("episode_rewards", [])
            self.episode_findings = checkpoint.get("episode_findings", [])
        
        if os.path.exists(agent_path):
            self.rl_agent.load(agent_path)
        
        logger.info(f"[DeepRLTrainer] Loaded checkpoint from {filepath}")
    
    def _generate_training_summary(self, training_time: float) -> Dict:
        """Generate training summary"""
        return {
            "training_time_seconds": training_time,
            "total_episodes": self.total_episodes,
            "total_steps": self.total_steps,
            "best_avg_reward": self.best_avg_reward,
            "final_avg_reward": np.mean(self.episode_rewards[-10:]) if self.episode_rewards else 0,
            "final_avg_findings": np.mean(self.episode_findings[-10:]) if self.episode_findings else 0,
            "experience_stats": self.experience_collector.stats,
            "timestamp": datetime.now().isoformat(),
        }
    
    def _save_training_report(self, summary: Dict):
        """Save training report"""
        report_path = os.path.join(
            self.config.log_dir,
            f"training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"[DeepRLTrainer] Training report saved: {report_path}")


def main():
    """Main entry point for training"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train Deep RL Agent")
    parser.add_argument("--config", help="Path to training config file")
    parser.add_argument("--resume", help="Path to checkpoint to resume from")
    parser.add_argument("--episodes", type=int, help="Override episodes per target")
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load config
    config = load_training_config(args.config)
    if args.episodes:
        config.episodes_per_target = args.episodes
    
    # Create trainer and run
    trainer = DeepRLTrainer(config)
    summary = trainer.train(resume_from=args.resume)
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"Total Episodes: {summary['total_episodes']}")
    print(f"Total Steps: {summary['total_steps']}")
    print(f"Best Avg Reward: {summary['best_avg_reward']:.2f}")
    print(f"Final Avg Reward: {summary['final_avg_reward']:.2f}")
    print(f"Final Avg Findings: {summary['final_avg_findings']:.2f}")
    print(f"Training Time: {summary['training_time_seconds']/3600:.2f} hours")
    print("="*60)


if __name__ == "__main__":
    main()
