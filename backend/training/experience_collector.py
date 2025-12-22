"""
Experience Collector for Deep RL Training
Collects (state, action, reward, next_state, done) tuples during scans
"""

import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class Experience:
    """Single experience tuple for RL training"""
    state: List[float]  # 128-dim state vector
    action: int  # Tool index
    reward: float
    next_state: List[float]
    done: bool
    
    # Metadata for analysis
    tool_name: str
    phase: str
    target: str
    findings_before: int
    findings_after: int
    execution_time: float
    success: bool
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Experience':
        return cls(**data)


class ExperienceCollector:
    """
    Collects and manages experiences during training.
    Supports saving/loading for offline training.
    """
    
    def __init__(self, save_dir: str = "backend/data/training_experiences"):
        self.save_dir = save_dir
        self.experiences: List[Experience] = []
        self.episode_experiences: List[Experience] = []
        self.current_episode = 0
        self.total_steps = 0
        
        # Statistics
        self.stats = {
            "total_experiences": 0,
            "total_rewards": 0.0,
            "positive_rewards": 0,
            "negative_rewards": 0,
            "tools_used": {},
            "phases_visited": {},
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        
        os.makedirs(save_dir, exist_ok=True)
    
    def start_episode(self, target: str, episode_num: int):
        """Start a new training episode"""
        self.episode_experiences = []
        self.current_episode = episode_num
        self.episode_start_time = time.time()
        self.episode_target = target
        logger.info(f"[ExperienceCollector] Starting episode {episode_num} on {target}")
    
    def add_experience(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool,
        tool_name: str,
        phase: str,
        target: str,
        findings_before: int,
        findings_after: int,
        execution_time: float,
        success: bool
    ):
        """Add a single experience"""
        exp = Experience(
            state=state.tolist() if isinstance(state, np.ndarray) else state,
            action=action,
            reward=reward,
            next_state=next_state.tolist() if isinstance(next_state, np.ndarray) else next_state,
            done=done,
            tool_name=tool_name,
            phase=phase,
            target=target,
            findings_before=findings_before,
            findings_after=findings_after,
            execution_time=execution_time,
            success=success
        )
        
        self.experiences.append(exp)
        self.episode_experiences.append(exp)
        self.total_steps += 1
        
        # Update statistics
        self.stats["total_experiences"] += 1
        self.stats["total_rewards"] += reward
        if reward > 0:
            self.stats["positive_rewards"] += 1
        elif reward < 0:
            self.stats["negative_rewards"] += 1
        
        self.stats["tools_used"][tool_name] = self.stats["tools_used"].get(tool_name, 0) + 1
        self.stats["phases_visited"][phase] = self.stats["phases_visited"].get(phase, 0) + 1
        
        return exp
    
    def end_episode(self, final_findings: List[Dict]) -> Dict:
        """End current episode and return summary"""
        episode_time = time.time() - self.episode_start_time
        episode_reward = sum(exp.reward for exp in self.episode_experiences)
        
        # Count findings by severity
        for finding in final_findings:
            severity = finding.get("severity", 0)
            if severity >= 9.0:
                self.stats["findings_by_severity"]["critical"] += 1
            elif severity >= 7.0:
                self.stats["findings_by_severity"]["high"] += 1
            elif severity >= 4.0:
                self.stats["findings_by_severity"]["medium"] += 1
            else:
                self.stats["findings_by_severity"]["low"] += 1
        
        summary = {
            "episode": self.current_episode,
            "target": self.episode_target,
            "steps": len(self.episode_experiences),
            "total_reward": episode_reward,
            "time_seconds": episode_time,
            "findings_count": len(final_findings),
            "tools_used": list(set(exp.tool_name for exp in self.episode_experiences)),
        }
        
        logger.info(f"[ExperienceCollector] Episode {self.current_episode} complete: "
                   f"{summary['steps']} steps, reward={episode_reward:.2f}, "
                   f"findings={len(final_findings)}")
        
        return summary
    
    def save_experiences(self, filename: Optional[str] = None):
        """Save all experiences to file"""
        if not filename:
            filename = f"experiences_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.save_dir, filename)
        
        data = {
            "metadata": {
                "total_experiences": len(self.experiences),
                "collection_date": datetime.now().isoformat(),
                "stats": self.stats,
            },
            "experiences": [exp.to_dict() for exp in self.experiences]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"[ExperienceCollector] Saved {len(self.experiences)} experiences to {filepath}")
        return filepath
    
    def load_experiences(self, filepath: str) -> int:
        """Load experiences from file"""
        with open(filepath) as f:
            data = json.load(f)
        
        loaded = 0
        for exp_data in data.get("experiences", []):
            try:
                exp = Experience.from_dict(exp_data)
                self.experiences.append(exp)
                loaded += 1
            except Exception as e:
                logger.warning(f"Failed to load experience: {e}")
        
        logger.info(f"[ExperienceCollector] Loaded {loaded} experiences from {filepath}")
        return loaded
    
    def get_batch(self, batch_size: int) -> List[Experience]:
        """Get random batch of experiences"""
        if len(self.experiences) < batch_size:
            return self.experiences
        
        indices = np.random.choice(len(self.experiences), batch_size, replace=False)
        return [self.experiences[i] for i in indices]
    
    def get_all_as_arrays(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Get all experiences as numpy arrays for training"""
        if not self.experiences:
            return None, None, None, None, None
        
        states = np.array([exp.state for exp in self.experiences])
        actions = np.array([exp.action for exp in self.experiences])
        rewards = np.array([exp.reward for exp in self.experiences])
        next_states = np.array([exp.next_state for exp in self.experiences])
        dones = np.array([exp.done for exp in self.experiences])
        
        return states, actions, rewards, next_states, dones
    
    def clear(self):
        """Clear all experiences"""
        self.experiences = []
        self.episode_experiences = []
        self.total_steps = 0


# Singleton
_collector = None

def get_experience_collector(save_dir: str = None) -> ExperienceCollector:
    """Get singleton experience collector"""
    global _collector
    if _collector is None:
        _collector = ExperienceCollector(save_dir or "backend/data/training_experiences")
    return _collector
