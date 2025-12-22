"""
Deep RL Training Configuration
Defines training targets, hyperparameters, and settings
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import os


@dataclass
class TrainingTarget:
    """Configuration for a training target VM"""
    name: str
    host: str
    port: int = 80
    target_type: str = "web"  # web, network, api
    difficulty: str = "medium"  # easy, medium, hard
    known_vulns: List[str] = field(default_factory=list)
    enabled: bool = True
    
    @property
    def url(self) -> str:
        protocol = "https" if self.port == 443 else "http"
        if self.port in [80, 443]:
            return f"{protocol}://{self.host}"
        return f"{protocol}://{self.host}:{self.port}"


@dataclass 
class RLTrainingConfig:
    """Configuration for Deep RL training"""
    
    # Training targets
    targets: List[TrainingTarget] = field(default_factory=lambda: [
        TrainingTarget(
            name="OWASP Juice Shop",
            host="demo.owasp-juice.shop",
            port=443,
            target_type="web",
            difficulty="medium",
            known_vulns=["sql_injection", "xss", "broken_auth", "sensitive_data_exposure"],
            enabled=True
        ),
        TrainingTarget(
            name="Local VM Target 1",
            host="192.168.131.128",
            port=80,
            target_type="web",
            difficulty="medium",
            known_vulns=["multiple"],
            enabled=True
        ),
        TrainingTarget(
            name="Canonical Landscape",
            host="landscape.canonical.com",
            port=443,
            target_type="web",
            difficulty="hard",
            known_vulns=["to_discover"],
            enabled=True
        ),
    ])
    
    # Training hyperparameters
    episodes_per_target: int = 30  # Number of full scans per target
    max_steps_per_episode: int = 100  # Max tool executions per scan
    max_time_per_episode: int = 1800  # 30 minutes per scan
    
    # DQN hyperparameters
    learning_rate: float = 0.0001
    gamma: float = 0.99  # Discount factor
    batch_size: int = 64
    buffer_size: int = 100000
    target_update_freq: int = 1000  # Steps between target network updates
    
    # Prioritized Experience Replay
    use_per: bool = True
    per_alpha: float = 0.6  # Priority exponent
    per_beta_start: float = 0.4  # Importance sampling start
    per_beta_frames: int = 100000  # Frames to anneal beta
    
    # Exploration
    use_noisy_nets: bool = True  # Use noisy networks instead of epsilon-greedy
    epsilon_start: float = 1.0
    epsilon_end: float = 0.01
    epsilon_decay_steps: int = 50000
    
    # Training schedule
    warmup_steps: int = 1000  # Steps before training starts
    train_freq: int = 4  # Train every N steps
    save_freq: int = 5000  # Save model every N steps
    eval_freq: int = 10  # Evaluate every N episodes
    
    # Paths
    model_save_dir: str = "backend/data/models/deep_rl"
    experience_save_dir: str = "backend/data/training_experiences"
    log_dir: str = "backend/logs/rl_training"
    
    # Reward shaping
    rewards: Dict[str, float] = field(default_factory=lambda: {
        # Positive rewards
        "critical_vuln_found": 10.0,
        "high_vuln_found": 5.0,
        "medium_vuln_found": 2.0,
        "low_vuln_found": 0.5,
        "info_found": 0.1,
        "new_service_discovered": 1.0,
        "new_technology_detected": 0.5,
        "successful_exploit": 15.0,
        "shell_obtained": 20.0,
        "credentials_found": 8.0,
        
        # Negative rewards (penalties)
        "tool_failed": -0.5,
        "tool_timeout": -1.0,
        "repeated_tool": -2.0,  # Running same tool again
        "no_findings": -0.1,
        "phase_stall": -1.0,  # No progress in phase
        "scan_timeout": -5.0,
    })
    
    def get_enabled_targets(self) -> List[TrainingTarget]:
        """Get list of enabled training targets"""
        return [t for t in self.targets if t.enabled]
    
    def to_dict(self) -> Dict:
        """Convert config to dictionary"""
        return {
            "targets": [t.__dict__ for t in self.targets],
            "episodes_per_target": self.episodes_per_target,
            "max_steps_per_episode": self.max_steps_per_episode,
            "learning_rate": self.learning_rate,
            "gamma": self.gamma,
            "batch_size": self.batch_size,
            "use_per": self.use_per,
            "use_noisy_nets": self.use_noisy_nets,
        }


# Default configuration
DEFAULT_TRAINING_CONFIG = RLTrainingConfig()


def load_training_config(config_path: Optional[str] = None) -> RLTrainingConfig:
    """Load training configuration from file or return default"""
    if config_path and os.path.exists(config_path):
        import json
        with open(config_path) as f:
            data = json.load(f)
        # Parse and return config
        config = RLTrainingConfig()
        # Update with loaded values
        for key, value in data.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return config
    return DEFAULT_TRAINING_CONFIG
