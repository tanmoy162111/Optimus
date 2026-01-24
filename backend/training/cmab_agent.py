"""
Contextual Multi-Armed Bandit Agent for Optimus
Implements Thompson Sampling + UCB for CPU-efficient tool selection

This replaces the TensorFlow-based Deep RL agent with a lightweight,
interpretable, and crash-tolerant online learning system.

Key Features:
- No TensorFlow/GPU dependencies (CPU-only, numpy-based)
- Thompson Sampling with Beta distributions
- Optional UCB (Upper Confidence Bound) strategy
- Rich contextual feature extraction
- Incremental persistence (JSON checkpoints)
- Fail-soft behavior with heuristic fallback
- Hot-swappable with future Deep RL

Architecture:
- ActionPolicy interface for strategy abstraction
- ContextExtractor for rich feature engineering
- BanditPolicy for Thompson Sampling / UCB
- RewardNormalizer for stable learning
"""

import os
import json
import logging
import numpy as np
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CMABConfig:
    """Configuration for CMAB Agent"""
    strategy: str = "thompson"  # "thompson" or "ucb"
    alpha_prior: float = 1.0
    beta_prior: float = 1.0
    ucb_exploration: float = 2.0
    reward_min: float = -5.0
    reward_max: float = 10.0
    num_context_bins: int = 10
    checkpoint_frequency: int = 10
    model_dir: str = None
    learning_rate: float = 0.1
    decay_factor: float = 0.99
    min_exploration_prob: float = 0.05
    exploration_decay: float = 0.995
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'CMABConfig':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ABSTRACTION (ActionPolicy Interface)
# ═══════════════════════════════════════════════════════════════════════════════

class ActionPolicy(ABC):
    """Abstract base class for action selection policies."""
    
    @abstractmethod
    def select_tool(self, context: Dict[str, Any], available_tools: List[str], 
                    training: bool = True) -> Tuple[int, str, float]:
        """Select a tool based on current context."""
        pass
    
    @abstractmethod
    def update(self, context: Dict[str, Any], action: int, tool_name: str,
               reward: float, next_context: Dict[str, Any] = None) -> Dict[str, float]:
        """Update policy based on observed reward."""
        pass
    
    @abstractmethod
    def save_state(self, path: str = None) -> bool:
        """Save policy state to disk."""
        pass
    
    @abstractmethod
    def load_state(self, path: str = None) -> bool:
        """Load policy state from disk."""
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# RICH CONTEXT EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

class RichContextExtractor:
    """
    Extracts rich contextual features from scan state for CMAB decisions.
    Features are designed to be interpretable and capture key decision factors.
    """
    
    PHASES = ['reconnaissance', 'enumeration', 'vulnerability_analysis', 
              'exploitation', 'post_exploitation']
    
    TARGET_TYPES = ['web', 'api', 'network', 'database', 'unknown']
    
    def __init__(self):
        self.feature_names = self._build_feature_names()
        logger.info(f"[RichContextExtractor] Initialized with {len(self.feature_names)} features")
    
    def _build_feature_names(self) -> List[str]:
        """Build list of feature names for interpretability."""
        names = []
        names.extend([f"phase_{p}" for p in self.PHASES])
        names.extend([f"target_{t}" for t in self.TARGET_TYPES])
        names.extend(['tools_executed_count', 'unique_tools_ratio', 'findings_count',
                      'critical_findings', 'high_findings', 'medium_findings',
                      'services_discovered', 'has_web_service', 'has_ssh', 'has_database',
                      'time_elapsed_ratio', 'stall_indicator', 'discovery_rate',
                      'phase_progress', 'exploitation_ready', 'has_credentials'])
        return names
    
    def extract(self, scan_state: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract rich context features from scan state.
        Returns dictionary of named features for interpretability.
        """
        features = {}
        
        # Phase encoding (one-hot)
        current_phase = scan_state.get('phase', 'reconnaissance').lower()
        for phase in self.PHASES:
            features[f"phase_{phase}"] = 1.0 if current_phase == phase else 0.0
        
        # Target type encoding
        target_type = self._detect_target_type(scan_state)
        for t in self.TARGET_TYPES:
            features[f"target_{t}"] = 1.0 if target_type == t else 0.0
        
        # Tool execution history
        tools_executed = scan_state.get('tools_executed', [])
        tool_names = [t.get('tool', t) if isinstance(t, dict) else str(t) 
                      for t in tools_executed]
        features['tools_executed_count'] = min(len(tool_names) / 30.0, 1.0)
        features['unique_tools_ratio'] = (len(set(tool_names)) / max(len(tool_names), 1))
        
        # Findings analysis
        findings = scan_state.get('findings', [])
        features['findings_count'] = min(len(findings) / 20.0, 1.0)
        
        severity_counts = self._count_severities(findings)
        features['critical_findings'] = min(severity_counts['critical'] / 5.0, 1.0)
        features['high_findings'] = min(severity_counts['high'] / 5.0, 1.0)
        features['medium_findings'] = min(severity_counts['medium'] / 10.0, 1.0)
        
        # Service discovery
        services = scan_state.get('discovered_services', scan_state.get('services', []))
        features['services_discovered'] = min(len(services) / 10.0, 1.0)
        
        service_names = ' '.join(str(s.get('service', s) if isinstance(s, dict) else s) 
                                 for s in services).lower()
        features['has_web_service'] = 1.0 if any(w in service_names for w in ['http', 'web', 'apache', 'nginx']) else 0.0
        features['has_ssh'] = 1.0 if 'ssh' in service_names else 0.0
        features['has_database'] = 1.0 if any(d in service_names for d in ['mysql', 'postgres', 'mssql', 'mongo']) else 0.0
        
        # Progress metrics
        time_elapsed = scan_state.get('time_elapsed', 0)
        time_budget = scan_state.get('config', {}).get('max_time', 3600)
        features['time_elapsed_ratio'] = min(time_elapsed / max(time_budget, 1), 1.0)
        
        # Stall detection
        last_finding_iter = scan_state.get('last_finding_iteration', 0)
        current_iter = len(tools_executed)
        stall_count = current_iter - last_finding_iter
        features['stall_indicator'] = min(stall_count / 10.0, 1.0)
        
        # Discovery rate
        features['discovery_rate'] = (len(findings) / max(len(tools_executed), 1))
        
        # Phase progress
        phase_idx = self.PHASES.index(current_phase) if current_phase in self.PHASES else 0
        features['phase_progress'] = phase_idx / (len(self.PHASES) - 1)
        
        # Exploitation readiness
        exploitable = any(f.get('exploitable', False) for f in findings)
        high_severity = severity_counts['critical'] > 0 or severity_counts['high'] > 0
        features['exploitation_ready'] = 1.0 if (exploitable or high_severity) else 0.0
        
        # Credential discovery
        has_creds = any('credential' in str(f).lower() or 'password' in str(f).lower() 
                       for f in findings)
        features['has_credentials'] = 1.0 if has_creds else 0.0
        
        return features
    
    def _detect_target_type(self, scan_state: Dict) -> str:
        """Detect target type from scan state."""
        services = scan_state.get('discovered_services', [])
        service_str = ' '.join(str(s) for s in services).lower()
        
        if any(w in service_str for w in ['http', 'web', 'apache', 'nginx', '80', '443']):
            if 'api' in service_str or scan_state.get('target_profile', {}).get('is_api'):
                return 'api'
            return 'web'
        if any(d in service_str for d in ['mysql', 'postgres', 'mssql', 'mongo', '3306', '5432']):
            return 'database'
        if services:
            return 'network'
        return 'unknown'
    
    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in findings:
            sev = f.get('severity', 0)
            if isinstance(sev, str):
                sev_map = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2}
                sev = sev_map.get(sev.lower(), 5)
            try:
                sev = float(sev)
            except:
                sev = 5.0
            
            if sev >= 9:
                counts['critical'] += 1
            elif sev >= 7:
                counts['high'] += 1
            elif sev >= 4:
                counts['medium'] += 1
            else:
                counts['low'] += 1
        return counts
    
    def get_context_key(self, features: Dict[str, float]) -> str:
        """Generate a hashable context key for table lookup."""
        phase = next((p for p in self.PHASES if features.get(f"phase_{p}", 0) > 0.5), 'unknown')
        target = next((t for t in self.TARGET_TYPES if features.get(f"target_{t}", 0) > 0.5), 'unknown')
        findings_level = 'high' if features.get('critical_findings', 0) > 0 else \
                        'medium' if features.get('high_findings', 0) > 0 else 'low'
        progress = 'early' if features.get('time_elapsed_ratio', 0) < 0.3 else \
                   'mid' if features.get('time_elapsed_ratio', 0) < 0.7 else 'late'
        
        return f"{phase}_{target}_{findings_level}_{progress}"


# ═══════════════════════════════════════════════════════════════════════════════
# REWARD NORMALIZER
# ═══════════════════════════════════════════════════════════════════════════════

class RewardNormalizer:
    """Normalizes rewards to [0, 1] range for Beta distribution updates."""
    
    def __init__(self, min_reward: float = -5.0, max_reward: float = 10.0):
        self.min_reward = min_reward
        self.max_reward = max_reward
    
    def normalize(self, reward: float) -> float:
        """Normalize reward to [0, 1] range."""
        clamped = max(self.min_reward, min(self.max_reward, reward))
        return (clamped - self.min_reward) / (self.max_reward - self.min_reward)
    
    def denormalize(self, normalized: float) -> float:
        """Convert normalized value back to reward scale."""
        return normalized * (self.max_reward - self.min_reward) + self.min_reward


# ═══════════════════════════════════════════════════════════════════════════════
# THOMPSON SAMPLING POLICY
# ═══════════════════════════════════════════════════════════════════════════════

class ThompsonSamplingPolicy(ActionPolicy):
    """
    Thompson Sampling policy using Beta distributions.
    Maintains separate Beta(alpha, beta) for each (context, action) pair.
    """
    
    def __init__(self, config: CMABConfig, tool_list: List[str]):
        self.config = config
        self.tool_list = tool_list
        self.num_actions = len(tool_list)
        self.tool_index = {tool: idx for idx, tool in enumerate(tool_list)}
        
        # Beta distribution parameters: {context_key: {tool: (alpha, beta)}}
        self.beta_params: Dict[str, Dict[str, Tuple[float, float]]] = defaultdict(
            lambda: {tool: (config.alpha_prior, config.beta_prior) for tool in tool_list}
        )
        
        # Statistics tracking
        self.total_updates = 0
        self.tool_selections = defaultdict(int)
        self.tool_rewards = defaultdict(list)
        
        self.context_extractor = RichContextExtractor()
        self.reward_normalizer = RewardNormalizer(config.reward_min, config.reward_max)
        
        logger.info(f"[ThompsonSampling] Initialized with {self.num_actions} actions")
    
    def select_tool(self, context: Dict[str, Any], available_tools: List[str],
                    training: bool = True) -> Tuple[int, str, float]:
        """Select tool using Thompson Sampling."""
        try:
            features = self.context_extractor.extract(context)
            context_key = self.context_extractor.get_context_key(features)
            
            # Get Beta parameters for this context
            params = self.beta_params[context_key]
            
            # Sample from Beta distributions
            samples = {}
            for tool in available_tools:
                if tool in params:
                    alpha, beta = params[tool]
                    samples[tool] = np.random.beta(alpha, beta)
                else:
                    samples[tool] = np.random.beta(self.config.alpha_prior, self.config.beta_prior)
            
            # Select tool with highest sample (exploration via sampling)
            if not samples:
                tool_name = available_tools[0] if available_tools else self.tool_list[0]
            else:
                tool_name = max(samples, key=samples.get)
            
            action_idx = self.tool_index.get(tool_name, 0)
            confidence = samples.get(tool_name, 0.5)
            
            self.tool_selections[tool_name] += 1
            
            logger.debug(f"[ThompsonSampling] Selected {tool_name} (ctx={context_key}, conf={confidence:.3f})")
            
            return action_idx, tool_name, float(confidence)
            
        except Exception as e:
            logger.error(f"[ThompsonSampling] Selection error: {e}, using fallback")
            tool_name = available_tools[0] if available_tools else self.tool_list[0]
            return self.tool_index.get(tool_name, 0), tool_name, 0.5
    
    def update(self, context: Dict[str, Any], action: int, tool_name: str,
               reward: float, next_context: Dict[str, Any] = None) -> Dict[str, float]:
        """Update Beta parameters based on observed reward."""
        try:
            features = self.context_extractor.extract(context)
            context_key = self.context_extractor.get_context_key(features)
            
            # Normalize reward to [0, 1]
            normalized_reward = self.reward_normalizer.normalize(reward)
            
            # Get current parameters
            alpha, beta = self.beta_params[context_key].get(
                tool_name, (self.config.alpha_prior, self.config.beta_prior)
            )
            
            # Update Beta distribution (Bayesian update)
            # Treat normalized reward as probability of success
            new_alpha = alpha + normalized_reward
            new_beta = beta + (1 - normalized_reward)
            
            # Apply decay to prevent parameter explosion
            decay = self.config.decay_factor
            new_alpha = self.config.alpha_prior + (new_alpha - self.config.alpha_prior) * decay
            new_beta = self.config.beta_prior + (new_beta - self.config.beta_prior) * decay
            
            self.beta_params[context_key][tool_name] = (new_alpha, new_beta)
            
            # Track statistics
            self.total_updates += 1
            self.tool_rewards[tool_name].append(reward)
            
            # Periodic checkpoint
            if self.total_updates % self.config.checkpoint_frequency == 0:
                self.save_state()
            
            metrics = {
                'alpha': new_alpha,
                'beta': new_beta,
                'expected_value': new_alpha / (new_alpha + new_beta),
                'normalized_reward': normalized_reward,
                'total_updates': self.total_updates
            }
            
            logger.debug(f"[ThompsonSampling] Updated {tool_name}: α={new_alpha:.2f}, β={new_beta:.2f}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"[ThompsonSampling] Update error: {e}")
            return {'error': str(e)}
    
    def save_state(self, path: str = None) -> bool:
        """Save policy state to JSON."""
        try:
            if path is None:
                model_dir = Path(self.config.model_dir or 
                               Path(__file__).parent.parent / 'data' / 'models' / 'cmab')
                model_dir.mkdir(parents=True, exist_ok=True)
                path = model_dir / 'thompson_state.json'
            
            state = {
                'beta_params': {ctx: dict(params) for ctx, params in self.beta_params.items()},
                'total_updates': self.total_updates,
                'tool_selections': dict(self.tool_selections),
                'config': self.config.to_dict(),
                'saved_at': datetime.now().isoformat()
            }
            
            with open(path, 'w') as f:
                json.dump(state, f, indent=2)
            
            logger.info(f"[ThompsonSampling] Saved state to {path}")
            return True
            
        except Exception as e:
            logger.error(f"[ThompsonSampling] Save error: {e}")
            return False
    
    def load_state(self, path: str = None) -> bool:
        """Load policy state from JSON."""
        try:
            if path is None:
                model_dir = Path(self.config.model_dir or 
                               Path(__file__).parent.parent / 'data' / 'models' / 'cmab')
                path = model_dir / 'thompson_state.json'
            
            if not Path(path).exists():
                logger.warning(f"[ThompsonSampling] No state file at {path}")
                return False
            
            with open(path, 'r') as f:
                state = json.load(f)
            
            # Restore Beta parameters
            for ctx, params in state.get('beta_params', {}).items():
                self.beta_params[ctx] = {tool: tuple(p) for tool, p in params.items()}
            
            self.total_updates = state.get('total_updates', 0)
            self.tool_selections = defaultdict(int, state.get('tool_selections', {}))
            
            logger.info(f"[ThompsonSampling] Loaded state from {path} ({self.total_updates} updates)")
            return True
            
        except Exception as e:
            logger.error(f"[ThompsonSampling] Load error: {e}")
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# UCB POLICY
# ═══════════════════════════════════════════════════════════════════════════════

class UCBPolicy(ActionPolicy):
    """
    Upper Confidence Bound (UCB) policy.
    Balances exploration-exploitation using confidence intervals.
    """
    
    def __init__(self, config: CMABConfig, tool_list: List[str]):
        self.config = config
        self.tool_list = tool_list
        self.num_actions = len(tool_list)
        self.tool_index = {tool: idx for idx, tool in enumerate(tool_list)}
        
        # UCB statistics: {context_key: {tool: {'count': n, 'sum': total_reward}}}
        self.stats: Dict[str, Dict[str, Dict[str, float]]] = defaultdict(
            lambda: {tool: {'count': 0, 'sum': 0.0} for tool in tool_list}
        )
        
        self.total_pulls = 0
        self.context_extractor = RichContextExtractor()
        self.reward_normalizer = RewardNormalizer(config.reward_min, config.reward_max)
        
        logger.info(f"[UCBPolicy] Initialized with {self.num_actions} actions, c={config.ucb_exploration}")
    
    def select_tool(self, context: Dict[str, Any], available_tools: List[str],
                    training: bool = True) -> Tuple[int, str, float]:
        """Select tool using UCB."""
        try:
            features = self.context_extractor.extract(context)
            context_key = self.context_extractor.get_context_key(features)
            
            stats = self.stats[context_key]
            self.total_pulls += 1
            
            ucb_values = {}
            for tool in available_tools:
                tool_stats = stats.get(tool, {'count': 0, 'sum': 0.0})
                n = tool_stats['count']
                
                if n == 0:
                    ucb_values[tool] = float('inf')  # Explore unvisited
                else:
                    mean = tool_stats['sum'] / n
                    exploration_bonus = self.config.ucb_exploration * np.sqrt(
                        np.log(self.total_pulls) / n
                    )
                    ucb_values[tool] = mean + exploration_bonus
            
            tool_name = max(ucb_values, key=ucb_values.get)
            action_idx = self.tool_index.get(tool_name, 0)
            
            # Confidence based on empirical mean
            tool_stats = stats.get(tool_name, {'count': 0, 'sum': 0.0})
            confidence = tool_stats['sum'] / max(tool_stats['count'], 1)
            
            logger.debug(f"[UCB] Selected {tool_name} (ucb={ucb_values[tool_name]:.3f})")
            
            return action_idx, tool_name, float(confidence)
            
        except Exception as e:
            logger.error(f"[UCB] Selection error: {e}")
            tool_name = available_tools[0] if available_tools else self.tool_list[0]
            return self.tool_index.get(tool_name, 0), tool_name, 0.5
    
    def update(self, context: Dict[str, Any], action: int, tool_name: str,
               reward: float, next_context: Dict[str, Any] = None) -> Dict[str, float]:
        """Update UCB statistics."""
        try:
            features = self.context_extractor.extract(context)
            context_key = self.context_extractor.get_context_key(features)
            
            normalized_reward = self.reward_normalizer.normalize(reward)
            
            if tool_name not in self.stats[context_key]:
                self.stats[context_key][tool_name] = {'count': 0, 'sum': 0.0}
            
            self.stats[context_key][tool_name]['count'] += 1
            self.stats[context_key][tool_name]['sum'] += normalized_reward
            
            n = self.stats[context_key][tool_name]['count']
            mean = self.stats[context_key][tool_name]['sum'] / n
            
            return {
                'count': n,
                'mean_reward': mean,
                'normalized_reward': normalized_reward,
                'total_pulls': self.total_pulls
            }
            
        except Exception as e:
            logger.error(f"[UCB] Update error: {e}")
            return {'error': str(e)}
    
    def save_state(self, path: str = None) -> bool:
        """Save UCB state."""
        try:
            if path is None:
                model_dir = Path(self.config.model_dir or 
                               Path(__file__).parent.parent / 'data' / 'models' / 'cmab')
                model_dir.mkdir(parents=True, exist_ok=True)
                path = model_dir / 'ucb_state.json'
            
            state = {
                'stats': {ctx: dict(s) for ctx, s in self.stats.items()},
                'total_pulls': self.total_pulls,
                'config': self.config.to_dict(),
                'saved_at': datetime.now().isoformat()
            }
            
            with open(path, 'w') as f:
                json.dump(state, f, indent=2)
            
            logger.info(f"[UCB] Saved state to {path}")
            return True
        except Exception as e:
            logger.error(f"[UCB] Save error: {e}")
            return False
    
    def load_state(self, path: str = None) -> bool:
        """Load UCB state."""
        try:
            if path is None:
                model_dir = Path(self.config.model_dir or 
                               Path(__file__).parent.parent / 'data' / 'models' / 'cmab')
                path = model_dir / 'ucb_state.json'
            
            if not Path(path).exists():
                return False
            
            with open(path, 'r') as f:
                state = json.load(f)
            
            for ctx, s in state.get('stats', {}).items():
                self.stats[ctx] = dict(s)
            
            self.total_pulls = state.get('total_pulls', 0)
            logger.info(f"[UCB] Loaded state ({self.total_pulls} pulls)")
            return True
        except Exception as e:
            logger.error(f"[UCB] Load error: {e}")
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# CMAB AGENT (Main Class - Drop-in replacement for DeepRLAgent)
# ═══════════════════════════════════════════════════════════════════════════════

class CMABAgent:
    """
    Contextual Multi-Armed Bandit Agent.
    Drop-in replacement for DeepRLAgent with compatible interface.
    """
    
    DEFAULT_TOOLS = [
        'nmap', 'nikto', 'nuclei', 'sqlmap', 'dalfox', 'commix',
        'gobuster', 'ffuf', 'dirb', 'wpscan', 'hydra', 'metasploit',
        'burpsuite', 'sublist3r', 'amass', 'whatweb', 'fierce',
        'dnsenum', 'sslscan', 'enum4linux', 'xsser', 'testssl',
        'wfuzz', 'arjun', 'paramspider', 'waybackurls', 'gau',
        'httpx', 'katana', 'subfinder', 'masscan', 'nessus',
        'openvas', 'zap', 'arachni', 'curl', 'wget'
    ]
    
    def __init__(
        self,
        num_actions: int = 35,
        state_dim: int = 128,  # Kept for interface compatibility
        strategy: str = "thompson",
        learning_rate: float = 0.1,
        model_dir: str = None,
        **kwargs  # Accept additional args for compatibility
    ):
        """
        Initialize CMAB Agent.
        
        Args:
            num_actions: Number of tools/actions
            state_dim: State dimension (for interface compatibility)
            strategy: "thompson" or "ucb"
            learning_rate: Learning rate for updates
            model_dir: Directory for model persistence
        """
        self.num_actions = num_actions
        self.state_dim = state_dim
        self.tool_list = self.DEFAULT_TOOLS[:num_actions]
        
        # Create configuration
        self.config = CMABConfig(
            strategy=strategy,
            learning_rate=learning_rate,
            model_dir=model_dir or str(Path(__file__).parent.parent / 'data' / 'models' / 'cmab')
        )
        
        # Initialize policy based on strategy
        if strategy == "ucb":
            self.policy = UCBPolicy(self.config, self.tool_list)
        else:
            self.policy = ThompsonSamplingPolicy(self.config, self.tool_list)
        
        # Training statistics
        self.training_steps = 0
        self.episodes = 0
        self.total_reward = 0.0
        self.epsilon = 0.0  # Not used but kept for compatibility
        
        # Context extractor (shared)
        self.context_extractor = RichContextExtractor()
        
        # Heuristic fallback for fail-soft behavior
        self._heuristic_fallback = HeuristicToolSelector(self.tool_list)
        
        logger.info(f"[CMABAgent] Initialized with strategy={strategy}, actions={num_actions}")
    
    def select_action(
        self,
        scan_state: Dict[str, Any],
        available_tools: List[str] = None,
        training: bool = True
    ) -> Tuple[int, str, float]:
        """
        Select action (tool) based on current state.
        Compatible with DeepRLAgent interface.
        """
        try:
            if available_tools is None:
                available_tools = self.tool_list
            
            # Filter to valid tools
            valid_tools = [t for t in available_tools if t in self.tool_list]
            if not valid_tools:
                valid_tools = self.tool_list[:5]
            
            return self.policy.select_tool(scan_state, valid_tools, training)
            
        except Exception as e:
            logger.error(f"[CMABAgent] Selection failed, using heuristic: {e}")
            return self._heuristic_fallback.select(scan_state, available_tools or self.tool_list)
    
    def store_experience(
        self,
        state: Dict[str, Any],
        action: int,
        reward: float,
        next_state: Dict[str, Any],
        done: bool
    ):
        """
        Store and learn from experience.
        For CMAB, this immediately updates the policy (online learning).
        """
        tool_name = self.tool_list[action] if action < len(self.tool_list) else self.tool_list[0]
        
        metrics = self.policy.update(
            context=state,
            action=action,
            tool_name=tool_name,
            reward=reward,
            next_context=next_state
        )
        
        self.training_steps += 1
        self.total_reward += reward
        
        if done:
            self.episodes += 1
    
    def train_step(self) -> Optional[Dict[str, float]]:
        """
        Training step - for CMAB this is a no-op since learning is online.
        Returns metrics for compatibility.
        """
        return {
            'training_steps': self.training_steps,
            'episodes': self.episodes,
            'total_reward': self.total_reward,
            'strategy': self.config.strategy
        }
    
    def calculate_reward(
        self,
        action: int,
        result: Dict[str, Any],
        scan_state: Dict[str, Any]
    ) -> float:
        """Calculate reward for action (backward compatibility)."""
        return self.calculate_global_reward(action, result, scan_state)
    
    def calculate_global_reward(
        self,
        action: int,
        result: Dict[str, Any],
        scan_state: Dict[str, Any],
        episode_reward: float = 0.0,
        lesson_reward: float = 0.0
    ) -> float:
        """Calculate unified global reward."""
        reward = 0.0
        
        if not result.get('success', False):
            return -0.5
        
        vulnerabilities = result.get('parsed_results', {}).get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 0)
            if isinstance(severity, str):
                sev_map = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2, 'info': 1}
                severity = sev_map.get(severity.lower(), 3)
            
            try:
                severity = float(severity)
            except:
                severity = 3.0
            
            if severity >= 9:
                reward += 5.0
            elif severity >= 7:
                reward += 3.0
            elif severity >= 4:
                reward += 1.5
            else:
                reward += 0.5
            
            if vuln.get('exploitable', False):
                reward += 2.0
            if vuln.get('cve'):
                reward += 0.5
        
        if not vulnerabilities and result.get('success', False):
            tools_executed = [t.get('tool', t) if isinstance(t, dict) else t 
                           for t in scan_state.get('tools_executed', [])]
            tool_name = self.tool_list[action] if action < len(self.tool_list) else ''
            
            if tools_executed.count(tool_name) > 1:
                reward -= 0.3
            else:
                reward += 0.1
        
        services = result.get('parsed_results', {}).get('services', [])
        hosts = result.get('parsed_results', {}).get('hosts', [])
        reward += len(services) * 0.1
        reward += len(hosts) * 0.05
        
        return reward + episode_reward + lesson_reward
    
    def save(self, path: str = None):
        """Save model state."""
        self.policy.save_state(path)
        
        # Also save agent metadata
        meta_path = Path(path or self.config.model_dir) / 'cmab_meta.json'
        meta = {
            'training_steps': self.training_steps,
            'episodes': self.episodes,
            'total_reward': self.total_reward,
            'strategy': self.config.strategy,
            'saved_at': datetime.now().isoformat()
        }
        try:
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            with open(meta_path, 'w') as f:
                json.dump(meta, f, indent=2)
            logger.info(f"[CMABAgent] Saved to {path or self.config.model_dir}")
        except Exception as e:
            logger.error(f"[CMABAgent] Save meta error: {e}")
    
    def load(self, path: str = None) -> bool:
        """Load model state."""
        success = self.policy.load_state(path)
        
        # Load agent metadata
        meta_path = Path(path or self.config.model_dir) / 'cmab_meta.json'
        try:
            if meta_path.exists():
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                self.training_steps = meta.get('training_steps', 0)
                self.episodes = meta.get('episodes', 0)
                self.total_reward = meta.get('total_reward', 0.0)
                logger.info(f"[CMABAgent] Loaded metadata: {self.training_steps} steps, {self.episodes} episodes")
        except Exception as e:
            logger.warning(f"[CMABAgent] Could not load metadata: {e}")
        
        return success
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        return {
            'training_steps': self.training_steps,
            'episodes': self.episodes,
            'total_reward': self.total_reward,
            'strategy': self.config.strategy,
            'num_actions': self.num_actions,
            'policy_type': type(self.policy).__name__
        }


# ═══════════════════════════════════════════════════════════════════════════════
# HEURISTIC FALLBACK
# ═══════════════════════════════════════════════════════════════════════════════

class HeuristicToolSelector:
    """Fallback heuristic selector when CMAB fails."""
    
    PHASE_TOOLS = {
        'reconnaissance': ['nmap', 'whatweb', 'wafw00f', 'amass', 'subfinder'],
        'enumeration': ['gobuster', 'ffuf', 'nikto', 'dirb', 'wpscan'],
        'vulnerability_analysis': ['nuclei', 'sqlmap', 'nikto', 'sslscan'],
        'exploitation': ['sqlmap', 'metasploit', 'hydra', 'commix', 'dalfox'],
        'post_exploitation': ['linpeas', 'curl', 'wget']
    }
    
    def __init__(self, tool_list: List[str]):
        self.tool_list = tool_list
        self.tool_index = {tool: idx for idx, tool in enumerate(tool_list)}
    
    def select(self, scan_state: Dict, available_tools: List[str]) -> Tuple[int, str, float]:
        """Select tool using simple heuristics."""
        phase = scan_state.get('phase', 'reconnaissance').lower()
        phase_tools = self.PHASE_TOOLS.get(phase, self.PHASE_TOOLS['reconnaissance'])
        
        # Find first available tool for this phase
        for tool in phase_tools:
            if tool in available_tools:
                idx = self.tool_index.get(tool, 0)
                return idx, tool, 0.5
        
        # Fallback to first available
        tool = available_tools[0] if available_tools else self.tool_list[0]
        return self.tool_index.get(tool, 0), tool, 0.3


# ═══════════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTION (Required for component registration)
# ═══════════════════════════════════════════════════════════════════════════════

def get_cmab_agent(**kwargs) -> CMABAgent:
    """
    Factory function to get configured CMAB agent.
    Required for component registration in training environment.
    """
    return CMABAgent(**kwargs)


def get_action_policy(strategy: str = "thompson", tool_list: List[str] = None, 
                      config: CMABConfig = None) -> ActionPolicy:
    """Factory function to get specific policy type."""
    if tool_list is None:
        tool_list = CMABAgent.DEFAULT_TOOLS[:35]
    if config is None:
        config = CMABConfig(strategy=strategy)
    
    if strategy == "ucb":
        return UCBPolicy(config, tool_list)
    return ThompsonSamplingPolicy(config, tool_list)


# ═══════════════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY ALIASES
# ═══════════════════════════════════════════════════════════════════════════════

# Alias for drop-in replacement
ContextualBanditAgent = CMABAgent

# For places that import DeepRLAgent directly, they can now use:
# from training.cmab_agent import CMABAgent as DeepRLAgent
