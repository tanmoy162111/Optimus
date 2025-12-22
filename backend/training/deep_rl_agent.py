"""
Deep Reinforcement Learning Agent for Optimus
Implements Dueling Double DQN with Prioritized Experience Replay

Architecture:
- Dueling DQN: Separates value and advantage estimation
- Double DQN: Reduces overestimation bias
- PER: Focuses learning on important experiences
- Target Network: Stabilizes training
"""

import os
import numpy as np
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

# TensorFlow imports with error handling
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model, optimizers
    from tensorflow.keras.initializers import Orthogonal, Zeros
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    tf = None
    keras = None
    layers = None
    Model = None
    optimizers = None
    Orthogonal = None
    Zeros = None

from .enhanced_state_encoder import EnhancedStateEncoder, get_state_encoder
from .prioritized_replay import PrioritizedReplayBuffer, StandardReplayBuffer

logger = logging.getLogger(__name__)


if TF_AVAILABLE:
    class NoisyDense(layers.Layer):
        """
        Noisy linear layer for exploration.
        
        Replaces epsilon-greedy with learned noise for better exploration.
        Reference: Fortunato et al., "Noisy Networks for Exploration" (2018)
        """
        
        def __init__(self, units: int, sigma_init: float = 0.5, **kwargs):
            super().__init__(**kwargs)
            self.units = units
            self.sigma_init = sigma_init
        
        def build(self, input_shape):
            self.input_dim = int(input_shape[-1])
            
            # Learnable parameters
            mu_range = 1.0 / np.sqrt(self.input_dim)
            
            self.w_mu = self.add_weight(
                name='w_mu',
                shape=(self.input_dim, self.units),
                initializer=tf.random_uniform_initializer(-mu_range, mu_range),
                trainable=True
            )
            self.w_sigma = self.add_weight(
                name='w_sigma',
                shape=(self.input_dim, self.units),
                initializer=tf.constant_initializer(self.sigma_init / np.sqrt(self.input_dim)),
                trainable=True
            )
            self.b_mu = self.add_weight(
                name='b_mu',
                shape=(self.units,),
                initializer=tf.random_uniform_initializer(-mu_range, mu_range),
                trainable=True
            )
            self.b_sigma = self.add_weight(
                name='b_sigma',
                shape=(self.units,),
                initializer=tf.constant_initializer(self.sigma_init / np.sqrt(self.units)),
                trainable=True
            )
        
        def call(self, inputs, training=None):
            if training:
                # Sample noise
                epsilon_in = self._f(tf.random.normal((self.input_dim, 1)))
                epsilon_out = self._f(tf.random.normal((1, self.units)))
                
                w_epsilon = tf.matmul(epsilon_in, epsilon_out)
                b_epsilon = tf.squeeze(epsilon_out)
                
                w = self.w_mu + self.w_sigma * w_epsilon
                b = self.b_mu + self.b_sigma * b_epsilon
            else:
                w = self.w_mu
                b = self.b_mu
            
            return tf.matmul(inputs, w) + b
        
        def _f(self, x):
            """Factorized Gaussian noise function"""
            return tf.sign(x) * tf.sqrt(tf.abs(x))


def create_dueling_network(
    state_dim: int,
    num_actions: int,
    hidden_sizes: List[int] = [256, 256, 128],
    use_noisy: bool = True,
    name: str = "dueling_dqn"
) -> Model:
    """
    Create Dueling DQN network.
    
    Architecture:
        Input → Shared layers → Split into Value and Advantage streams
        Q(s,a) = V(s) + (A(s,a) - mean(A(s,a')))
    
    Args:
        state_dim: Input state dimensions
        num_actions: Number of possible actions
        hidden_sizes: Sizes of shared hidden layers
        use_noisy: Whether to use noisy layers
        name: Model name
        
    Returns:
        Keras Model
    """
    if not TF_AVAILABLE:
        raise ImportError("TensorFlow not available. Install with: pip install tensorflow")
    
    # Input layer
    state_input = layers.Input(shape=(state_dim,), name='state_input')
    
    # Shared feature extraction layers
    x = state_input
    for i, size in enumerate(hidden_sizes):
        if use_noisy and i == len(hidden_sizes) - 1:
            x = NoisyDense(size, name=f'shared_noisy_{i}')(x)
        else:
            x = layers.Dense(
                size,
                kernel_initializer=Orthogonal(gain=np.sqrt(2)),
                bias_initializer=Zeros(),
                name=f'shared_{i}'
            )(x)
        x = layers.ReLU()(x)
        x = layers.LayerNormalization()(x)
    
    # Value stream - estimates V(s)
    value_stream = x
    if use_noisy:
        value_stream = NoisyDense(64, name='value_hidden')(value_stream)
    else:
        value_stream = layers.Dense(64, activation='relu', name='value_hidden')(value_stream)
    
    if use_noisy:
        value = NoisyDense(1, name='value_output')(value_stream)
    else:
        value = layers.Dense(1, name='value_output')(value_stream)
    
    # Advantage stream - estimates A(s, a)
    advantage_stream = x
    if use_noisy:
        advantage_stream = NoisyDense(64, name='advantage_hidden')(advantage_stream)
    else:
        advantage_stream = layers.Dense(64, activation='relu', name='advantage_hidden')(advantage_stream)
    
    if use_noisy:
        advantage = NoisyDense(num_actions, name='advantage_output')(advantage_stream)
    else:
        advantage = layers.Dense(num_actions, name='advantage_output')(advantage_stream)
    
    # Combine: Q(s,a) = V(s) + (A(s,a) - mean(A))
    import keras.ops as K
    q_values = layers.Add()([value, layers.Subtract()([advantage, K.mean(advantage, axis=1, keepdims=True)])])
    
    model = Model(inputs=state_input, outputs=q_values, name=name)
    
    return model


class DeepRLAgent:
    """
    Deep RL Agent using Dueling Double DQN with PER.
    
    This agent learns to select optimal security tools based on
    the current scan state, using deep reinforcement learning.
    
    Key features:
    - Dueling architecture for better value estimation
    - Double DQN to reduce overestimation
    - Prioritized replay for efficient learning
    - Target network for stable training
    - Noisy networks for exploration (optional)
    """
    
    def __init__(
        self,
        num_actions: int = 35,
        state_dim: int = 128,
        learning_rate: float = 1e-4,
        gamma: float = 0.99,
        tau: float = 0.005,
        buffer_size: int = 100000,
        batch_size: int = 64,
        use_per: bool = True,
        use_noisy: bool = True,
        per_alpha: float = 0.6,
        per_beta_start: float = 0.4,
        model_dir: str = None
    ):
        """
        Initialize Deep RL Agent.
        
        Args:
            num_actions: Number of tools to choose from
            state_dim: State vector dimension (128 for enhanced encoder)
            learning_rate: Adam learning rate
            gamma: Discount factor for future rewards
            tau: Soft update coefficient for target network
            buffer_size: Replay buffer capacity
            batch_size: Training batch size
            use_per: Whether to use Prioritized Experience Replay
            use_noisy: Whether to use noisy networks
            per_alpha: PER priority exponent
            per_beta_start: PER initial importance sampling exponent
            model_dir: Directory to save/load models
        """
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow required. Install with: pip install tensorflow")
        
        self.num_actions = num_actions
        self.state_dim = state_dim
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.tau = tau
        self.batch_size = batch_size
        self.use_per = use_per
        self.use_noisy = use_noisy
        
        # Set up model directory
        if model_dir is None:
            model_dir = Path(__file__).parent.parent / 'models' / 'deep_rl'
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize state encoder
        self.state_encoder = get_state_encoder()
        
        # Create networks
        logger.info(f"[DeepRL] Creating networks: state_dim={state_dim}, actions={num_actions}")
        
        self.online_network = create_dueling_network(
            state_dim, num_actions,
            use_noisy=use_noisy,
            name='online_network'
        )
        self.target_network = create_dueling_network(
            state_dim, num_actions,
            use_noisy=use_noisy,
            name='target_network'
        )
        
        # Initialize target network with same weights
        self.target_network.set_weights(self.online_network.get_weights())
        
        # Optimizer
        self.optimizer = optimizers.Adam(learning_rate=learning_rate)
        
        # Replay buffer
        if use_per:
            self.replay_buffer = PrioritizedReplayBuffer(
                capacity=buffer_size,
                alpha=per_alpha,
                beta_start=per_beta_start
            )
        else:
            self.replay_buffer = StandardReplayBuffer(capacity=buffer_size)
        
        # Training state
        self.training_steps = 0
        self.episodes = 0
        self.total_reward = 0.0
        
        # For epsilon-greedy (fallback when not using noisy)
        self.epsilon = 1.0 if not use_noisy else 0.0
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        
        # Tool mapping (indices to tool names)
        self.tool_list = self._get_default_tool_list()
        
        logger.info(f"[DeepRL] Agent initialized (PER: {use_per}, Noisy: {use_noisy})")
    
    def _get_default_tool_list(self) -> List[str]:
        """Get default list of tools matching state encoder"""
        return [
            'nmap', 'nikto', 'nuclei', 'sqlmap', 'dalfox', 'commix',
            'gobuster', 'ffuf', 'dirb', 'wpscan', 'hydra', 'metasploit',
            'burpsuite', 'sublist3r', 'amass', 'whatweb', 'fierce',
            'dnsenum', 'sslscan', 'enum4linux', 'xsser', 'testssl',
            'wfuzz', 'arjun', 'paramspider', 'waybackurls', 'gau',
            'httpx', 'katana', 'subfinder', 'masscan', 'nessus',
            'openvas', 'zap', 'arachni'
        ][:self.num_actions]
    
    def select_action(
        self,
        scan_state: Dict[str, Any],
        available_tools: List[str] = None,
        training: bool = True
    ) -> Tuple[int, str, float]:
        """
        Select action (tool) based on current state.
        
        Args:
            scan_state: Current scan state dictionary
            available_tools: List of currently available tools (for masking)
            training: Whether in training mode (affects exploration)
            
        Returns:
            Tuple of (action_index, tool_name, confidence)
        """
        # Encode state
        state_vector = self.state_encoder.encode(scan_state)
        state_tensor = tf.expand_dims(state_vector, 0)
        
        # Get Q-values
        q_values = self.online_network(state_tensor, training=training)[0].numpy()
        
        # Apply tool availability mask if provided
        if available_tools:
            mask = np.zeros(self.num_actions)
            for tool in available_tools:
                if tool in self.tool_list:
                    idx = self.tool_list.index(tool)
                    mask[idx] = 1.0
            
            # Mask unavailable actions with large negative value
            q_values = np.where(mask > 0, q_values, -1e9)
        
        # Epsilon-greedy exploration (only if not using noisy networks)
        if training and not self.use_noisy and np.random.random() < self.epsilon:
            valid_indices = np.where(q_values > -1e8)[0]
            if len(valid_indices) > 0:
                action = np.random.choice(valid_indices)
            else:
                action = np.random.randint(0, self.num_actions)
        else:
            action = int(np.argmax(q_values))
        
        # Get tool name and confidence
        tool_name = self.tool_list[action] if action < len(self.tool_list) else f"tool_{action}"
        
        # Calculate confidence from Q-values (softmax normalized)
        q_exp = np.exp(q_values - np.max(q_values))
        q_probs = q_exp / q_exp.sum()
        confidence = float(q_probs[action])
        
        return action, tool_name, confidence
    
    def store_experience(
        self,
        state: Dict[str, Any],
        action: int,
        reward: float,
        next_state: Dict[str, Any],
        done: bool
    ):
        """
        Store experience in replay buffer.
        
        Args:
            state: State when action was taken
            action: Action (tool index) that was taken
            reward: Reward received
            next_state: Resulting state
            done: Whether episode ended
        """
        state_vec = self.state_encoder.encode(state)
        next_state_vec = self.state_encoder.encode(next_state)
        
        self.replay_buffer.add(state_vec, action, reward, next_state_vec, done)
    
    def train_step(self) -> Optional[Dict[str, float]]:
        """
        Perform one training step.
        
        Returns:
            Training metrics dict or None if buffer not ready
        """
        if not self.replay_buffer.is_ready(self.batch_size):
            return None
        
        # Sample batch
        states, actions, rewards, next_states, dones, weights, indices = \
            self.replay_buffer.sample(self.batch_size)
        
        if len(states) == 0:
            return None
        
        # Convert to tensors
        states = tf.convert_to_tensor(np.array(states), dtype=tf.float32)
        actions = tf.convert_to_tensor(actions, dtype=tf.int32)
        rewards = tf.convert_to_tensor(rewards, dtype=tf.float32)
        next_states = tf.convert_to_tensor(np.array(next_states), dtype=tf.float32)
        dones = tf.convert_to_tensor(dones, dtype=tf.float32)
        weights = tf.convert_to_tensor(weights, dtype=tf.float32)
        
        # Training step with gradient computation
        with tf.GradientTape() as tape:
            # Current Q-values for taken actions
            current_q = self.online_network(states, training=True)
            action_masks = tf.one_hot(actions, self.num_actions)
            current_q_values = tf.reduce_sum(current_q * action_masks, axis=1)
            
            # Double DQN: Use online network to select actions, target network to evaluate
            next_q_online = self.online_network(next_states, training=False)
            next_actions = tf.argmax(next_q_online, axis=1, output_type=tf.int32)
            next_action_masks = tf.one_hot(next_actions, self.num_actions)
            
            next_q_target = self.target_network(next_states, training=False)
            next_q_values = tf.reduce_sum(next_q_target * next_action_masks, axis=1)
            
            # TD target: r + gamma * Q_target(s', argmax_a Q_online(s', a))
            target_q_values = rewards + (1 - dones) * self.gamma * next_q_values
            
            # TD errors (for PER priority update)
            td_errors = current_q_values - target_q_values
            
            # Huber loss with importance sampling weights
            huber_loss = tf.keras.losses.Huber(reduction=tf.keras.losses.Reduction.NONE)
            losses = huber_loss(target_q_values, current_q_values)
            weighted_loss = tf.reduce_mean(weights * losses)
        
        # Apply gradients
        gradients = tape.gradient(weighted_loss, self.online_network.trainable_variables)
        
        # Clip gradients for stability
        gradients, _ = tf.clip_by_global_norm(gradients, 10.0)
        
        self.optimizer.apply_gradients(
            zip(gradients, self.online_network.trainable_variables)
        )
        
        # Update priorities in PER buffer
        if self.use_per:
            self.replay_buffer.update_priorities(indices, td_errors.numpy())
        
        # Soft update target network
        self._soft_update_target()
        
        # Update epsilon (for non-noisy case)
        if not self.use_noisy and self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        self.training_steps += 1
        
        return {
            'loss': float(weighted_loss.numpy()),
            'mean_q': float(tf.reduce_mean(current_q_values).numpy()),
            'mean_td_error': float(tf.reduce_mean(tf.abs(td_errors)).numpy()),
            'epsilon': self.epsilon,
            'buffer_size': len(self.replay_buffer),
            'training_steps': self.training_steps
        }
    
    def _soft_update_target(self):
        """Soft update target network weights: θ_target = τ*θ_online + (1-τ)*θ_target"""
        for target_var, online_var in zip(
            self.target_network.trainable_variables,
            self.online_network.trainable_variables
        ):
            target_var.assign(self.tau * online_var + (1 - self.tau) * target_var)
    
    def hard_update_target(self):
        """Hard update: Copy online network weights to target"""
        self.target_network.set_weights(self.online_network.get_weights())
    
    def calculate_reward(
        self,
        action: int,
        result: Dict[str, Any],
        scan_state: Dict[str, Any]
    ) -> float:
        """
        Calculate reward for action based on result.
        
        Reward structure:
        - High reward for critical/high severity findings
        - Moderate reward for medium findings
        - Small reward for low/info findings
        - Penalty for failed execution
        - Penalty for repeated tools without findings
        - Bonus for progressing phases
        
        Args:
            action: Action (tool index) that was taken
            result: Execution result from tool
            scan_state: Current scan state
            
        Returns:
            Calculated reward value
        """
        reward = 0.0
        
        # Check execution success
        if not result.get('success', False):
            return -0.5
        
        # Reward based on findings
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
            
            # Severity-based reward
            if severity >= 9:
                reward += 5.0
            elif severity >= 7:
                reward += 3.0
            elif severity >= 4:
                reward += 1.5
            else:
                reward += 0.5
            
            # Bonus for exploitable
            if vuln.get('exploitable', False):
                reward += 2.0
            
            # Bonus for CVE
            if vuln.get('cve'):
                reward += 0.5
        
        # Penalty for no findings after execution
        if not vulnerabilities and result.get('success', False):
            # Check if tool was recently used
            tools_executed = [
                t['tool'] if isinstance(t, dict) else t 
                for t in scan_state.get('tools_executed', [])
            ]
            tool_name = self.tool_list[action] if action < len(self.tool_list) else ''
            
            if tools_executed.count(tool_name) > 1:
                reward -= 0.3
            else:
                reward += 0.1
        
        # Services/host discovery reward
        services = result.get('parsed_results', {}).get('services', [])
        hosts = result.get('parsed_results', {}).get('hosts', [])
        reward += len(services) * 0.1
        reward += len(hosts) * 0.05
        
        return reward
    
    def save(self, path: str = None):
        """
        Save model weights and state.
        
        Args:
            path: Save path (uses default if None)
        """
        if path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            path = self.model_dir / f'checkpoint_{timestamp}'
        
        path = Path(path)
        # Remove .pt extension if present
        if path.suffix == '.pt':
            path = path.with_suffix('')
        path.mkdir(parents=True, exist_ok=True)
        
        # Save weights
        self.online_network.save_weights(str(path / 'online_weights.weights.h5'))
        self.target_network.save_weights(str(path / 'target_weights.weights.h5'))
        
        # Save training state
        state = {
            'training_steps': self.training_steps,
            'episodes': self.episodes,
            'epsilon': self.epsilon,
            'total_reward': self.total_reward
        }
        
        import json
        with open(path / 'training_state.json', 'w') as f:
            json.dump(state, f)
        
        logger.info(f"[DeepRL] Saved checkpoint to {path}")
    
    def load(self, path: str = None):
        """
        Load model weights and state.
        
        Args:
            path: Load path (uses latest if None)
        """
        if path is None:
            # Find latest checkpoint
            checkpoints = list(self.model_dir.glob('checkpoint_*'))
            if not checkpoints:
                logger.warning("[DeepRL] No checkpoints found")
                return False
            path = max(checkpoints, key=lambda p: p.stat().st_mtime)
        
        path = Path(path)
        # Remove .pt extension if present
        if path.suffix == '.pt':
            path = path.with_suffix('')
        
        try:
            # Try new format first, fallback to old
            online_weights = path / 'online_weights.weights.h5'
            target_weights = path / 'target_weights.weights.h5'
            if not online_weights.exists():
                online_weights = path / 'online_weights.h5'
                target_weights = path / 'target_weights.h5'
            
            self.online_network.load_weights(str(online_weights))
            self.target_network.load_weights(str(target_weights))
            
            import json
            with open(path / 'training_state.json', 'r') as f:
                state = json.load(f)
            
            self.training_steps = state.get('training_steps', 0)
            self.episodes = state.get('episodes', 0)
            self.epsilon = state.get('epsilon', self.epsilon)
            self.total_reward = state.get('total_reward', 0.0)
            
            logger.info(f"[DeepRL] Loaded checkpoint from {path}")
            return True
            
        except Exception as e:
            logger.error(f"[DeepRL] Failed to load checkpoint: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return {
            'training_steps': self.training_steps,
            'episodes': self.episodes,
            'epsilon': self.epsilon,
            'buffer_size': len(self.replay_buffer),
            'total_reward': self.total_reward,
            'use_per': self.use_per,
            'use_noisy': self.use_noisy
        }


# Factory function
def get_deep_rl_agent(**kwargs) -> DeepRLAgent:
    """
    Get configured Deep RL agent.
    
    Args:
        **kwargs: Arguments to pass to DeepRLAgent
        
    Returns:
        Configured DeepRLAgent instance
    """
    return DeepRLAgent(**kwargs)
