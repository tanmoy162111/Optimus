"""
Reinforcement Learning Agent for Tool Selection
Uses Deep Q-Network (DQN) for sequential decision making
"""
import numpy as np
import tensorflow as tf
from tensorflow import keras
from typing import Dict, Any, List, Tuple
import random
from collections import deque
import os
import pickle
from datetime import datetime

class EnhancedRLAgent:
    """DQN-based RL agent for tool selection in pentesting"""
    
    def __init__(self, state_dim: int = 23, num_actions: int = 20, learning_rate: float = 0.001):
        self.state_dim = state_dim
        self.num_actions = num_actions
        self.learning_rate = learning_rate
        
        # DQN parameters
        self.gamma = 0.95  # Discount factor
        self.epsilon = 1.0  # Exploration rate
        self.epsilon_min = 0.05
        self.epsilon_decay = 0.99  # Increased decay rate for faster convergence
        self.batch_size = 32
        self.memory = deque(maxlen=2000)
        
        # Track epsilon history
        self.epsilon_history = [self.epsilon]
        self.reward_history = []
        self.loss_history = []
        self.update_counter = 0
        self.target_update_frequency = 100
        
        # Build Q-networks
        self.q_network = self._build_q_network()
        self.target_network = self._build_q_network()
        self.update_target_network()
        
        # Tool mapping
        self.tool_index = {}
        self.index_to_tool = {}
        
    def _build_q_network(self) -> keras.Model:
        """Build Deep Q-Network"""
        model = keras.Sequential([
            keras.layers.Dense(128, activation='relu', input_shape=(self.state_dim,)),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dense(self.num_actions, activation='linear')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='mse'
        )
        
        return model
    
    def update_target_network(self):
        """Copy weights from Q-network to target network"""
        self.target_network.set_weights(self.q_network.get_weights())
    
    def select_action(self, state: np.ndarray, available_tools: List[str], epsilon: float = None) -> str:
        """
        Select action using epsilon-greedy policy
        Args:
            state: Current state vector
            available_tools: List of available tool names
            epsilon: Exploration rate (uses self.epsilon if None)
        Returns:
            Selected tool name
        """
        if epsilon is None:
            epsilon = self.epsilon
        
        # Map tools to indices
        if not self.tool_index:
            self._build_tool_mapping(available_tools)
        
        # Get available action indices
        available_indices = [self.tool_index.get(tool, 0) for tool in available_tools if tool in self.tool_index]
        
        if not available_indices:
            # Fallback to random tool
            return random.choice(available_tools) if available_tools else 'nmap'
        
        # Epsilon-greedy
        if random.random() < epsilon:
            # Explore: random action
            selected_idx = random.choice(available_indices)
        else:
            # Exploit: best action
            state_batch = np.expand_dims(state, axis=0)
            q_values = self.q_network.predict(state_batch, verbose=0)[0]
            
            # Mask unavailable actions
            masked_q_values = np.full(self.num_actions, -np.inf)
            masked_q_values[available_indices] = q_values[available_indices]
            
            selected_idx = np.argmax(masked_q_values)
        
        return self.index_to_tool.get(selected_idx, available_tools[0] if available_tools else 'nmap')
    
    def remember(self, state: np.ndarray, action_idx: int, reward: float, next_state: np.ndarray, done: bool):
        """Store experience in replay memory"""
        self.memory.append((state, action_idx, reward, next_state, done))
    
    def replay(self) -> float:
        """
        Train on batch of experiences from replay memory
        Returns: Average loss
        """
        if len(self.memory) < self.batch_size:
            return 0.0
        
        # Sample random batch
        batch = random.sample(self.memory, self.batch_size)
        
        states = np.array([exp[0] for exp in batch])
        actions = np.array([exp[1] for exp in batch])
        rewards = np.array([exp[2] for exp in batch])
        next_states = np.array([exp[3] for exp in batch])
        dones = np.array([exp[4] for exp in batch])
        
        # Predict Q-values for current states
        current_q_values = self.q_network.predict(states, verbose=0)
        
        # Predict Q-values for next states using target network
        next_q_values = self.target_network.predict(next_states, verbose=0)
        
        # Update Q-values
        for i in range(self.batch_size):
            if dones[i]:
                current_q_values[i][actions[i]] = rewards[i]
            else:
                current_q_values[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q_values[i])
        
        # Train
        history = self.q_network.fit(states, current_q_values, epochs=1, verbose=0, batch_size=self.batch_size)
        
        return history.history['loss'][0]
    
    def calculate_reward(self, action_result: Dict[str, Any]) -> float:
        """
        Calculate reward based on action results
        Args:
            action_result: Dict containing:
                - new_vulns: List of newly discovered vulnerabilities
                - execution_time: Time taken in seconds
                - false_positives: Number of false positives
                - phase: Current phase
                - detection_triggered: Whether detection was triggered
        Returns:
            Reward value (can be negative)
        """
        reward = 0.0
        
        # Vulnerability discovery rewards
        for vuln in action_result.get('new_vulns', []):
            severity = vuln.get('severity', 0.0)
            if severity >= 9.0:
                reward += 20  # Critical
            elif severity >= 7.0:
                reward += 10  # High
            elif severity >= 4.0:
                reward += 5   # Medium
            else:
                reward += 1   # Low
        
        # Exploitability bonus
        if any(v.get('exploitable', False) for v in action_result.get('new_vulns', [])):
            reward += 10
        
        # Time penalty (encourage efficiency)
        execution_time = action_result.get('execution_time', 0)
        reward -= execution_time / 100  # Small penalty for time
        
        # False positive penalty
        reward -= action_result.get('false_positives', 0) * 5
        
        # No findings penalty
        if len(action_result.get('new_vulns', [])) == 0:
            reward -= 2
        
        # Detection penalty (for stealth phases)
        if action_result.get('detection_triggered', False):
            phase = action_result.get('phase', 'unknown')
            if phase in ['reconnaissance', 'post_exploitation', 'covering_tracks']:
                reward -= 50  # Severe penalty for stealth phases
            else:
                reward -= 15  # Lighter penalty for other phases
        
        return reward
    
    def update(self, state: np.ndarray, action: str, reward: float, next_state: np.ndarray, done: bool):
        """
        Update agent with experience
        Args:
            state: Current state
            action: Action taken (tool name)
            reward: Reward received
            next_state: Next state
            done: Whether episode is done
        """
        # Convert action to index
        action_idx = self.tool_index.get(action, 0)
        
        # Store experience
        self.remember(state, action_idx, reward, next_state, done)
        
        # Store reward for tracking
        self.reward_history.append(reward)
        
        # Train on experience
        loss = 0.0
        if len(self.memory) >= self.batch_size:
            loss = self.replay()
            self.loss_history.append(loss)
        
        # Update target network periodically
        self.update_counter += 1
        if self.update_counter % self.target_update_frequency == 0:
            self.update_target_network()
        
        # Decay epsilon AFTER episode completes
        if done:
            old_epsilon = self.epsilon
            if self.epsilon > self.epsilon_min:
                self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
            self.epsilon_history.append(self.epsilon)
            
            # Log every 10 episodes
            if len(self.epsilon_history) % 10 == 0:
                print(f"Episode {len(self.epsilon_history)}: "
                      f"Epsilon = {self.epsilon:.4f} (decayed from {old_epsilon:.4f})")
    
    def train_from_episodes(self, episodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train on batch of episodes
        Args:
            episodes: List of episode dicts with 'experiences' key
        Returns:
            Training metrics
        """
        total_reward = 0
        total_loss = 0
        num_steps = 0
        
        for episode in episodes:
            episode_reward = 0
            
            for exp in episode.get('experiences', []):
                state = exp['state']
                action = exp['action']
                reward = exp['reward']
                next_state = exp['next_state']
                done = exp['done']
                
                self.update(state, action, reward, next_state, done)
                
                episode_reward += reward
                num_steps += 1
            
            total_reward += episode_reward
        
        # Update target network periodically
        self.update_target_network()
        
        avg_reward = total_reward / max(len(episodes), 1)
        avg_loss = total_loss / max(num_steps, 1)
        
        metrics = {
            'avg_episode_reward': avg_reward,
            'episodes_trained': len(episodes),
            'epsilon': self.epsilon,
            'memory_size': len(self.memory)
        }
        
        return metrics
    
    def save_model(self, path: str):
        """Save model with all training state"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Save as pickle with all state
        save_data = {
            'q_network_weights': self.q_network.get_weights(),
            'target_network_weights': self.target_network.get_weights(),
            'epsilon': self.epsilon,
            'epsilon_history': self.epsilon_history,
            'reward_history': self.reward_history[-1000:],  # Keep last 1000
            'loss_history': self.loss_history[-1000:],  # Keep last 1000
            'replay_buffer': list(self.memory)[-1000:],  # Keep last 1000
            'hyperparameters': {
                'gamma': self.gamma,
                'epsilon_decay': self.epsilon_decay,
                'epsilon_min': self.epsilon_min,
                'batch_size': self.batch_size,
                'learning_rate': float(self.q_network.optimizer.learning_rate.numpy())
            },
            'metadata': {
                'episodes_trained': len(self.epsilon_history),
                'update_counter': self.update_counter,
                'timestamp': datetime.now().isoformat()
            }
        }
        
        with open(path, 'wb') as f:
            pickle.dump(save_data, f)
        
        print(f"✅ Model saved to {path}")
        print(f"   Episodes: {len(self.epsilon_history)}")
        print(f"   Epsilon: {self.epsilon:.4f}")
    
    def load_model(self, path: str):
        """Load model with all training state"""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model not found: {path}")
        
        with open(path, 'rb') as f:
            save_data = pickle.load(f)
        
        # Load network weights
        self.q_network.set_weights(save_data['q_network_weights'])
        self.target_network.set_weights(save_data['target_network_weights'])
        
        # Restore epsilon and history
        self.epsilon = save_data.get('epsilon', self.epsilon_min)
        self.epsilon_history = save_data.get('epsilon_history', [])
        self.reward_history = save_data.get('reward_history', [])
        self.loss_history = save_data.get('loss_history', [])
        
        # Restore replay buffer
        if 'replay_buffer' in save_data:
            self.memory = deque(save_data['replay_buffer'], maxlen=2000)
        
        # Restore counter
        metadata = save_data.get('metadata', {})
        self.update_counter = metadata.get('update_counter', 0)
        
        print(f"✅ Model loaded from {path}")
        print(f"   Episodes trained: {len(self.epsilon_history)}")
        print(f"   Current epsilon: {self.epsilon:.4f}")
        print(f"   Replay buffer size: {len(self.memory)}")
    
    def _build_tool_mapping(self, available_tools: List[str]):
        """Build mapping between tool names and action indices"""
        for idx, tool in enumerate(available_tools[:self.num_actions]):
            self.tool_index[tool] = idx
            self.index_to_tool[idx] = tool
