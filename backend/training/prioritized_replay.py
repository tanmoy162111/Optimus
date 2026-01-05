"""
Prioritized Experience Replay Buffer
Samples important experiences more frequently based on TD-error

This significantly improves learning efficiency by focusing on
experiences where the agent's predictions were most wrong.
"""

import numpy as np
from typing import List, Tuple, Optional, NamedTuple
from dataclasses import dataclass, field
import random
import logging

logger = logging.getLogger(__name__)


class Experience(NamedTuple):
    """Single experience tuple for replay buffer"""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class SumTree:
    """
    Binary sum tree for efficient priority-based sampling.
    
    Provides O(log n) operations for:
    - Adding/updating priorities
    - Sampling proportional to priority
    
    Structure:
    - Leaf nodes store priorities
    - Internal nodes store sum of children
    - Root stores total priority sum
    """
    
    def __init__(self, capacity: int):
        """
        Initialize sum tree.
        
        Args:
            capacity: Maximum number of experiences to store
        """
        self.capacity = capacity
        # Tree has (2 * capacity - 1) nodes
        # Leaves are at indices [capacity-1, 2*capacity-2]
        self.tree = np.zeros(2 * capacity - 1, dtype=np.float64)
        self.data = [None] * capacity
        self.write_idx = 0
        self.n_entries = 0
    
    def _propagate(self, idx: int, change: float):
        """Propagate priority change up to root"""
        parent = (idx - 1) // 2
        self.tree[parent] += change
        if parent != 0:
            self._propagate(parent, change)
    
    def _retrieve(self, idx: int, s: float) -> int:
        """
        Find leaf index for cumulative sum s.
        
        Args:
            idx: Current node index
            s: Target cumulative sum
            
        Returns:
            Leaf index
        """
        left = 2 * idx + 1
        right = left + 1
        
        # If at leaf, return
        if left >= len(self.tree):
            return idx
        
        # Go left if s is in left subtree, else go right
        if s <= self.tree[left]:
            return self._retrieve(left, s)
        else:
            return self._retrieve(right, s - self.tree[left])
    
    def total(self) -> float:
        """Get total priority sum (root value)"""
        return self.tree[0]
    
    def add(self, priority: float, data: Experience):
        """
        Add experience with given priority.
        
        Args:
            priority: Priority value (typically |TD-error| + epsilon)
            data: Experience tuple to store
        """
        # Calculate tree index for this data
        tree_idx = self.write_idx + self.capacity - 1
        
        # Store data
        self.data[self.write_idx] = data
        
        # Update tree
        self.update(tree_idx, priority)
        
        # Move write pointer
        self.write_idx = (self.write_idx + 1) % self.capacity
        self.n_entries = min(self.n_entries + 1, self.capacity)
    
    def update(self, tree_idx: int, priority: float):
        """
        Update priority at given tree index.
        
        Args:
            tree_idx: Index in tree array
            priority: New priority value
        """
        # Clamp priority to reasonable range
        priority = max(priority, 1e-6)
        priority = min(priority, 1e6)
        
        change = priority - self.tree[tree_idx]
        self.tree[tree_idx] = priority
        self._propagate(tree_idx, change)
    
    def get(self, s: float) -> Tuple[int, float, Optional[Experience]]:
        """
        Get experience for cumulative sum s.
        
        Args:
            s: Cumulative sum to search for
            
        Returns:
            Tuple of (tree_index, priority, experience)
        """
        # Clamp s to valid range
        s = max(0, min(s, self.total() - 1e-6))
        
        tree_idx = self._retrieve(0, s)
        data_idx = tree_idx - self.capacity + 1
        
        # Bounds check
        if data_idx < 0 or data_idx >= self.capacity:
            return tree_idx, 0.0, None
        
        return tree_idx, self.tree[tree_idx], self.data[data_idx]
    
    def min_priority(self) -> float:
        """Get minimum priority among stored experiences"""
        if self.n_entries == 0:
            return 1.0
        
        leaf_start = self.capacity - 1
        leaf_end = leaf_start + self.n_entries
        priorities = self.tree[leaf_start:leaf_end]
        
        # Filter out zeros
        non_zero = priorities[priorities > 0]
        if len(non_zero) == 0:
            return 1e-6
        
        return float(np.min(non_zero))
    
    def max_priority(self) -> float:
        """Get maximum priority among stored experiences"""
        if self.n_entries == 0:
            return 1.0
        
        leaf_start = self.capacity - 1
        leaf_end = leaf_start + self.n_entries
        return float(np.max(self.tree[leaf_start:leaf_end]))


class PrioritizedReplayBuffer:
    """
    Prioritized Experience Replay (PER) buffer.
    
    Samples experiences proportional to their TD-error priority,
    with importance sampling weights to correct for bias.
    
    Key hyperparameters:
    - alpha: Priority exponent (0=uniform, 1=full prioritization)
    - beta: Importance sampling exponent (annealed from start to 1.0)
    
    Reference: Schaul et al., "Prioritized Experience Replay" (2016)
    """
    
    def __init__(
        self,
        capacity: int = 100000,
        alpha: float = 0.6,
        beta_start: float = 0.4,
        beta_end: float = 1.0,
        beta_frames: int = 100000
    ):
        """
        Initialize PER buffer.
        
        Args:
            capacity: Maximum buffer size
            alpha: Priority exponent [0, 1] - higher = more prioritization
            beta_start: Initial importance sampling exponent
            beta_end: Final importance sampling exponent (usually 1.0)
            beta_frames: Frames over which to anneal beta
        """
        self.tree = SumTree(capacity)
        self.capacity = capacity
        self.alpha = alpha
        self.beta_start = beta_start
        self.beta_end = beta_end
        self.beta_frames = beta_frames
        self.frame = 0
        
        # Small constant to ensure non-zero priority
        self.epsilon = 1e-6
        
        # Track max priority for new experiences
        self._max_priority = 1.0
        
        logger.info(
            f"[PER] Initialized: capacity={capacity}, alpha={alpha}, "
            f"beta={beta_start}->{beta_end}"
        )
    
    @property
    def beta(self) -> float:
        """Current importance sampling exponent (annealed over training)"""
        fraction = min(self.frame / max(self.beta_frames, 1), 1.0)
        return self.beta_start + fraction * (self.beta_end - self.beta_start)
    
    def add(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool
    ):
        """
        Add experience to buffer with max priority.
        
        New experiences get maximum priority to ensure they're
        sampled at least once.
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Resulting state
            done: Episode done flag
        """
        # Create experience tuple
        exp = Experience(
            state=np.array(state, dtype=np.float32),
            action=int(action),
            reward=float(reward),
            next_state=np.array(next_state, dtype=np.float32),
            done=bool(done)
        )
        
        # Verify experience tuple order
        logger.debug(f"[PER] Adding experience: (state_shape={exp.state.shape}, action={exp.action}, reward={exp.reward:.3f}, next_state_shape={exp.next_state.shape}, done={exp.done})")
        
        # New experiences get max priority
        priority = self._max_priority ** self.alpha
        self.tree.add(priority, exp)
    
    def sample(self, batch_size: int) -> Tuple[
        List[np.ndarray],  # states
        List[int],         # actions
        List[float],       # rewards
        List[np.ndarray],  # next_states
        List[bool],        # dones
        np.ndarray,        # importance weights
        List[int]          # tree indices (for priority updates)
    ]:
        """
        Sample batch with priority-based selection.
        
        Uses stratified sampling: divides priority range into
        segments and samples one experience from each.
        
        Args:
            batch_size: Number of experiences to sample
            
        Returns:
            Tuple of (states, actions, rewards, next_states, dones, weights, indices)
        """
        states, actions, rewards, next_states, dones = [], [], [], [], []
        indices = []
        priorities = []
        
        # Adjust batch size if buffer doesn't have enough
        actual_batch = min(batch_size, self.tree.n_entries)
        if actual_batch == 0:
            return [], [], [], [], [], np.array([]), []
        
        # Get total priority
        total = self.tree.total()
        if total <= 0:
            total = 1e-6
        
        # Segment size for stratified sampling
        segment = total / actual_batch
        
        for i in range(actual_batch):
            # Sample uniformly from segment
            a = segment * i
            b = segment * (i + 1)
            s = random.uniform(a, b)
            
            tree_idx, priority, exp = self.tree.get(s)
            
            if exp is not None:
                states.append(exp.state)
                actions.append(exp.action)
                rewards.append(exp.reward)
                next_states.append(exp.next_state)
                dones.append(exp.done)
                indices.append(tree_idx)
                priorities.append(max(priority, self.epsilon))
        
        if not states:
            return [], [], [], [], [], np.array([]), []
        
        # Calculate importance sampling weights
        priorities = np.array(priorities, dtype=np.float64)
        probs = priorities / total
        
        # IS weights: (N * P(i))^(-beta)
        weights = (self.tree.n_entries * probs) ** (-self.beta)
        
        # Normalize by max weight for stability
        weights = weights / weights.max()
        
        # Increment frame counter for beta annealing
        self.frame += actual_batch
        
        return (
            states,
            actions, 
            rewards,
            next_states,
            dones,
            weights.astype(np.float32),
            indices
        )
    
    def update_priorities(self, indices: List[int], td_errors: np.ndarray):
        """
        Update priorities based on TD errors.
        
        Args:
            indices: Tree indices of sampled experiences
            td_errors: Corresponding TD errors from learning
        """
        for idx, td_error in zip(indices, td_errors):
            # Priority = |TD-error| + epsilon
            priority = (abs(float(td_error)) + self.epsilon) ** self.alpha
            
            # Update max priority
            self._max_priority = max(self._max_priority, priority)
            
            # Update tree
            self.tree.update(idx, priority)
    
    def __len__(self) -> int:
        """Current buffer size"""
        return self.tree.n_entries
    
    def is_ready(self, batch_size: int) -> bool:
        """Check if buffer has enough samples for training"""
        return len(self) >= batch_size


class StandardReplayBuffer:
    """
    Standard (uniform) replay buffer.
    
    Fallback when PER is disabled or for comparison experiments.
    """
    
    def __init__(self, capacity: int = 100000):
        """
        Initialize standard replay buffer.
        
        Args:
            capacity: Maximum buffer size
        """
        self.capacity = capacity
        self.buffer: List[Experience] = []
        self.position = 0
        
        logger.info(f"[ReplayBuffer] Initialized with capacity={capacity}")
    
    def add(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool
    ):
        """Add experience to buffer"""
        exp = Experience(
            state=np.array(state, dtype=np.float32),
            action=int(action),
            reward=float(reward),
            next_state=np.array(next_state, dtype=np.float32),
            done=bool(done)
        )
        
        # Verify experience tuple order for standard buffer
        logger.debug(f"[ReplayBuffer] Adding experience: (state_shape={exp.state.shape}, action={exp.action}, reward={exp.reward:.3f}, next_state_shape={exp.next_state.shape}, done={exp.done})")
        
        if len(self.buffer) < self.capacity:
            self.buffer.append(exp)
        else:
            self.buffer[self.position] = exp
        
        self.position = (self.position + 1) % self.capacity
    
    def sample(self, batch_size: int) -> Tuple[
        List[np.ndarray],
        List[int],
        List[float],
        List[np.ndarray],
        List[bool],
        np.ndarray,
        List[int]
    ]:
        """Sample random batch"""
        actual_batch = min(batch_size, len(self.buffer))
        batch = random.sample(self.buffer, actual_batch)
        
        states = [e.state for e in batch]
        actions = [e.action for e in batch]
        rewards = [e.reward for e in batch]
        next_states = [e.next_state for e in batch]
        dones = [e.done for e in batch]
        
        # Uniform weights for standard buffer
        weights = np.ones(actual_batch, dtype=np.float32)
        
        # No indices needed for uniform sampling
        indices = list(range(actual_batch))
        
        return states, actions, rewards, next_states, dones, weights, indices
    
    def update_priorities(self, indices: List[int], td_errors: np.ndarray):
        """No-op for standard buffer"""
        pass
    
    def __len__(self) -> int:
        return len(self.buffer)
    
    def is_ready(self, batch_size: int) -> bool:
        return len(self) >= batch_size
