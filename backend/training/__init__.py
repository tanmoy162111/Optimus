# Backend training module
"""
Optimus Training Module

Provides learning agents for intelligent tool selection:
- CMABAgent: CPU-efficient Contextual Multi-Armed Bandit (Thompson Sampling/UCB)
- DeepRLAgent: TensorFlow-based Deep RL (requires GPU/TF installation)

Recommended: Use CMAB for most deployments (no TensorFlow dependency)
"""

# Lazy imports to prevent cascading failures
_cmab_agent = None
_deep_rl_agent = None


def get_cmab_agent(**kwargs):
    """Get CMAB agent instance (factory function)"""
    global _cmab_agent
    from .cmab_agent import get_cmab_agent as _get_cmab
    return _get_cmab(**kwargs)


def get_learning_agent(**kwargs):
    """
    Get best available learning agent.
    Prefers CMAB (CPU-efficient), falls back to DeepRL if available.
    """
    try:
        return get_cmab_agent(**kwargs)
    except Exception:
        try:
            from .deep_rl_agent import get_deep_rl_agent
            return get_deep_rl_agent(**kwargs)
        except Exception:
            return None


# Expose key classes for direct import
__all__ = [
    'get_cmab_agent',
    'get_learning_agent',
]
