"""
Intelligence Package for Optimus Penetration Testing Agent

This package contains advanced AI/ML capabilities:
- memory_system: Persistent cross-scan memory
- web_intelligence: Real-time web intel gathering  
- delegation_system: Multi-agent task delegation
- adaptive_exploitation: Real-time adaptation
- vulnerability_chaining: Attack graph analysis
- explainable_ai: Decision explanations
- continuous_learning: Production learning
- campaign_intelligence: Multi-target campaigns
- optimus_brain: Unified intelligence engine
"""

from .optimus_brain import get_optimus_brain, OptimusBrain, OptimusConfig
from .memory_system import get_memory_system, SmartMemorySystem
from .web_intelligence import get_web_intelligence, WebIntelligenceEngine
from .delegation_system import get_agent_coordinator, AgentCoordinator
from .adaptive_exploitation import get_adaptive_engine, RealTimeAdaptiveEngine
from .vulnerability_chaining import get_chain_engine, VulnerabilityChainEngine
from .explainable_ai import get_explainable_engine, ExplainableAIEngine
from .continuous_learning import get_learning_engine, get_zeroday_engine
from .campaign_intelligence import get_campaign_engine, CampaignIntelligenceEngine

# New V3 Intelligence modules
from .surface_web_intel import (
    SurfaceWebIntelligence,
    get_surface_intel,
    VulnerabilityInfo,
    IntelResult
)
from .dark_web_intel import (
    DarkWebIntelligence,
    get_dark_web_intel,
    BreachInfo,
    DarkWebResult
)
from .unified_intel import (
    UnifiedIntelligence,
    get_unified_intel,
    ThreatAssessment,
    search_intelligence_sync
)

__all__ = [
    'get_optimus_brain',
    'OptimusBrain', 
    'OptimusConfig',
    'get_memory_system',
    'SmartMemorySystem',
    'get_web_intelligence',
    'WebIntelligenceEngine',
    'get_agent_coordinator',
    'AgentCoordinator',
    'get_adaptive_engine',
    'RealTimeAdaptiveEngine',
    'get_chain_engine',
    'VulnerabilityChainEngine',
    'get_explainable_engine',
    'ExplainableAIEngine',
    'get_learning_engine',
    'get_zeroday_engine',
    'get_campaign_engine',
    'CampaignIntelligenceEngine',
    # V3 Intelligence
    'SurfaceWebIntelligence',
    'get_surface_intel',
    'VulnerabilityInfo',
    'IntelResult',
    'DarkWebIntelligence',
    'get_dark_web_intel',
    'BreachInfo',
    'DarkWebResult',
    'UnifiedIntelligence',
    'get_unified_intel',
    'ThreatAssessment',
    'search_intelligence_sync'
]
