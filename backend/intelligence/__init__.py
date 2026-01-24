"""Intelligence Package for Optimus Penetration Testing Agent

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

NOTE: All imports are lazy to prevent cascading failures when optional
dependencies (numpy, requests, etc.) are missing.
"""

import logging

logger = logging.getLogger(__name__)

# Lazy import helpers - these return None if dependencies are missing
def _safe_import(module_path, class_names):
    """Safely import from a module, returning None for missing dependencies"""
    try:
        module = __import__(f'intelligence.{module_path}', fromlist=class_names)
        return tuple(getattr(module, name, None) for name in class_names)
    except ImportError as e:
        logger.debug(f"Optional import failed for {module_path}: {e}")
        return tuple(None for _ in class_names)
    except Exception as e:
        logger.warning(f"Unexpected error importing {module_path}: {e}")
        return tuple(None for _ in class_names)

# Lazy-loaded module references (populated on first access)
_lazy_modules = {}

def _get_lazy(module_path, class_name):
    """Get a lazily-loaded class/function"""
    key = f"{module_path}.{class_name}"
    if key not in _lazy_modules:
        try:
            module = __import__(f'intelligence.{module_path}', fromlist=[class_name])
            _lazy_modules[key] = getattr(module, class_name, None)
        except ImportError as e:
            logger.debug(f"Lazy import failed for {key}: {e}")
            _lazy_modules[key] = None
        except Exception as e:
            logger.warning(f"Unexpected error in lazy import {key}: {e}")
            _lazy_modules[key] = None
    return _lazy_modules[key]

# Factory functions for lazy loading
def get_optimus_brain(*args, **kwargs):
    func = _get_lazy('optimus_brain', 'get_optimus_brain')
    return func(*args, **kwargs) if func else None

def get_memory_system(*args, **kwargs):
    func = _get_lazy('memory_system', 'get_memory_system')
    return func(*args, **kwargs) if func else None

def get_web_intelligence(*args, **kwargs):
    func = _get_lazy('web_intelligence', 'get_web_intelligence')
    return func(*args, **kwargs) if func else None

def get_agent_coordinator(*args, **kwargs):
    func = _get_lazy('delegation_system', 'get_agent_coordinator')
    return func(*args, **kwargs) if func else None

def get_adaptive_engine(*args, **kwargs):
    func = _get_lazy('adaptive_exploitation', 'get_adaptive_engine')
    return func(*args, **kwargs) if func else None

def get_chain_engine(*args, **kwargs):
    func = _get_lazy('vulnerability_chaining', 'get_chain_engine')
    return func(*args, **kwargs) if func else None

def get_explainable_engine(*args, **kwargs):
    func = _get_lazy('explainable_ai', 'get_explainable_engine')
    return func(*args, **kwargs) if func else None

def get_learning_engine(*args, **kwargs):
    func = _get_lazy('continuous_learning', 'get_learning_engine')
    return func(*args, **kwargs) if func else None

def get_zeroday_engine(*args, **kwargs):
    func = _get_lazy('continuous_learning', 'get_zeroday_engine')
    return func(*args, **kwargs) if func else None

def get_campaign_engine(*args, **kwargs):
    func = _get_lazy('campaign_intelligence', 'get_campaign_engine')
    return func(*args, **kwargs) if func else None

def get_surface_intel(*args, **kwargs):
    func = _get_lazy('surface_web_intel', 'get_surface_intel')
    return func(*args, **kwargs) if func else None

def get_dark_web_intel(*args, **kwargs):
    func = _get_lazy('dark_web_intel', 'get_dark_web_intel')
    return func(*args, **kwargs) if func else None

def get_unified_intel(*args, **kwargs):
    func = _get_lazy('unified_intel', 'get_unified_intel')
    return func(*args, **kwargs) if func else None

def search_intelligence_sync(*args, **kwargs):
    func = _get_lazy('unified_intel', 'search_intelligence_sync')
    return func(*args, **kwargs) if func else None

# Class references (lazy property pattern)
class _LazyClass:
    """Lazy class loader that returns the actual class on attribute access"""
    def __init__(self, module_path, class_name):
        self._module_path = module_path
        self._class_name = class_name
        self._class = None
    
    def _load(self):
        if self._class is None:
            self._class = _get_lazy(self._module_path, self._class_name)
        return self._class
    
    def __call__(self, *args, **kwargs):
        cls = self._load()
        if cls:
            return cls(*args, **kwargs)
        raise ImportError(f"Could not load {self._module_path}.{self._class_name}")
    
    def __getattr__(self, name):
        cls = self._load()
        if cls:
            return getattr(cls, name)
        raise ImportError(f"Could not load {self._module_path}.{self._class_name}")

# Lazy class references
OptimusBrain = _LazyClass('optimus_brain', 'OptimusBrain')
OptimusConfig = _LazyClass('optimus_brain', 'OptimusConfig')
SmartMemorySystem = _LazyClass('memory_system', 'SmartMemorySystem')
WebIntelligenceEngine = _LazyClass('web_intelligence', 'WebIntelligenceEngine')
AgentCoordinator = _LazyClass('delegation_system', 'AgentCoordinator')
RealTimeAdaptiveEngine = _LazyClass('adaptive_exploitation', 'RealTimeAdaptiveEngine')
VulnerabilityChainEngine = _LazyClass('vulnerability_chaining', 'VulnerabilityChainEngine')
ExplainableAIEngine = _LazyClass('explainable_ai', 'ExplainableAIEngine')
CampaignIntelligenceEngine = _LazyClass('campaign_intelligence', 'CampaignIntelligenceEngine')
SurfaceWebIntelligence = _LazyClass('surface_web_intel', 'SurfaceWebIntelligence')
VulnerabilityInfo = _LazyClass('surface_web_intel', 'VulnerabilityInfo')
IntelResult = _LazyClass('surface_web_intel', 'IntelResult')
DarkWebIntelligence = _LazyClass('dark_web_intel', 'DarkWebIntelligence')
BreachInfo = _LazyClass('dark_web_intel', 'BreachInfo')
DarkWebResult = _LazyClass('dark_web_intel', 'DarkWebResult')
UnifiedIntelligence = _LazyClass('unified_intel', 'UnifiedIntelligence')
ThreatAssessment = _LazyClass('unified_intel', 'ThreatAssessment')

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
