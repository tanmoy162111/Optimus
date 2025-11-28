"""
Phase-Aware Tool Selector - Recommends tools based on context and ML/RL/Phase-Specific Models
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from typing import Dict, List, Any
from config import Config
import logging
from .rule_based_tool_selector import RuleBasedToolSelector

# Import phase-specific models
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'training'))
    from phase_specific_models import PhaseSpecificToolSelector as PSToolSelector
    PHASE_SPECIFIC_MODELS_AVAILABLE = True
except ImportError as e:
    PHASE_SPECIFIC_MODELS_AVAILABLE = False
    logger_import = logging.getLogger(__name__)
    logger_import.warning(f"Phase-specific models not available: {e}")

logger = logging.getLogger(__name__)

class PhaseAwareToolSelector:
    """Intelligent tool selection using ML/RL and phase-specific models"""
    
    def __init__(self):
        self.phase_configs = self._load_phase_configs()
        self.all_tools = self._get_all_tools()
        
        # Placeholders for ML/RL components (loaded separately)
        self.tool_recommender_ml = None
        self.rl_agent = None
        self.rl_state_encoder = None
        
        # Add rule-based fallback
        self.rule_selector = RuleBasedToolSelector()
        self.use_hybrid = True  # Enable hybrid mode
        self.ml_confidence_threshold = 0.5
        
        # Initialize phase-specific models (if available)
        self.phase_specific_selector = None
        self.use_phase_specific = True
        if PHASE_SPECIFIC_MODELS_AVAILABLE:
            try:
                self.phase_specific_selector = PSToolSelector()
                logger.info("✅ Phase-specific models loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load phase-specific models: {e}")
                self.use_phase_specific = False
        else:
            logger.info("Phase-specific models not available, using fallback methods")
        
    def recommend_tools(self, scan_state: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced recommendation with better context awareness"""
        phase = scan_state.get('phase', 'reconnaissance')
        findings = scan_state.get('findings', [])
        tools_executed = [t['tool'] if isinstance(t, dict) else t 
                          for t in scan_state.get('tools_executed', [])]

        # Extract what we know about the target
        scan_state['target_type'] = scan_state.get('target_type', 'web')
        scan_state['recently_used_tools'] = tools_executed[-3:] if len(tools_executed) > 3 else tools_executed

        # Use phase-specific models first (Tier 1)
        if self.use_phase_specific and self.phase_specific_selector:
            try:
                ps_result = self.phase_specific_selector.recommend_tools(scan_state)
                
                if not ps_result.get('error') and ps_result.get('confidence', 0) >= 0.7:
                    logger.info(f"Using phase-specific model: {ps_result['tools'][:3]}")
                    
                    # Combine with rule-based enhancements
                    rule_tools = self.apply_phase_rules(scan_state, phase)
                    final_tools = rule_tools + [t for t in ps_result['tools'] if t not in rule_tools]
                    
                    return {
                        'tools': final_tools[:5],
                        'phase': phase,
                        'method': 'phase_specific_ml',
                        'ml_confidence': ps_result.get('confidence', 0.0),
                        'reasoning': f"Phase-specific {phase} model with rule enhancements"
                    }
            except Exception as e:
                logger.warning(f"Phase-specific model failed: {e}")

        # Fall back to rule-based (Tier 3) - ALWAYS RELIABLE
        if self.use_hybrid:
            logger.info(f"Using rule-based selector for {phase}")
            rule_tools = self.rule_selector.recommend_tools(scan_state)
            reasoning = self.rule_selector.get_reasoning(scan_state, rule_tools)
            
            return {
                'tools': rule_tools[:5],
                'phase': phase,
                'method': 'rule_based',
                'ml_confidence': 0.8,  # High confidence in rules
                'reasoning': reasoning
            }

    def apply_phase_rules(self, state: Dict[str, Any], phase: str) -> List[str]:
        """
        Apply rule-based tool selection for phase
        Returns: List of tools to execute
        """
        rule_tools = []
        
        if phase == 'reconnaissance':
            # Always start with subdomain enumeration
            if len(state.get('tools_executed', [])) == 0:
                rule_tools.append('sublist3r')
            
            # If no technologies detected, use whatweb
            if state.get('phase_data', {}).get('technologies', 0) == 0:
                rule_tools.append('whatweb')
        
        elif phase == 'scanning':
            # Always start with nmap for port scanning
            if 'nmap' not in state.get('tools_executed', []):
                rule_tools.append('nmap')
            
            # If web app detected, use web vuln scanners
            if state.get('target_type') == 'web_app':
                if 'nikto' not in state.get('tools_executed', []):
                    rule_tools.append('nikto')
        
        elif phase == 'exploitation':
            # If SQL injection detected, use sqlmap
            sql_detected = any(v.get('type') == 'sql_injection' for v in state.get('findings', []))
            if sql_detected and 'sqlmap' not in state.get('tools_executed', []):
                rule_tools.append('sqlmap')
            
            # If XSS detected, use specific XSS tools
            xss_detected = any(v.get('type') == 'xss' for v in state.get('findings', []))
            if xss_detected:
                rule_tools.append('dalfox')
        
        elif phase == 'post_exploitation':
            # If access gained, escalate privileges
            if state.get('phase_data', {}).get('access_gained'):
                rule_tools.append('linpeas')
        
        elif phase == 'covering_tracks':
            # Clean up logs
            rule_tools.append('clear_logs')
        
        return rule_tools
    
    def extract_phase_features(self, scan_state: Dict[str, Any]) -> List[float]:
        """Extract features for ML tool recommendation"""
        features = []
        
        # Phase encoding (one-hot)
        phases = ['reconnaissance', 'scanning', 'exploitation', 'post_exploitation', 'covering_tracks']
        for p in phases:
            features.append(1.0 if scan_state.get('phase') == p else 0.0)
        
        # State features
        features.append(len(scan_state.get('findings', [])) / 20.0)  # Normalize
        features.append(self._get_highest_severity(scan_state.get('findings', [])) / 10.0)
        features.append(scan_state.get('time_elapsed', 0) / 3600.0)
        features.append(scan_state.get('coverage', 0.0))
        features.append(scan_state.get('ml_confidence', 0.5))
        
        return features
    
    def merge_ml_rl(self, ml_tools: Dict[str, float], rl_tool: str) -> List[str]:
        """
        Merge ML probabilities with RL selection
        Returns: Ordered list of tools
        """
        # Sort ML tools by probability
        sorted_ml_tools = sorted(ml_tools.items(), key=lambda x: x[1], reverse=True)
        
        # Put RL selected tool first (if present)
        result = []
        if rl_tool and rl_tool in ml_tools:
            result.append(rl_tool)
        
        # Add other ML tools
        for tool, prob in sorted_ml_tools:
            if tool not in result:
                result.append(tool)
        
        return result
    
    def generate_reasoning(self, phase: str, ml_tools: Dict[str, float], 
                          rl_tool: str, rule_tools: List[str]) -> str:
        """Generate human-readable reasoning for tool selection"""
        parts = []
        
        if rule_tools:
            parts.append(f"Rule-based: {', '.join(rule_tools)}")
        
        if ml_tools:
            top_ml = sorted(ml_tools.items(), key=lambda x: x[1], reverse=True)[:2]
            ml_str = ', '.join([f"{t} ({p:.2f})" for t, p in top_ml])
            parts.append(f"ML recommendations: {ml_str}")
        
        if rl_tool:
            parts.append(f"RL selected: {rl_tool}")
        
        return "; ".join(parts) if parts else f"Default tools for {phase}"
    
    def _load_phase_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load phase-specific configurations"""
        return {
            'reconnaissance': {
                'allowed_tools': ['sublist3r', 'theHarvester', 'shodan', 'dnsenum', 
                                'fierce', 'whatweb', 'builtwith'],
                'default_tools': ['sublist3r', 'whatweb'],
                'ml_confidence_threshold': 0.6,
                'max_tools_per_iteration': 3
            },
            'scanning': {
                'allowed_tools': ['nmap', 'masscan', 'nuclei', 'nikto', 'nessus', 
                                'unicornscan', 'enum4linux'],
                'default_tools': ['nmap', 'nikto'],
                'ml_confidence_threshold': 0.7,
                'max_tools_per_iteration': 4
            },
            'exploitation': {
                'allowed_tools': ['sqlmap', 'metasploit', 'dalfox', 'commix', 
                                'xsser', 'hydra', 'medusa'],
                'default_tools': ['sqlmap'],
                'ml_confidence_threshold': 0.8,
                'max_tools_per_iteration': 2
            },
            'post_exploitation': {
                'allowed_tools': ['linpeas', 'winpeas', 'mimikatz', 'lazagne', 
                                'crackmapexec', 'psexec'],
                'default_tools': ['linpeas'],
                'ml_confidence_threshold': 0.7,
                'max_tools_per_iteration': 3
            },
            'covering_tracks': {
                'allowed_tools': ['clear_logs', 'wevtutil', 'shred', 'timestomp'],
                'default_tools': ['clear_logs'],
                'ml_confidence_threshold': 0.6,
                'max_tools_per_iteration': 2
            }
        }
    
    def _get_all_tools(self) -> List[str]:
        """Get list of all available tools"""
        all_tools = set()
        for phase_config in self.phase_configs.values():
            all_tools.update(phase_config.get('allowed_tools', []))
        return list(all_tools)
    
    def _get_ml_recommendations(self, features: List[float], phase_config: Dict[str, Any]) -> Dict[str, float]:
        """Get ML tool recommendations (placeholder for actual ML model)"""
        # This would use the trained tool_recommender model
        # For now, return empty dict (will be populated when ML model is integrated)
        return {}
    
    def _get_highest_severity(self, findings: List[Dict[str, Any]]) -> float:
        """Get highest severity from findings"""
        if not findings:
            return 0.0
        return max(f.get('severity', 0.0) for f in findings)
    
    def set_ml_model(self, model):
        """Set ML tool recommender model"""
        self.tool_recommender_ml = model
    
    def set_rl_agent(self, agent, state_encoder):
        """Set RL agent and state encoder"""
        self.rl_agent = agent
        self.rl_state_encoder = state_encoder