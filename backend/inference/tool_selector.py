"""
Phase-Aware Tool Selector - Recommends tools based on context and ML/RL
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from typing import Dict, List, Any
from config import Config
import logging

logger = logging.getLogger(__name__)

class PhaseAwareToolSelector:
    """Intelligent tool selection using ML/RL and rules"""
    
    def __init__(self):
        self.phase_configs = self._load_phase_configs()
        self.all_tools = self._get_all_tools()
        
        # Placeholders for ML/RL components (loaded separately)
        self.tool_recommender_ml = None
        self.rl_agent = None
        self.rl_state_encoder = None
        
    def recommend_tools(self, scan_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recommend tools for current scan state
        Returns: {'tools': [...], 'phase': str, 'ml_confidence': float, 'reasoning': str}
        """
        phase = scan_state.get('phase', 'reconnaissance')
        phase_config = self.phase_configs.get(phase, {})
        
        # 1. Apply phase-based rules (always execute first)
        rule_tools = self.apply_phase_rules(scan_state, phase)
        
        # 2. Get ML recommendations (if ML model loaded)
        ml_tools_filtered = {}
        ml_confidence = 0.5
        
        if self.tool_recommender_ml:
            try:
                features = self.extract_phase_features(scan_state)
                ml_tools_filtered = self._get_ml_recommendations(features, phase_config)
                ml_confidence = max(ml_tools_filtered.values()) if ml_tools_filtered else 0.5
            except Exception as e:
                logger.warning(f"ML recommendation failed: {e}")
        
        # 3. Get RL selection (if RL agent loaded)
        rl_tool = None
        if self.rl_agent and self.rl_state_encoder:
            try:
                rl_state_dict = self.rl_state_encoder.encode_state(scan_state)
                rl_state_vector = self.rl_state_encoder.state_to_vector(rl_state_dict)
                available = list(ml_tools_filtered.keys()) if ml_tools_filtered else phase_config.get('default_tools', [])
                rl_tool = self.rl_agent.select_action(rl_state_vector, available, epsilon=0.1)
            except Exception as e:
                logger.warning(f"RL selection failed: {e}")
        
        # 4. Merge recommendations
        threshold = phase_config.get('ml_confidence_threshold', 0.6)
        
        if ml_confidence > threshold and ml_tools_filtered:
            recommended = self.merge_ml_rl(ml_tools_filtered, rl_tool)
        else:
            # Fall back to default tools for phase
            recommended = phase_config.get('default_tools', ['nmap'])
        
        # 5. Combine with rule-based tools (rules have priority)
        final_tools = rule_tools + [t for t in recommended if t not in rule_tools]
        
        # Limit to top 5 tools
        final_tools = final_tools[:5]
        
        return {
            'tools': final_tools,
            'phase': phase,
            'ml_confidence': ml_confidence,
            'rl_selected': rl_tool,
            'reasoning': self.generate_reasoning(phase, ml_tools_filtered, rl_tool, rule_tools)
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
