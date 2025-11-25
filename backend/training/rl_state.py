"""
RL State Encoder - Converts scan context to state vectors for RL agent
"""
import numpy as np
from typing import Dict, Any, List

class RLStateEncoder:
    """Encode scan context into state vectors for RL agent"""
    
    def __init__(self):
        self.target_types = ['web_app', 'api', 'network']
        self.phases = ['reconnaissance', 'scanning', 'exploitation', 'post_exploitation', 'covering_tracks']
        self.state_dim = 23
        
    def encode_state(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert scan context to state dictionary
        Returns: {'vector': np.array, 'metadata': dict}
        """
        state_dict = {
            # Target information
            'target_type': scan_context.get('target_type', 'web_app'),
            'target_complexity': scan_context.get('target_complexity', 0.5),
            
            # Current phase
            'phase': scan_context.get('phase', 'reconnaissance'),
            
            # Findings
            'num_vulns_found': len(scan_context.get('findings', [])),
            'highest_severity': self._get_highest_severity(scan_context.get('findings', [])),
            'avg_severity': self._get_avg_severity(scan_context.get('findings', [])),
            'unique_attack_types': len(set(v.get('type', '') for v in scan_context.get('findings', []))),
            'has_critical_vuln': any(v.get('severity', 0) >= 9.0 for v in scan_context.get('findings', [])),
            'has_exploitable_vuln': any(v.get('exploitable', False) for v in scan_context.get('findings', [])),
            
            # Time and resources
            'time_elapsed': scan_context.get('time_elapsed', 0),
            'time_remaining': scan_context.get('time_budget', 3600) - scan_context.get('time_elapsed', 0),
            'num_tools_used': len(scan_context.get('tools_executed', [])),
            
            # ML/AI metrics
            'ml_confidence': scan_context.get('ml_confidence', 0.5),
            'scan_coverage': scan_context.get('coverage', 0.0),
            
            # Attack type flags
            'sql_detected': any(v.get('type') == 'sql_injection' for v in scan_context.get('findings', [])),
            'xss_detected': any(v.get('type') == 'xss' for v in scan_context.get('findings', [])),
            'rce_detected': any(v.get('type') == 'rce' for v in scan_context.get('findings', [])),
        }
        
        return state_dict
    
    def state_to_vector(self, state_dict: Dict[str, Any]) -> np.ndarray:
        """
        Convert state dictionary to numpy vector (24 dimensions)
        """
        vector = []
        
        # Target type (one-hot: 3 dims)
        for ttype in self.target_types:
            vector.append(1.0 if state_dict.get('target_type') == ttype else 0.0)
        
        # Target complexity (1 dim)
        vector.append(float(state_dict.get('target_complexity', 0.5)))
        
        # Phase (one-hot: 5 dims)
        for phase in self.phases:
            vector.append(1.0 if state_dict.get('phase') == phase else 0.0)
        
        # Findings (6 dims)
        vector.append(float(min(state_dict.get('num_vulns_found', 0), 20)) / 20.0)  # Normalize
        vector.append(float(state_dict.get('highest_severity', 0.0)) / 10.0)
        vector.append(float(state_dict.get('avg_severity', 0.0)) / 10.0)
        vector.append(float(min(state_dict.get('unique_attack_types', 0), 10)) / 10.0)
        vector.append(1.0 if state_dict.get('has_critical_vuln') else 0.0)
        vector.append(1.0 if state_dict.get('has_exploitable_vuln') else 0.0)
        
        # Time and resources (3 dims)
        vector.append(float(min(state_dict.get('time_elapsed', 0), 3600)) / 3600.0)
        vector.append(float(max(state_dict.get('time_remaining', 3600), 0)) / 3600.0)
        vector.append(float(min(state_dict.get('num_tools_used', 0), 20)) / 20.0)
        
        # ML metrics (2 dims)
        vector.append(float(state_dict.get('ml_confidence', 0.5)))
        vector.append(float(state_dict.get('scan_coverage', 0.0)))
        
        # Attack flags (3 dims)
        vector.append(1.0 if state_dict.get('sql_detected') else 0.0)
        vector.append(1.0 if state_dict.get('xss_detected') else 0.0)
        vector.append(1.0 if state_dict.get('rce_detected') else 0.0)
        
        return np.array(vector, dtype=np.float32)
    
    def get_state_dimensions(self) -> int:
        """Return state vector dimensions"""
        return self.state_dim
    
    def _get_highest_severity(self, findings: List[Dict[str, Any]]) -> float:
        """Get highest severity from findings"""
        if not findings:
            return 0.0
        return max(f.get('severity', 0.0) for f in findings)
    
    def _get_avg_severity(self, findings: List[Dict[str, Any]]) -> float:
        """Get average severity from findings"""
        if not findings:
            return 0.0
        severities = [f.get('severity', 0.0) for f in findings]
        return sum(severities) / len(severities)
