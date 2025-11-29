"""
Target Analyzer - Analyzes targets to determine optimal scanning strategies
"""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class TargetAnalyzer:
    """Analyzes targets to build profiles for intelligent scanning"""
    
    def analyze_target(self, target: str) -> Dict[str, Any]:
        """
        Analyze a target and return a profile
        
        Args:
            target: Target URL/IP
            
        Returns:
            Dictionary with target profile information
        """
        logger.info(f"[TargetAnalyzer] Analyzing target: {target}")
        
        # Simple target analysis based on URL patterns
        profile = {
            'target': target,
            'type': self._determine_target_type(target),
            'technologies': self._identify_technologies(target),
            'risk_level': self._assess_risk_level(target),
            'scan_strategy': self._recommend_strategy(target)
        }
        
        logger.info(f"[TargetAnalyzer] Target profile: {profile}")
        return profile
    
    def _determine_target_type(self, target: str) -> str:
        """Determine target type based on URL"""
        if 'http' in target:
            return 'web'
        elif ':' in target and '.' in target:
            return 'network'
        else:
            return 'unknown'
    
    def _identify_technologies(self, target: str) -> list:
        """Identify likely technologies based on target"""
        technologies = []
        
        # Simple heuristics based on common patterns
        if 'http' in target:
            technologies.extend(['http_server', 'web_framework'])
            
        if '.php' in target or 'php' in target.lower():
            technologies.append('php')
        elif '.asp' in target or '.aspx' in target:
            technologies.append('asp_net')
        elif '.jsp' in target:
            technologies.append('java')
        elif '.py' in target:
            technologies.append('python')
            
        return technologies
    
    def _assess_risk_level(self, target: str) -> str:
        """Assess risk level of target"""
        # For training purposes, we'll use a moderate risk level
        return 'medium'
    
    def _recommend_strategy(self, target: str) -> str:
        """Recommend scanning strategy based on target"""
        target_type = self._determine_target_type(target)
        
        if target_type == 'web':
            return 'web_application'
        elif target_type == 'network':
            return 'network_scanning'
        else:
            return 'comprehensive'

# For backwards compatibility
TargetProfileAnalyzer = TargetAnalyzer