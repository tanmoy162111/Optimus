"""
Strategy Selector - Selects optimal scanning strategies based on target profile and findings
"""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class StrategySelector:
    """Selects optimal scanning strategies based on target profile and current findings"""
    
    def __init__(self):
        self.strategies = {
            'adaptive': {
                'description': 'Adaptive strategy that changes based on findings',
                'tools': ['nmap', 'nikto', 'whatweb']
            },
            'aggressive': {
                'description': 'Aggressive scanning with all available tools',
                'tools': ['nmap', 'nikto', 'sqlmap', 'gobuster', 'ffuf', 'nuclei']
            },
            'stealth': {
                'description': 'Stealth scanning with slower, less detectable tools',
                'tools': ['nmap', 'whatweb']
            },
            'comprehensive': {
                'description': 'Comprehensive scanning with maximum coverage',
                'tools': ['nmap', 'nikto', 'sqlmap', 'gobuster', 'ffuf', 'nuclei', 'wpscan', 'sslscan']
            }
        }
    
    def select_strategy(self, scan_state: Dict[str, Any]) -> str:
        """
        Select the optimal strategy based on scan state
        
        Args:
            scan_state: Current scan state dictionary
            
        Returns:
            Strategy name
        """
        # Validate input
        if scan_state is None:
            return 'adaptive'
            
        # Start with adaptive strategy
        if not scan_state.get('strategy'):
            return 'adaptive'
        
        # Change strategy based on findings and progress
        findings = scan_state.get('findings', [])
        phase = scan_state.get('phase', 'reconnaissance')
        
        # If we have many findings, be more aggressive
        if len(findings) > 10:
            return 'aggressive'
        
        # If we're in exploitation phase, be aggressive
        if phase in ['exploitation', 'post_exploitation']:
            return 'aggressive'
        
        # Default to current strategy
        return scan_state.get('strategy', 'adaptive')
    
    def should_change_strategy(self, scan_state: Dict[str, Any]) -> bool:
        """
        Determine if strategy should be changed based on scan state
        
        Args:
            scan_state: Current scan state dictionary
            
        Returns:
            Boolean indicating if strategy should change
        """
        # Validate input
        if scan_state is None:
            return False
            
        # Change strategy if we haven't found anything in a while
        last_finding = scan_state.get('last_finding_iteration', 0)
        tools_executed = len(scan_state.get('tools_executed', []))
        
        # If we've executed 5 tools since last finding, consider changing strategy
        if tools_executed - last_finding > 5:
            return True
            
        # Change strategy if we're stuck in the same phase
        strategy_changes = scan_state.get('strategy_changes', 0)
        if strategy_changes < 3:  # Allow up to 3 strategy changes
            return True
            
        return False
    
    def get_strategy_tools(self, strategy: str) -> list:
        """
        Get tools recommended for a specific strategy
        
        Args:
            strategy: Strategy name
            
        Returns:
            List of recommended tools
        """
        return self.strategies.get(strategy, {}).get('tools', ['nmap'])

# For backwards compatibility
AdaptiveStrategySelector = StrategySelector