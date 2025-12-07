"""
Strategy Selector - Selects optimal scanning strategies based on target profile and findings
"""
import logging
from typing import Dict, Any, List
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

class StrategySelector:
    """Selects optimal scanning strategies based on target profile and current findings"""
    
    def __init__(self):
        self.strategies = {
            'adaptive': {
                'description': 'Adaptive strategy that changes based on findings',
                'tools': ['nmap', 'nikto', 'whatweb'],
                'success_rate': 0.5,  # Track success
                'avg_findings': 0.0,
                'executions': 0
            },
            'aggressive': {
                'description': 'Aggressive scanning with all available tools',
                'tools': ['nmap', 'nikto', 'sqlmap', 'gobuster', 'ffuf', 'nuclei'],
                'success_rate': 0.5,
                'avg_findings': 0.0,
                'executions': 0
            },
            'stealth': {
                'description': 'Stealth scanning with slower, less detectable tools',
                'tools': ['nmap', 'whatweb'],
                'success_rate': 0.5,
                'avg_findings': 0.0,
                'executions': 0
            },
            'targeted': {
                'description': 'Targeted exploitation based on discovered vulnerabilities',
                'tools': ['sqlmap', 'dalfox', 'commix'],
                'success_rate': 0.5,
                'avg_findings': 0.0,
                'executions': 0
            }
        }
        
        self.strategy_performance_history = defaultdict(list)
    
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
        time_remaining = scan_state.get('time_remaining', 1.0)
        
        # Score each strategy
        strategy_scores = {}
        
        for strategy_name, strategy_data in self.strategies.items():
            score = 0.0
            
            # Base score from learned performance
            if strategy_data['executions'] > 0:
                score += strategy_data['avg_findings'] * 10  # Weight findings heavily
                score += strategy_data['success_rate'] * 5
            else:
                score += 5.0  # Neutral score for untried strategies
            
            # Adjust for phase
            if phase == 'reconnaissance':
                if strategy_name in ['adaptive', 'stealth']:
                    score += 3.0
            elif phase == 'exploitation':
                if strategy_name in ['aggressive', 'targeted']:
                    score += 3.0
                if len(findings) > 0:
                    if strategy_name == 'targeted':
                        score += 5.0  # Highly favor targeted when vulns known
            
            # Adjust for time constraints
            if time_remaining < 0.3:
                if strategy_name == 'aggressive':
                    score += 2.0  # Need results fast
            
            strategy_scores[strategy_name] = score
        
        # Select best strategy
        best_strategy = max(strategy_scores, key=strategy_scores.get)
        
        logger.info(f"Strategy selection: {best_strategy} "
                   f"(scores: {strategy_scores})")
        
        return best_strategy
    
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
    
    def update_strategy_performance(self, strategy: str, success: bool, findings_count: int):
        """Update strategy performance based on execution results."""
        if strategy not in self.strategies:
            return
        
        stats = self.strategies[strategy]
        stats['executions'] += 1
        
        if success:
            stats['success_rate'] = (
                (stats['success_rate'] * (stats['executions'] - 1) + 1.0) / stats['executions']
            )
        else:
            stats['success_rate'] = (
                (stats['success_rate'] * (stats['executions'] - 1)) / stats['executions']
            )
        
        # Update average findings
        total_findings = stats['avg_findings'] * (stats['executions'] - 1) + findings_count
        stats['avg_findings'] = total_findings / stats['executions']
        
        # Record in history
        self.strategy_performance_history[strategy].append({
            'success': success,
            'findings': findings_count,
            'timestamp': datetime.now().isoformat()
        })

    def get_strategy_tool_boost(self, strategy: str, available_tools: List[str]) -> List[str]:
        """
        Return tools that should be prioritized for the current strategy.
        """
        if strategy not in self.strategies:
            return []
        
        strategy_tools = self.strategies[strategy].get('tools', [])
        boosted = [t for t in strategy_tools if t in available_tools]
        
        return boosted

    def get_strategy_report(self) -> Dict[str, Any]:
        """Generate performance report for all strategies"""
        report = {
            'strategies': {},
            'best_overall': None,
            'recommendations': []
        }
        
        best_score = -1
        best_strategy = None
        
        for name, data in self.strategies.items():
            if data['executions'] > 0:
                effectiveness = (data['avg_findings'] * 0.6) + (data['success_rate'] * 0.4)
                report['strategies'][name] = {
                    'executions': data['executions'],
                    'avg_findings': data['avg_findings'],
                    'success_rate': data['success_rate'],
                    'effectiveness_score': effectiveness
                }
                
                if effectiveness > best_score:
                    best_score = effectiveness
                    best_strategy = name
        
        report['best_overall'] = best_strategy
        
        # Generate recommendations
        for name, data in self.strategies.items():
            if data['executions'] > 3:  # Enough data
                if data['success_rate'] < 0.3:
                    report['recommendations'].append(
                        f"Consider tuning {name} strategy - low success rate"
                    )
                
                if data['avg_findings'] < 1.0 and name != 'stealth':
                    report['recommendations'].append(
                        f"{name} strategy finding few vulnerabilities - review tool selection"
                    )
        
        return report

# For backwards compatibility
AdaptiveStrategySelector = StrategySelector