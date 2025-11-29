"""
Real-time Learning Module - Learns from scan executions to improve future performance
"""
import logging
from typing import Dict, Any, List
from collections import defaultdict

logger = logging.getLogger(__name__)

class RealTimeLearningModule:
    """Learns from scan executions to improve future performance"""
    
    def __init__(self):
        self.execution_history = defaultdict(list)
        self.tool_effectiveness = defaultdict(lambda: {'success_count': 0, 'total_count': 0, 'findings': 0})
        self.patterns = {}
    
    def learn_from_execution(self, tool_name: str, result: Dict[str, Any], scan_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Learn from a tool execution result
        
        Args:
            tool_name: Name of the tool executed
            result: Tool execution result
            scan_state: Current scan state
            
        Returns:
            Dictionary with learning insights
        """
        try:
            # Validate inputs
            if result is None:
                result = {}
            if scan_state is None:
                scan_state = {}
                
            # Record execution
            execution_record = {
                'tool': tool_name,
                'success': result.get('success', False) if result else False,
                'execution_time': result.get('execution_time', 0) if result else 0,
                'findings_count': len(result.get('parsed_results', {}).get('vulnerabilities', [])) if result else 0,
                'timestamp': result.get('end_time') if result else None
            }
            
            self.execution_history[tool_name].append(execution_record)
            
            # Update tool effectiveness metrics
            self.tool_effectiveness[tool_name]['total_count'] += 1
            if result.get('success', False) if result else False:
                self.tool_effectiveness[tool_name]['success_count'] += 1
            self.tool_effectiveness[tool_name]['findings'] += execution_record['findings_count']
            
            # Keep only last 50 executions to prevent memory bloat
            if len(self.execution_history[tool_name]) > 50:
                self.execution_history[tool_name] = self.execution_history[tool_name][-50:]
                
            logger.info(f"[LearningModule] Learned from {tool_name} execution: {execution_record['findings_count']} findings")
            
            # Return insights
            return {
                'tool': tool_name,
                'success': result.get('success', False) if result else False,
                'findings_count': execution_record['findings_count'],
                'recommendations': []
            }
            
        except Exception as e:
            logger.error(f"[LearningModule] Error learning from execution: {e}")
            # Return empty insights on error
            return {
                'tool': tool_name,
                'success': False,
                'findings_count': 0,
                'recommendations': []
            }
    
    def get_tool_effectiveness(self, tool_name: str) -> float:
        """
        Get effectiveness score for a tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Effectiveness score (0.0 to 1.0)
        """
        stats = self.tool_effectiveness[tool_name]
        if stats['total_count'] == 0:
            return 0.0
            
        # Calculate effectiveness as a combination of success rate and findings per execution
        success_rate = stats['success_count'] / stats['total_count']
        avg_findings = stats['findings'] / max(stats['total_count'], 1)
        
        # Weighted score (70% success rate, 30% findings)
        effectiveness = (success_rate * 0.7) + (min(avg_findings / 10.0, 1.0) * 0.3)
        return effectiveness
    
    def get_effective_tools(self, phase: str = None) -> List[str]:
        """
        Get list of effective tools based on learning
        
        Args:
            phase: Current scan phase (optional)
            
        Returns:
            List of effective tool names
        """
        # Get tools with effectiveness > 0.5
        effective_tools = []
        for tool_name, stats in self.tool_effectiveness.items():
            if self.get_tool_effectiveness(tool_name) > 0.5:
                effective_tools.append(tool_name)
                
        return effective_tools if effective_tools else ['nmap']  # Fallback to nmap
    
    def identify_patterns(self, scan_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identify patterns from scan execution data
        
        Args:
            scan_state: Current scan state
            
        Returns:
            Dictionary of identified patterns
        """
        # Validate input
        if scan_state is None:
            scan_state = {}
            
        patterns = {}
        
        # Tool effectiveness pattern
        tool_scores = {}
        for tool_name in self.tool_effectiveness:
            tool_scores[tool_name] = self.get_tool_effectiveness(tool_name)
            
        patterns['tool_effectiveness'] = tool_scores
        
        # Finding patterns
        total_findings = len(scan_state.get('findings', [])) if scan_state else 0
        patterns['total_findings'] = total_findings
        
        # Phase progression pattern
        patterns['current_phase'] = scan_state.get('phase', 'unknown') if scan_state else 'unknown'
        
        return patterns
    
    def should_recommend_tool(self, tool_name: str, target_profile: Dict[str, Any]) -> bool:
        """
        Determine if a tool should be recommended based on learning
        
        Args:
            tool_name: Name of the tool
            target_profile: Target profile information
            
        Returns:
            Boolean indicating if tool should be recommended
        """
        # Always recommend if we have no data
        if self.tool_effectiveness[tool_name]['total_count'] == 0:
            return True
            
        # Recommend if tool is effective
        return self.get_tool_effectiveness(tool_name) > 0.3
    
    def should_try_different_approach(self, scan_state: Dict[str, Any]) -> bool:
        """
        Determine if we should try a different approach based on learning
        
        Args:
            scan_state: Current scan state
            
        Returns:
            Boolean indicating if we should try a different approach
        """
        # Validate input
        if scan_state is None:
            return False
            
        # If we haven't found anything in a while, try a different approach
        last_finding = scan_state.get('last_finding_iteration', 0) if scan_state else 0
        tools_executed = len(scan_state.get('tools_executed', [])) if scan_state else 0
        
        # If we've executed 5 tools since last finding, consider changing approach
        if tools_executed - last_finding > 5:
            return True
            
        # If we're stuck in the same phase with low coverage
        coverage = scan_state.get('coverage', 0.0) if scan_state else 0.0
        if coverage < 0.3 and tools_executed > 10:
            return True
            
        return False

# For backwards compatibility
AdaptiveLearningModule = RealTimeLearningModule