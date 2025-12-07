"""
Real-time Learning Module - Learns from scan executions to improve future performance
"""
import logging
from typing import Dict, Any, List
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

class RealTimeLearningModule:
    """Learns from scan executions to improve future performance"""
    
    def __init__(self):
        self.execution_history = defaultdict(list)
        self.tool_effectiveness = defaultdict(lambda: {'success_count': 0, 'total_count': 0, 'findings': 0})
        self.patterns = {}
        # Add context-aware effectiveness tracking
        self.context_effectiveness = defaultdict(dict)
        # Add phase effectiveness tracking
        self.phase_stats = defaultdict(lambda: {
            'total_executions': 0,
            'total_findings': 0,
            'recent_findings': [],  # Last 10 findings timestamps
        })
    
    def get_phase_effectiveness(self, phase: str) -> Dict:
        """Get effectiveness metrics for a phase."""
        stats = self.phase_stats[phase]
        
        # Calculate recent findings rate (findings in last 5 executions)
        recent_count = len([f for f in stats['recent_findings'][-5:]])
        recent_rate = recent_count / 5.0 if stats['total_executions'] >= 5 else 0.5
        
        return {
            'total_executions': stats['total_executions'],
            'total_findings': stats['total_findings'],
            'recent_findings_rate': recent_rate,
            'avg_findings': stats['total_findings'] / max(1, stats['total_executions'])
        }

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
            
            # Track phase stats
            phase = scan_state.get('phase', 'unknown')
            findings_count = execution_record['findings_count']
            
            self.phase_stats[phase]['total_executions'] += 1
            self.phase_stats[phase]['total_findings'] += findings_count
            
            if findings_count > 0:
                self.phase_stats[phase]['recent_findings'].append(datetime.now().isoformat())
                # Keep only last 20
                self.phase_stats[phase]['recent_findings'] = self.phase_stats[phase]['recent_findings'][-20:]
            
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
    
    def learn_from_live_execution(self, tool_name: str, context: Dict, execution_result: Dict, ground_truth: Dict = None) -> Dict:
        """
        Learn from actual tool execution against live target
        
        Args:
            tool_name: Tool executed
            context: Scan context (phase, target_type, etc.)
            execution_result: Actual execution results from ToolManager
            ground_truth: Known vulnerabilities for validation (optional)
            
        Learning updates:
        1. Tool effectiveness in this context
        2. Time patterns (when tool is fast/slow)
        3. Finding patterns (what types of vulns found)
        4. Parameter effectiveness (which options worked)
        
        Returns:
            Learning insights and recommendations
        """
        # Extract metrics from execution
        execution_time = execution_result.get('execution_time', 0)
        success = execution_result.get('success', False)
        findings = execution_result.get('parsed_results', {}).get('vulnerabilities', [])
        
        # Update tool effectiveness tracking
        context_key = self._create_context_key(context)
        
        if context_key not in self.context_effectiveness:
            self.context_effectiveness[context_key] = defaultdict(lambda: {
                'executions': 0,
                'successes': 0,
                'total_findings': 0,
                'avg_time': 0.0
            })
        
        stats = self.context_effectiveness[context_key][tool_name]
        stats['executions'] += 1
        if success:
            stats['successes'] += 1
        stats['total_findings'] += len(findings)
        stats['avg_time'] = (stats['avg_time'] * (stats['executions'] - 1) + execution_time) / stats['executions']
        
        # Calculate effectiveness score
        effectiveness = self._calculate_contextual_effectiveness(stats)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            tool_name, context, effectiveness, findings
        )
        
        return {
            'effectiveness_score': effectiveness,
            'recommendations': recommendations,
            'should_continue': effectiveness > 0.3,
            'alternative_tools': self._suggest_alternatives(context, effectiveness)
        }
    
    def _create_context_key(self, context: Dict) -> str:
        """Create hashable context key for tracking"""
        return f"{context.get('phase', 'unknown')}_{context.get('target_type', 'unknown')}"
    
    def _calculate_contextual_effectiveness(self, stats: Dict) -> float:
        """Calculate tool effectiveness in specific context"""
        if stats['executions'] == 0:
            return 0.5  # Neutral for untried tools
            
        success_rate = stats['successes'] / stats['executions']
        findings_rate = stats['total_findings'] / stats['executions']
        
        # Combine metrics
        effectiveness = (success_rate * 0.4) + (min(findings_rate / 5.0, 1.0) * 0.6)
        return effectiveness
    
    def _generate_recommendations(self, tool_name: str, context: Dict, effectiveness: float, findings: List) -> List[str]:
        """Generate actionable recommendations based on execution"""
        recommendations = []
        
        if effectiveness < 0.3:
            recommendations.append(f"Consider replacing {tool_name} - low effectiveness in {context['phase']}")
        
        if len(findings) == 0 and context.get('expected_findings', 0) > 0:
            recommendations.append(f"{tool_name} missed expected findings - check parameters")
        
        if effectiveness > 0.7:
            recommendations.append(f"{tool_name} highly effective in {context['phase']} - prioritize")
        
        return recommendations
    
    def _suggest_alternatives(self, context: Dict, effectiveness: float) -> List[str]:
        """Suggest alternative tools based on context and effectiveness"""
        # This would be enhanced with actual tool database
        alternatives = []
        
        phase = context.get('phase', 'reconnaissance')
        if phase == 'reconnaissance':
            alternatives = ['amass', 'sublist3r', 'theHarvester']
        elif phase == 'scanning':
            alternatives = ['nmap', 'nikto', 'nuclei']
        elif phase == 'exploitation':
            alternatives = ['sqlmap', 'dalfox', 'commix']
        
        return alternatives[:3]  # Return top 3 alternatives
    
    def get_best_tools_for_context(self, context: Dict, top_n: int = 3) -> List[str]:
        """Get best performing tools for given context"""
        context_key = self._create_context_key(context)
        
        if context_key not in self.context_effectiveness:
            return []  # No data yet
            
        # Sort tools by effectiveness
        tools_effectiveness = []
        for tool, stats in self.context_effectiveness[context_key].items():
            effectiveness = self._calculate_contextual_effectiveness(stats)
            tools_effectiveness.append((tool, effectiveness))
            
        tools_effectiveness.sort(key=lambda x: x[1], reverse=True)
        
        return [tool for tool, _ in tools_effectiveness[:top_n]]
    
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