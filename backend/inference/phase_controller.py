"""Intelligent Phase Controller - Decides when to transition between pentest phases"""
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class PhaseController:
    """Controls phase transitions based on scan progress and findings"""
    
    def __init__(self):
        self.phase_order = [
            'reconnaissance',
            'scanning', 
            'exploitation',
            'post_exploitation',
            'covering_tracks'
        ]
        self.transition_history = []
    
    def should_transition(self, current_state: Dict[str, Any]) -> str:
        """
        Determine if phase should transition based on progress metrics
        
        Args:
            current_state: Current scan state
            
        Returns:
            Next phase name, or current phase if no transition needed
        """
        phase = current_state['phase']
        findings = current_state.get('findings', [])
        tools_executed = current_state.get('tools_executed', [])
        coverage = current_state.get('coverage', 0.0)
        
        # Convert tools_executed to list of tool names if it contains dicts
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_names = [t['tool'] for t in tools_executed]
        else:
            tool_names = tools_executed
        
        print(f"[PhaseController] Checking transition for {phase}")
        print(f"  Tools executed: {len(tool_names)}")
        print(f"  Findings: {len(findings)}")
        print(f"  Coverage: {coverage:.2f}")
        
        # NEW: Check for tool repetition that indicates stuck state
        if len(tool_names) >= 5:
            # Look at last 10 tool executions
            recent_tools = tool_names[-10:] if len(tool_names) >= 10 else tool_names
            tool_counts = {}
            for tool in recent_tools:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
            
            # Check if any tool has been executed 4+ times in recent history
            repetition_count = 0
            most_common = ""
            if tool_counts:
                most_common = max(tool_counts.keys(), key=lambda x: tool_counts[x])
                repetition_count = tool_counts[most_common]
            
            print(f"  Recent tool usage: {tool_counts}")
            
            # If same tool repeated 4+ times in last 10 executions, force transition
            if repetition_count >= 4:
                print(f"[PhaseController] FORCING TRANSITION - {most_common} repeated {repetition_count} times")
                next_phase = self.get_next_phase(phase, current_state)
                return next_phase
        
        # NEW: Check if no progress (0 findings after 10+ tools)
        if len(findings) == 0 and len(tool_names) >= 10:
            print(f"[PhaseController] FORCING TRANSITION - No findings after {len(tool_names)} tools")
            next_phase = self.get_next_phase(phase, current_state)
            return next_phase
        
        # NEW: Track iterations in same phase for stall detection
        # This would require storing phase start time in the state
        # For now, we'll use the length of tools executed as a proxy
        
        # Original transition criteria
        transition_criteria = {
            'reconnaissance': self._check_recon_complete(current_state),
            'scanning': self._check_scanning_complete(current_state),
            'exploitation': self._check_exploitation_complete(current_state),
            'post_exploitation': self._check_post_exploit_complete(current_state),
            'covering_tracks': self._check_cleanup_complete(current_state)
        }
        
        should_transition = transition_criteria.get(phase, False)
        
        if should_transition:
            print(f"[PhaseController] Natural transition triggered for {phase}")
            next_phase = self.get_next_phase(phase, current_state)
            return next_phase
        else:
            return phase
    
    def _check_recon_complete(self, state: Dict[str, Any]) -> bool:
        """Check if reconnaissance phase is complete"""
        phase_data = state.get('phase_data', {})
        subdomains = phase_data.get('subdomains', 0)
        technologies = phase_data.get('technologies', 0)
        coverage = state.get('coverage', 0.0)
        
        # Complete if we have decent coverage or significant findings
        if coverage >= 0.3 or subdomains >= 5 or technologies >= 3:
            return True
            
        # Also complete if we've executed enough recon tools
        tools_executed = state.get('tools_executed', [])
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_count = len(tools_executed)
        else:
            tool_count = len(tools_executed)
            
        if tool_count >= 5:  # Executed 5+ recon tools
            return True
            
        return False
    
    def _check_scanning_complete(self, state: Dict[str, Any]) -> bool:
        """Check if scanning phase is complete"""
        phase_data = state.get('phase_data', {})
        services = phase_data.get('services_found', 0)
        hosts = phase_data.get('hosts_found', 0)
        coverage = state.get('coverage', 0.0)
        
        # Complete if we have good coverage or found significant services
        if coverage >= 0.5 or services >= 3 or hosts >= 1:
            return True
            
        # Also complete if we've executed enough scanning tools
        tools_executed = state.get('tools_executed', [])
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_count = len(tools_executed)
        else:
            tool_count = len(tools_executed)
            
        if tool_count >= 4:  # Executed 4+ scanning tools
            return True
            
        return False
    
    def _check_exploitation_complete(self, state: Dict[str, Any]) -> bool:
        """Check if exploitation phase is complete"""
        findings = state.get('findings', [])
        phase_data = state.get('phase_data', {})
        shells_obtained = phase_data.get('shells_obtained', 0)
        coverage = state.get('coverage', 0.0)
        
        # Complete if we have high coverage, shells, or critical findings
        critical_findings = len([f for f in findings if f.get('severity', 0) >= 9.0])
        
        if coverage >= 0.7 or shells_obtained >= 1 or critical_findings >= 1:
            return True
            
        # Also complete if we've executed enough exploitation tools
        tools_executed = state.get('tools_executed', [])
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_count = len(tools_executed)
        else:
            tool_count = len(tools_executed)
            
        if tool_count >= 6:  # Executed 6+ exploitation tools
            return True
            
        return False
    
    def _check_post_exploit_complete(self, state: Dict[str, Any]) -> bool:
        """Check if post-exploitation phase is complete"""
        phase_data = state.get('phase_data', {})
        access_gained = phase_data.get('access_gained', False)
        coverage = state.get('coverage', 0.0)
        
        # Complete if we have good coverage or access
        if coverage >= 0.8 or access_gained:
            return True
            
        # Also complete if we've executed enough post-exploitation tools
        tools_executed = state.get('tools_executed', [])
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_count = len(tools_executed)
        else:
            tool_count = len(tools_executed)
            
        if tool_count >= 4:  # Executed 4+ post-exploitation tools
            return True
            
        return False
    
    def _check_cleanup_complete(self, state: Dict[str, Any]) -> bool:
        """Check if covering tracks phase is complete"""
        coverage = state.get('coverage', 0.0)
        
        # Complete if we have high coverage
        if coverage >= 0.9:
            return True
            
        # Also complete if we've executed enough cleanup tools
        tools_executed = state.get('tools_executed', [])
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_count = len(tools_executed)
        else:
            tool_count = len(tools_executed)
            
        if tool_count >= 3:  # Executed 3+ cleanup tools
            return True
            
        return False
    
    def get_next_phase(self, current_phase: str, state: Dict[str, Any]) -> str:
        """Get the next phase in the sequence"""
        try:
            current_index = self.phase_order.index(current_phase)
            if current_index < len(self.phase_order) - 1:
                next_phase = self.phase_order[current_index + 1]
                self.transition_history.append({
                    'from': current_phase,
                    'to': next_phase,
                    'findings': len(state.get('findings', [])),
                    'coverage': state.get('coverage', 0.0),
                    'tools_executed': len(state.get('tools_executed', []))
                })
                return next_phase
            else:
                # Already at last phase
                return current_phase
        except ValueError:
            # Current phase not in order list
            return current_phase
    
    def get_transition_history(self) -> List[Dict[str, Any]]:
        """Get history of phase transitions"""
        return self.transition_history