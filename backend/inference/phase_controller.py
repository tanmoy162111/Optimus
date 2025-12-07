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
        # Define tools available for each phase
        self.phase_tools = {
            'reconnaissance': ['sublist3r', 'amass', 'theHarvester', 'whatweb', 'dnsenum'],
            'scanning': ['nmap', 'nikto', 'nuclei', 'masscan'],
            'exploitation': ['sqlmap', 'dalfox', 'commix', 'ffuf', 'wpscan'],
            'post_exploitation': ['linpeas', 'winpeas'],
            'covering_tracks': ['clear_logs']
        }
    
    def should_transition(self, current_state: Dict[str, Any]) -> str:
        """
        Determine if phase should transition based on progress metrics
        IMPROVED: More lenient criteria to allow tools time to find vulnerabilities
        
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
        
        # Count UNIQUE tools executed (not total executions)
        unique_tools = list(set(tool_names))
        
        print(f"[PhaseController] Checking transition for {phase}")
        print(f"  Total executions: {len(tool_names)}")
        print(f"  Unique tools: {len(unique_tools)}")
        print(f"  Findings: {len(findings)}")
        print(f"  Coverage: {coverage:.2f}")
        
        # Don't force transitions in first 2 minutes of phase
        phase_start_time = current_state.get('phase_start_time')
        if phase_start_time:
            from datetime import datetime
            time_in_phase = (datetime.now() - datetime.fromisoformat(phase_start_time)).total_seconds()
            if time_in_phase < 120:  # 2 minutes minimum
                # Only allow natural transitions, not forced ones
                print(f"[PhaseController] In warmup period ({time_in_phase:.1f}s), only allowing natural transitions")
                should_transition = self._check_phase_completion(current_state)
                if should_transition:
                    return self.get_next_phase(phase, current_state)
                return phase
        
        # RELAXED: Force transition only after MANY more executions
        # This gives tools time to actually complete and find things
        MAX_EXECUTIONS_PER_PHASE = 50  # Increased from 30
        if len(tool_names) >= MAX_EXECUTIONS_PER_PHASE:
            print(f"[PhaseController] FORCING TRANSITION - {len(tool_names)} executions in {phase}")
            return self.get_next_phase(phase, current_state)
        
        # RELAXED: Only force transition if we've tried MANY unique tools
        # Changed from 5 to 15 tools minimum before forcing transition
        if len(unique_tools) >= 15 and len(findings) == 0:
            print(f"[PhaseController] FORCING TRANSITION - {len(unique_tools)} unique tools, 0 findings")
            return self.get_next_phase(phase, current_state)
        
        # REMOVED: The aggressive "tool repeated 2+ times" check
        # This was causing premature transitions
        # Tools often need to run multiple times with different parameters
        
        # Check for SEVERE tool repetition only (same tool 5+ times)
        if len(tool_names) >= 5:
            recent_tools = tool_names[-10:] if len(tool_names) >= 10 else tool_names
            tool_counts = {}
            for tool in recent_tools:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
            
            # Only transition if a tool appears 5+ times (severe stuck)
            max_count = max(tool_counts.values()) if tool_counts else 0
            if max_count >= 5:
                most_repeated = [k for k, v in tool_counts.items() if v == max_count][0]
                print(f"[PhaseController] FORCING TRANSITION - {most_repeated} repeated {max_count} times (SEVERE)")
                return self.get_next_phase(phase, current_state)
        
        # Check phase-specific completion criteria
        should_transition = self._check_phase_completion(current_state)
        
        if should_transition:
            print(f"[PhaseController] Natural transition triggered for {phase}")
            return self.get_next_phase(phase, current_state)
        
        return phase

    def should_transition_intelligent(self, current_state: Dict, learning_module=None) -> str:
        """
        Make intelligent transition decision using learning data.
        """
        phase = current_state['phase']
        
        # Check basic transition criteria first
        basic_result = self.should_transition(current_state)
        
        # If basic says transition, check if learning agrees
        if basic_result != phase and learning_module:
            phase_effectiveness = learning_module.get_phase_effectiveness(phase)
            
            # If this phase is still finding things, stay longer
            if phase_effectiveness.get('recent_findings_rate', 0) > 0.2:
                logger.info(f"Learning suggests staying in {phase} - still effective")
                return phase
        
        return basic_result
    
    def _should_change_approach_or_phase(self, state: Dict[str, Any]) -> bool:
        """
        Check if all tools in current phase have been tried without sufficient findings
        
        Args:
            state: Current scan state
            
        Returns:
            True if all tools have been tried and we should consider changing approach or phase
        """
        phase = state['phase']
        findings = state.get('findings', [])
        tools_executed = state.get('tools_executed', [])
        
        # Get tools for current phase
        phase_tools = self.phase_tools.get(phase, [])
        if not phase_tools:
            return False
            
        # Get executed tool names
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_names = [t['tool'] for t in tools_executed]
        else:
            tool_names = tools_executed
            
        # Check if all phase tools have been executed
        executed_phase_tools = [tool for tool in tool_names if tool in phase_tools]
        unique_executed_phase_tools = list(set(executed_phase_tools))
        
        # If we've tried all tools in this phase and have few findings, consider change
        if len(unique_executed_phase_tools) >= len(phase_tools) and len(findings) < 3:
            return True
            
        return False
    
    def _should_change_approach(self, state: Dict[str, Any]) -> bool:
        """
        Determine if we should change approach rather than move to next phase
        
        Args:
            state: Current scan state
            
        Returns:
            True if we should change approach, False if we should move to next phase
        """
        phase = state['phase']
        findings = state.get('findings', [])
        tools_executed = state.get('tools_executed', [])
        coverage = state.get('coverage', 0.0)
        
        # Get executed tool names
        if tools_executed and len(tools_executed) > 0 and isinstance(tools_executed[0], dict):
            tool_names = [t['tool'] for t in tools_executed]
        else:
            tool_names = tools_executed
            
        # Get tools for current phase
        phase_tools = self.phase_tools.get(phase, [])
        
        # If we have some findings but coverage is low, try different approach
        if len(findings) > 0 and coverage < 0.3:
            return True
            
        # If we've tried many tools but have very few findings, try different approach
        if len(tool_names) >= 8 and len(findings) < 2:
            return True
            
        # If we're in early phases and haven't found much, try different approach
        if phase in ['reconnaissance', 'scanning'] and len(findings) < 1:
            return True
            
        # Otherwise, move to next phase
        return False
    
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
    
    def _check_phase_completion(self, state: Dict[str, Any]) -> bool:
        """
        Check if the current phase is complete based on specific criteria
        
        Args:
            state: Current scan state
            
        Returns:
            True if the phase is complete, False otherwise
        """
        phase = state['phase']
        transition_criteria = {
            'reconnaissance': self._check_recon_complete(state),
            'scanning': self._check_scanning_complete(state),
            'exploitation': self._check_exploitation_complete(state),
            'post_exploitation': self._check_post_exploit_complete(state),
            'covering_tracks': self._check_cleanup_complete(state)
        }
        
        return transition_criteria.get(phase, False)
    
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