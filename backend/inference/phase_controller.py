"""
Phase Transition Controller - Manages transitions between pentesting phases
"""
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class PhaseTransitionController:
    """Controls phase transitions in autonomous pentesting"""
    
    def __init__(self):
        self.phases = [
            'reconnaissance',
            'scanning', 
            'exploitation',
            'post_exploitation',
            'covering_tracks'
        ]
        
        self.transition_history = []
        
    def should_transition(self, current_state: Dict[str, Any]) -> str:
        """
        Determine if phase transition should occur
        Returns: Next phase name or current phase if no transition
        """
        phase = current_state.get('phase', 'reconnaissance')
        
        # Check completion criteria for current phase
        transition_criteria = {
            'reconnaissance': self._check_recon_complete(current_state),
            'scanning': self._check_scanning_complete(current_state),
            'exploitation': self._check_exploitation_complete(current_state),
            'post_exploitation': self._check_post_exploit_complete(current_state),
            'covering_tracks': self._check_cleanup_complete(current_state)
        }
        
        if transition_criteria.get(phase, False):
            next_phase = self.get_next_phase(phase, current_state)
            ml_confidence = self.verify_transition_with_ml(current_state, next_phase)
            
            if ml_confidence > 0.7:
                self.log_transition(phase, next_phase, current_state)
                return next_phase
        
        return phase
    
    def get_next_phase(self, current_phase: str, state: Dict[str, Any]) -> str:
        """Get next phase in sequence"""
        if current_phase not in self.phases:
            return 'reconnaissance'
        
        current_idx = self.phases.index(current_phase)
        
        # Check if scan should end
        if current_phase == 'covering_tracks':
            return 'complete'
        
        # Special cases
        if current_phase == 'exploitation':
            # If no exploitable vulns found, skip post-exploitation
            if not state.get('phase_data', {}).get('access_gained', False):
                if state.get('coverage', 0) >= 0.9:
                    return 'covering_tracks'
        
        # Normal progression
        if current_idx < len(self.phases) - 1:
            return self.phases[current_idx + 1]
        
        return 'complete'
    
    def verify_transition_with_ml(self, state: Dict[str, Any], next_phase: str) -> float:
        """
        Use ML to verify transition decision
        Returns: Confidence score 0-1
        """
        # Simple heuristic-based confidence for now
        # In production, this would use a trained ML model
        
        phase = state.get('phase')
        coverage = state.get('coverage', 0.0)
        num_vulns = len(state.get('findings', []))
        
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on coverage
        if coverage >= 0.7:
            confidence += 0.2
        
        # Increase confidence based on findings
        if num_vulns >= 3:
            confidence += 0.1
        
        # Phase-specific adjustments
        if phase == 'reconnaissance' and next_phase == 'scanning':
            subdomains = state.get('phase_data', {}).get('subdomains', 0)
            if subdomains >= 5:
                confidence += 0.2
        
        elif phase == 'scanning' and next_phase == 'exploitation':
            high_severity = any(v.get('severity', 0) >= 7.0 for v in state.get('findings', []))
            if high_severity:
                confidence += 0.2
        
        elif phase == 'exploitation' and next_phase == 'post_exploitation':
            if state.get('phase_data', {}).get('access_gained', False):
                confidence += 0.3
        
        return min(confidence, 1.0)
    
    def log_transition(self, from_phase: str, to_phase: str, state: Dict[str, Any]):
        """Log phase transition"""
        transition = {
            'from': from_phase,
            'to': to_phase,
            'coverage': state.get('coverage', 0.0),
            'findings': len(state.get('findings', [])),
            'time_elapsed': state.get('time_elapsed', 0)
        }
        
        self.transition_history.append(transition)
        logger.info(f"Phase transition: {from_phase} -> {to_phase} "
                   f"(coverage: {transition['coverage']:.2f}, "
                   f"findings: {transition['findings']})")
    
    def _check_recon_complete(self, state: Dict[str, Any]) -> bool:
        """Check if reconnaissance phase is complete"""
        phase_data = state.get('phase_data', {})
        
        # Criteria: Found sufficient subdomains and technologies
        subdomains = phase_data.get('subdomains', 0)
        technologies = phase_data.get('technologies', 0)
        coverage = state.get('coverage', 0.0)
        
        return (
            subdomains >= 5 and
            technologies >= 3 and
            coverage >= 0.6
        )
    
    def _check_scanning_complete(self, state: Dict[str, Any]) -> bool:
        """Check if scanning phase is complete"""
        findings = state.get('findings', [])
        coverage = state.get('coverage', 0.0)
        
        # Criteria: Found vulnerabilities and good coverage
        has_findings = len(findings) >= 3
        has_high_severity = any(v.get('severity', 0) >= 7.0 for v in findings)
        good_coverage = coverage >= 0.7
        
        return has_findings and (has_high_severity or good_coverage)
    
    def _check_exploitation_complete(self, state: Dict[str, Any]) -> bool:
        """Check if exploitation phase is complete"""
        phase_data = state.get('phase_data', {})
        
        # Criteria: Gained access or exhausted exploitable vulnerabilities
        access_gained = phase_data.get('access_gained', False)
        shells_obtained = phase_data.get('shells_obtained', 0)
        exploit_attempts = phase_data.get('exploit_attempts', 0)
        
        return (
            access_gained or
            shells_obtained > 0 or
            exploit_attempts >= 10  # Tried enough times
        )
    
    def _check_post_exploit_complete(self, state: Dict[str, Any]) -> bool:
        """Check if post-exploitation phase is complete"""
        phase_data = state.get('phase_data', {})
        
        # Criteria: Gathered sufficient data or escalated privileges
        credentials_dumped = phase_data.get('credentials_dumped', 0)
        privilege_escalated = phase_data.get('privilege_escalated', False)
        lateral_movement = phase_data.get('lateral_movement', 0)
        
        return (
            credentials_dumped >= 1 or
            privilege_escalated or
            lateral_movement >= 1
        )
    
    def _check_cleanup_complete(self, state: Dict[str, Any]) -> bool:
        """Check if covering tracks phase is complete"""
        phase_data = state.get('phase_data', {})
        
        # Criteria: Cleaned up artifacts
        logs_cleared = phase_data.get('logs_cleared', False)
        artifacts_removed = phase_data.get('artifacts_removed', False)
        
        return logs_cleared and artifacts_removed
    
    def get_transition_history(self) -> list:
        """Get history of phase transitions"""
        return self.transition_history
