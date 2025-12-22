"""
Reward Calculator for Deep RL Training
Calculates rewards based on tool execution results
"""

import logging
from typing import Dict, List, Any, Optional
from .rl_training_config import RLTrainingConfig, DEFAULT_TRAINING_CONFIG

logger = logging.getLogger(__name__)


class RewardCalculator:
    """
    Calculates rewards for RL agent based on tool execution results.
    Uses reward shaping to guide learning.
    """
    
    def __init__(self, config: RLTrainingConfig = None):
        self.config = config or DEFAULT_TRAINING_CONFIG
        self.rewards = self.config.rewards
        
        # Track state for reward calculation
        self.previous_findings_count = 0
        self.previous_services = set()
        self.previous_technologies = set()
        self.tools_executed_this_episode = []
        self.phase_stall_counter = {}
    
    def reset_episode(self):
        """Reset state for new episode"""
        self.previous_findings_count = 0
        self.previous_services = set()
        self.previous_technologies = set()
        self.tools_executed_this_episode = []
        self.phase_stall_counter = {}
    
    def calculate_reward(
        self,
        tool_name: str,
        result: Dict[str, Any],
        scan_state: Dict[str, Any],
        execution_time: float
    ) -> float:
        """
        Calculate reward for a tool execution.
        
        Args:
            tool_name: Name of tool executed
            result: Tool execution result
            scan_state: Current scan state
            execution_time: Time taken for execution
            
        Returns:
            Calculated reward value
        """
        reward = 0.0
        reward_breakdown = {}
        
        # 1. Check tool success/failure
        success = result.get("success", False)
        if not success:
            error = result.get("error", "")
            if "timeout" in error.lower():
                reward += self.rewards["tool_timeout"]
                reward_breakdown["timeout"] = self.rewards["tool_timeout"]
            else:
                reward += self.rewards["tool_failed"]
                reward_breakdown["failed"] = self.rewards["tool_failed"]
        
        # 2. Check for repeated tool usage
        if tool_name in self.tools_executed_this_episode:
            reward += self.rewards["repeated_tool"]
            reward_breakdown["repeated"] = self.rewards["repeated_tool"]
        self.tools_executed_this_episode.append(tool_name)
        
        # 3. Calculate findings-based rewards
        parsed_results = result.get("parsed_results", {})
        new_vulns = parsed_results.get("vulnerabilities", [])
        
        if new_vulns:
            for vuln in new_vulns:
                severity = vuln.get("severity", 0)
                vuln_type = vuln.get("type", "").lower()
                
                if severity >= 9.0:
                    reward += self.rewards["critical_vuln_found"]
                    reward_breakdown["critical"] = reward_breakdown.get("critical", 0) + self.rewards["critical_vuln_found"]
                elif severity >= 7.0:
                    reward += self.rewards["high_vuln_found"]
                    reward_breakdown["high"] = reward_breakdown.get("high", 0) + self.rewards["high_vuln_found"]
                elif severity >= 4.0:
                    reward += self.rewards["medium_vuln_found"]
                    reward_breakdown["medium"] = reward_breakdown.get("medium", 0) + self.rewards["medium_vuln_found"]
                else:
                    reward += self.rewards["low_vuln_found"]
                    reward_breakdown["low"] = reward_breakdown.get("low", 0) + self.rewards["low_vuln_found"]
                
                # Bonus for specific exploit types
                if "shell" in vuln_type or "rce" in vuln_type:
                    reward += self.rewards["shell_obtained"]
                    reward_breakdown["shell"] = self.rewards["shell_obtained"]
                elif "credential" in vuln_type or "password" in vuln_type:
                    reward += self.rewards["credentials_found"]
                    reward_breakdown["credentials"] = self.rewards["credentials_found"]
        else:
            # No findings penalty (small)
            reward += self.rewards["no_findings"]
            reward_breakdown["no_findings"] = self.rewards["no_findings"]
        
        # 4. Check for new discoveries
        services = set(parsed_results.get("services", []))
        new_services = services - self.previous_services
        if new_services:
            service_reward = len(new_services) * self.rewards["new_service_discovered"]
            reward += service_reward
            reward_breakdown["new_services"] = service_reward
            self.previous_services.update(new_services)
        
        technologies = set(parsed_results.get("technologies", []))
        new_techs = technologies - self.previous_technologies
        if new_techs:
            tech_reward = len(new_techs) * self.rewards["new_technology_detected"]
            reward += tech_reward
            reward_breakdown["new_technologies"] = tech_reward
            self.previous_technologies.update(new_techs)
        
        # 5. Phase progress tracking
        phase = scan_state.get("phase", "reconnaissance")
        current_findings = len(scan_state.get("findings", []))
        
        if current_findings == self.previous_findings_count:
            self.phase_stall_counter[phase] = self.phase_stall_counter.get(phase, 0) + 1
            if self.phase_stall_counter[phase] > 5:
                reward += self.rewards["phase_stall"]
                reward_breakdown["stall"] = self.rewards["phase_stall"]
        else:
            self.phase_stall_counter[phase] = 0
        
        self.previous_findings_count = current_findings
        
        # 6. Efficiency bonus (faster execution with findings)
        if new_vulns and execution_time < 60:
            efficiency_bonus = 0.5 * (1 - execution_time / 60)
            reward += efficiency_bonus
            reward_breakdown["efficiency"] = efficiency_bonus
        
        logger.debug(f"[RewardCalculator] {tool_name}: total={reward:.2f}, breakdown={reward_breakdown}")
        
        return reward
    
    def calculate_episode_end_reward(
        self,
        scan_state: Dict[str, Any],
        completed_normally: bool,
        total_time: float,
        max_time: float
    ) -> float:
        """Calculate bonus/penalty at end of episode"""
        reward = 0.0
        
        findings = scan_state.get("findings", [])
        
        # Bonus for completing with findings
        if completed_normally and findings:
            # Scale by severity
            critical_count = sum(1 for f in findings if f.get("severity", 0) >= 9.0)
            high_count = sum(1 for f in findings if 7.0 <= f.get("severity", 0) < 9.0)
            
            completion_bonus = 5.0 + (critical_count * 2.0) + (high_count * 1.0)
            reward += completion_bonus
        
        # Penalty for timeout without findings
        if total_time >= max_time and not findings:
            reward += self.rewards["scan_timeout"]
        
        # Time efficiency bonus
        if completed_normally and total_time < max_time * 0.5:
            time_bonus = 2.0 * (1 - total_time / max_time)
            reward += time_bonus
        
        return reward


# Singleton
_calculator = None

def get_reward_calculator(config: RLTrainingConfig = None) -> RewardCalculator:
    """Get singleton reward calculator"""
    global _calculator
    if _calculator is None:
        _calculator = RewardCalculator(config)
    return _calculator
