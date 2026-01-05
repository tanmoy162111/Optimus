#!/usr/bin/env python3
"""
Selector Adapter for Training Environment

This adapter allows the training environment to use the same selector API 
as the autonomous agent, ensuring consistent tool selection behavior.
"""

import logging
from typing import Dict, List, Any
from inference.intelligent_selector import IntelligentToolSelector
from inference.tool_selector import PhaseAwareToolSelector

logger = logging.getLogger(__name__)

class SelectorAdapter:
    """
    Adapter to make training environment use the same selector API as autonomous agent.
    """
    
    def __init__(self, ssh_client=None):
        # Use the same selector as the autonomous agent
        self.phase_aware_selector = PhaseAwareToolSelector(ssh_client=ssh_client)
        self.intelligent_selector = IntelligentToolSelector()
        
        # Training to real phase mapping
        self.phase_mapping = {
            "training": "reconnaissance",  # default
            "web": "enumeration",
            "scan": "vulnerability_analysis",
            "exploit": "exploitation",
            "recon": "reconnaissance",
            "enum": "enumeration",
            "vuln": "vulnerability_analysis",
            "post_exploit": "post_exploitation",
            # Add more mappings as needed
        }
    
    def select_tools(self, phase: str, scan_state: Dict[str, Any], count: int = 5) -> List[Dict[str, Any]]:
        """
        Adapter method that maps training phases to real phases and calls the 
        same selector API used by the autonomous agent.
        
        Args:
            phase: Training phase (e.g., "training", "web", "exploit")
            scan_state: Current scan state
            count: Number of tools to return
            
        Returns:
            List of tool recommendations in the same format training expects
        """
        # Map training phase to real phase
        mapped_phase = self.phase_mapping.get(phase, "reconnaissance")
        print(f"[selector_adapter] training_phase={phase} mapped_phase={mapped_phase}")
        
        # Update scan_state with mapped phase for consistency
        scan_state['phase'] = mapped_phase
        
        # Call the same selector method used by autonomous agent
        # The PhaseAwareToolSelector.recommend_tools returns a dict with 'tools' key
        recommendation = self.phase_aware_selector.recommend_tools(scan_state)
        
        # Convert to the format expected by training environment
        tools = recommendation.get('tools', [])[:count]
        
        # Create ToolRecommendation-like objects (similar to IntelligentToolSelector)
        tool_recommendations = []
        for i, tool in enumerate(tools):
            # Create a basic recommendation object
            tool_rec = {
                'tool': tool,
                'args': '',  # Will be filled by training logic
                'priority': 1.0 - (i * 0.1),  # Higher priority for earlier tools
                'reason': f'Phase-aware selection for {mapped_phase}',
                'source': 'phase_aware_adapter'
            }
            tool_recommendations.append(tool_rec)
        
        return tool_recommendations


def get_selector_adapter(ssh_client=None):
    """Factory function to get selector adapter instance."""
    return SelectorAdapter(ssh_client=ssh_client)


# For backward compatibility, keep the original select_tools function behavior
# but route it through the adapter
def select_tools_for_training(phase: str, scan_state: Dict[str, Any], count: int = 5):
    """
    Legacy function that maintains compatibility with existing training code
    but uses the new unified selector.
    """
    adapter = get_selector_adapter()
    return adapter.select_tools(phase, scan_state, count)


class PhaseAwareSelectorAdapter:
    """
    Adapter that wraps PhaseAwareToolSelector to provide the same interface
    as IntelligentToolSelector.select_tools() for training compatibility.
    """
    
    def __init__(self, ssh_client=None):
        self.phase_aware_selector = PhaseAwareToolSelector(ssh_client=ssh_client)
        
        # Training to real phase mapping
        self.phase_mapping = {
            "training": "reconnaissance",  # default
            "web": "enumeration",
            "scan": "vulnerability_analysis",
            "exploit": "exploitation",
            "recon": "reconnaissance",
            "enum": "enumeration",
            "vuln": "vulnerability_analysis",
            "post_exploit": "post_exploitation",
            # Add more mappings as needed
        }
    
    def select_tools(self, phase: str, scan_state: Dict[str, Any], count: int = 5):
        """
        Wrapper method that provides the same interface as IntelligentToolSelector.select_tools
        but uses PhaseAwareToolSelector internally.
        """
        # Map training phase to real phase
        mapped_phase = self.phase_mapping.get(phase, "reconnaissance")
        print(f"[selector_adapter] training_phase={phase} mapped_phase={mapped_phase}")
        
        # Update scan_state with mapped phase for consistency
        scan_state['phase'] = mapped_phase
        
        # Call the PhaseAwareToolSelector.recommend_tools method
        recommendation = self.phase_aware_selector.recommend_tools(scan_state)
        
        # Convert to the format expected by training environment
        tools = recommendation.get('tools', [])[:count]
        
        # Create ToolRecommendation-like objects to match expected interface
        from dataclasses import dataclass
        
        @dataclass
        class ToolRecommendation:
            tool: str
            args: str
            priority: float
            reason: str
            source: str
        
        tool_recommendations = []
        for i, tool in enumerate(tools):
            # Create a ToolRecommendation object
            tool_rec = ToolRecommendation(
                tool=tool,
                args='',  # Will be filled by training logic
                priority=1.0 - (i * 0.1),  # Higher priority for earlier tools
                reason=f'Phase-aware selection for {mapped_phase}',
                source='phase_aware_adapter'
            )
            tool_recommendations.append(tool_rec)
        
        return tool_recommendations


def get_phase_aware_selector_adapter(ssh_client=None):
    """Factory function to get phase aware selector adapter instance."""
    return PhaseAwareSelectorAdapter(ssh_client=ssh_client)