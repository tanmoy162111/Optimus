"""
Configuration for the tools module
"""
import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class ToolsConfig:
    """Configuration for the tools module"""
    
    # Tool discovery
    enable_discovery: bool = True
    discovery_on_startup: bool = True
    discovery_cache_hours: int = 24
    
    # LLM command generation
    enable_llm_generation: bool = True
    llm_confidence_threshold: float = 0.5
    block_dangerous_commands: bool = True
    
    # Web research
    enable_web_research: bool = True
    research_cache_days: int = 7
    
    # Safety settings
    require_confirmation_for_ai_commands: bool = True
    max_command_length: int = 1000
    blocked_command_patterns: list = None
    
    # Storage paths
    inventory_path: str = "data/tool_inventory.json"
    research_cache_path: str = "data/tool_research_cache"
    
    # Timeouts
    tool_execution_timeout: int = 300
    discovery_timeout: int = 60
    
    def __post_init__(self):
        if self.blocked_command_patterns is None:
            self.blocked_command_patterns = [
                'rm -rf',
                'dd if=',
                '> /dev/',
                'mkfs',
                ':(){:|:&};:',
                'chmod -R 777 /',
            ]
    
    @classmethod
    def from_env(cls):
        """Load configuration from environment variables"""
        return cls(
            enable_discovery=os.getenv('TOOLS_ENABLE_DISCOVERY', 'true').lower() == 'true',
            discovery_on_startup=os.getenv('TOOLS_DISCOVERY_ON_STARTUP', 'true').lower() == 'true',
            enable_llm_generation=os.getenv('TOOLS_ENABLE_LLM', 'true').lower() == 'true',
            llm_confidence_threshold=float(os.getenv('TOOLS_LLM_THRESHOLD', '0.5')),
            enable_web_research=os.getenv('TOOLS_ENABLE_WEB_RESEARCH', 'true').lower() == 'true',
            require_confirmation_for_ai_commands=os.getenv('TOOLS_REQUIRE_AI_CONFIRMATION', 'true').lower() == 'true',
            inventory_path=os.getenv('TOOLS_INVENTORY_PATH', 'data/tool_inventory.json'),
            research_cache_path=os.getenv('TOOLS_RESEARCH_CACHE', 'data/tool_research_cache'),
            tool_execution_timeout=int(os.getenv('TOOLS_EXECUTION_TIMEOUT', '300'))
        )