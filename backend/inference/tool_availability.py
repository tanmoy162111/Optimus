"""
Tool availability checking with registry-based verification.
"""
import shutil
import time
import logging
from typing import Dict, List, Optional, Set
from threading import Lock

logger = logging.getLogger(__name__)

from .tool_registry import is_tool_registered


class ToolAvailabilityCache:
    """
    In-memory cache for tool availability with TTL support.
    Uses the ground-truth registry to verify tool availability.
    """
    
    def __init__(self, ttl_minutes: int = 10):
        self.cache: Dict[str, tuple] = {}  # {tool_name: (available, timestamp)}
        self.ttl_seconds = ttl_minutes * 60
        self.lock = Lock()
        
    def is_available(self, tool_name: str, ssh_client=None, aliases: List[str] = None) -> bool:
        """
        Check if a tool is available using the registry, with caching.
        
        Args:
            tool_name: Primary tool name to check
            ssh_client: SSH client for remote checking (if None, checks locally)
            aliases: Alternative names for the tool (e.g., ["sublist3r", "sublist3r.py"])
        
        Returns:
            bool: True if tool is available in registry, False otherwise
        """
        # Check cache first
        with self.lock:
            current_time = time.time()
            
            # Check if cached result exists and is still valid
            if tool_name in self.cache:
                available, timestamp = self.cache[tool_name]
                if current_time - timestamp < self.ttl_seconds:
                    return available
            
            # Perform actual availability check using registry
            available = self._check_availability(tool_name, ssh_client, aliases)
            
            # Cache the result
            self.cache[tool_name] = (available, current_time)
            return available
    
    def _check_availability(self, tool_name: str, ssh_client=None, aliases: List[str] = None) -> bool:
        """
        Internal method to check tool availability using the registry.
        """
        # Log the tool availability check
        logger.info(f"[ToolAvailability] Checking availability for tool: {tool_name}")
        
        # First check the primary tool name in the registry
        if is_tool_registered(tool_name):
            logger.info(f"[ToolAvailability] Tool {tool_name} found in registry")
            return True
        else:
            logger.debug(f"[ToolAvailability] Tool {tool_name} not found in registry")
        
        # Use aliases if provided
        if aliases:
            for alias in aliases:
                if is_tool_registered(alias):
                    logger.info(f"[ToolAvailability] Tool {tool_name} found via alias {alias}")
                    return True
        
        logger.info(f"[ToolAvailability] Tool {tool_name} not found in registry, attempting discovery")
        
        # If not found in registry, try to discover it and register it
        # This allows for dynamic discovery of new tools
        try:
            from ..tools.tool_discovery import ToolDiscovery
            discovery = ToolDiscovery(ssh_client)
        except ImportError:
            # Fallback import for when module is run directly
            from tools.tool_discovery import ToolDiscovery
            discovery = ToolDiscovery(ssh_client)
        
        # Scan for the specific tool
        if ssh_client:
            # For remote, check if it's available and register it
            try:
                stdin, stdout, stderr = ssh_client.exec_command(f"command -v {tool_name} || which {tool_name}", timeout=10)
                stdout_content = stdout.read().decode('utf-8')
                stderr_content = stderr.read().decode('utf-8')
                exit_status = stdout.channel.recv_exit_status()
                
                if exit_status == 0 and stdout_content.strip():
                    path = stdout_content.strip()
                    # Register the tool in the registry
                    from .tool_registry import get_tool_registry
                    registry = get_tool_registry()
                    version = discovery._get_remote_tool_version(tool_name)
                    registry.register_tool(
                        name=tool_name,
                        path=path,
                        version=version,
                        category=discovery.categorize_tool(tool_name)
                    )
                    return True
            except Exception:
                pass
        else:
            # For local, check if it's available and register it
            if shutil.which(tool_name):
                path = shutil.which(tool_name)
                # Register the tool in the registry
                from .tool_registry import get_tool_registry
                registry = get_tool_registry()
                version = discovery._get_local_tool_version(tool_name)
                registry.register_tool(
                    name=tool_name,
                    path=path,
                    version=version,
                    category=discovery.categorize_tool(tool_name)
                )
                return True
        
        return False
    
    def clear_cache(self):
        """Clear the availability cache."""
        with self.lock:
            self.cache.clear()
    
    def invalidate_tool(self, tool_name: str):
        """Remove a specific tool from cache."""
        with self.lock:
            if tool_name in self.cache:
                del self.cache[tool_name]


# Global instance
_tool_cache = ToolAvailabilityCache()


def is_tool_available(tool_name: str, ssh_client=None, aliases: List[str] = None) -> bool:
    """
    Convenience function to check tool availability using registry.
    """
    return _tool_cache.is_available(tool_name, ssh_client, aliases)


def clear_tool_availability_cache():
    """Clear the global tool availability cache."""
    _tool_cache.clear_cache()
