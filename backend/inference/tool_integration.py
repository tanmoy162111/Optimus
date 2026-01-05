"""
Tool Integration System - Coordinates tool detection, registration, and command generation
"""
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from .tool_registry import get_tool_registry, ToolRegistry
from .tool_availability import is_tool_available
from .evolving_commands import get_evolving_command_generator, EvolvingCommandGenerator
from ..tools.tool_discovery import discover_tools, ToolDiscovery

logger = logging.getLogger(__name__)


class ToolIntegrationCoordinator:
    """
    Coordinates the integration between tool detection, registry, and command generation.
    Ensures that discovered tools are automatically registered and made available for command generation.
    """
    
    def __init__(self, ssh_client=None):
        self.ssh_client = ssh_client
        self.registry = get_tool_registry()
        self.evolving_generator = get_evolving_command_generator(ssh_client=ssh_client)
        self.discovery = ToolDiscovery(ssh_client=ssh_client)
        
        logger.info("[ToolIntegration] Coordinator initialized")
    
    def sync_tools(self) -> Dict[str, Any]:
        """
        Synchronize tools between system discovery and registry.
        This ensures all available tools are registered in the ground-truth registry.
        """
        logger.info("[ToolIntegration] Starting tool synchronization...")
        
        # Discover all tools on the system
        discovered_tools = discover_tools(self.ssh_client)
        logger.info(f"[ToolIntegration] Discovered {len(discovered_tools)} tools")
        
        # Register all discovered tools in the registry
        registered_count = 0
        for tool_info in discovered_tools:
            name = tool_info.get('name', '')
            path = tool_info.get('path', '')
            
            if name and path:
                # Check if already registered
                if not self.registry.is_tool_registered(name):
                    # Register the tool
                    success = self.registry.register_tool(
                        name=name,
                        path=path,
                        version=tool_info.get('version', ''),
                        category=tool_info.get('category', 'misc'),
                        description=tool_info.get('description', ''),
                        metadata=tool_info.get('metadata', {})
                    )
                    if success:
                        registered_count += 1
                        logger.info(f"[ToolIntegration] Registered new tool: {name}")
                    else:
                        logger.warning(f"[ToolIntegration] Failed to register tool: {name}")
        
        # Also sync Metasploit modules
        try:
            from ..tools.tool_discovery import discover_metasploit_modules
            msf_modules = discover_metasploit_modules(self.ssh_client)
            for module in msf_modules:
                name = module.get('name', '')
                module_type = module.get('type', '')
                path = module.get('path', '')
                
                if name and module_type and path:
                    self.registry.register_metasploit_module(
                        name=name,
                        module_type=module_type,
                        path=path,
                        description=module.get('description', '')
                    )
                    logger.info(f"[ToolIntegration] Registered MSF module: {name}")
        except Exception as e:
            logger.warning(f"[ToolIntegration] MSF module discovery failed: {e}")
        
        result = {
            'discovered_count': len(discovered_tools),
            'newly_registered': registered_count,
            'total_registered': len(self.registry.get_all_registered_tools()),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"[ToolIntegration] Synchronization completed: {result}")
        return result
    
    def ensure_tool_availability(self, tool_name: str) -> bool:
        """
        Ensure a specific tool is available in the registry.
        If not found, attempt to discover and register it.
        """
        logger.info(f"[ToolIntegration] Ensuring availability of tool: {tool_name}")
        
        # Check if tool is already in registry
        if self.registry.is_tool_registered(tool_name):
            logger.debug(f"[ToolIntegration] Tool {tool_name} already registered")
            return True
        
        # If not registered, try to discover it directly
        discovery = ToolDiscovery(self.ssh_client)
        
        if self.ssh_client:
            # For remote systems
            try:
                result = self.ssh_client.execute_command(f"command -v {tool_name} || which {tool_name}")
                if result['success'] and result.get('stdout', '').strip():
                    path = result.get('stdout', '').strip()
                    version = discovery._get_remote_tool_version(tool_name)
                    category = discovery.categorize_tool(tool_name)
                    
                    success = self.registry.register_tool(
                        name=tool_name,
                        path=path,
                        version=version,
                        category=category
                    )
                    
                    if success:
                        logger.info(f"[ToolIntegration] Discovered and registered tool: {tool_name}")
                        return True
            except Exception as e:
                logger.debug(f"[ToolIntegration] Remote discovery failed for {tool_name}: {e}")
        else:
            # For local systems
            import shutil
            if shutil.which(tool_name):
                path = shutil.which(tool_name)
                version = discovery._get_local_tool_version(tool_name)
                category = discovery.categorize_tool(tool_name)
                
                success = self.registry.register_tool(
                    name=tool_name,
                    path=path,
                    version=version,
                    category=category
                )
                
                if success:
                    logger.info(f"[ToolIntegration] Discovered and registered tool: {tool_name}")
                    return True
        
        logger.warning(f"[ToolIntegration] Could not ensure availability of tool: {tool_name}")
        return False
    
    def generate_command_for_tool(self, tool_name: str, target: str, 
                                context: Dict[str, Any] = None) -> Optional[str]:
        """
        Generate a command for a tool, ensuring the tool is available in the registry.
        """
        logger.info(f"[ToolIntegration] Generating command for tool: {tool_name}")
        
        # Ensure tool is available in registry
        if not self.ensure_tool_availability(tool_name):
            logger.error(f"[ToolIntegration] Cannot generate command: tool {tool_name} not available")
            return None
        
        # Now generate the command using the evolving command generator
        try:
            command, source = self.evolving_generator.generate_command(tool_name, target, context)
            if command:
                # Validate the generated command uses registered tools
                from .tool_registry import validate_command_tool
                if validate_command_tool(command):
                    logger.info(f"[ToolIntegration] Successfully generated command for {tool_name}")
                    return command
                else:
                    logger.error(f"[ToolIntegration] Generated command uses unregistered tools: {command}")
                    return None
            else:
                logger.warning(f"[ToolIntegration] Failed to generate command for {tool_name}")
                return None
        except Exception as e:
            logger.error(f"[ToolIntegration] Command generation failed for {tool_name}: {e}")
            return None
    
    def refresh_and_validate(self) -> Dict[str, Any]:
        """
        Perform a full refresh of the tool registry and validate all registered tools.
        """
        logger.info("[ToolIntegration] Starting full refresh and validation...")
        
        # Sync tools
        sync_result = self.sync_tools()
        
        # Validate registered tools by testing their availability
        all_tools = self.registry.get_all_registered_tools()
        valid_tools = 0
        invalid_tools = []
        
        for tool in all_tools:
            tool_name = tool['name']
            tool_path = tool['path']
            
            try:
                if self.ssh_client:
                    # Check remote availability
                    result = self.ssh_client.execute_command(f"test -x '{tool_path}' && echo 'exists'")
                    if result.get('stdout', '').strip() == 'exists':
                        valid_tools += 1
                    else:
                        invalid_tools.append(tool_name)
                else:
                    # Check local availability
                    import os
                    if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
                        valid_tools += 1
                    else:
                        invalid_tools.append(tool_name)
            except Exception as e:
                logger.debug(f"[ToolIntegration] Validation failed for {tool_name}: {e}")
                invalid_tools.append(tool_name)
        
        # Remove invalid tools from registry
        for tool_name in invalid_tools:
            self.registry.remove_tool(tool_name)
            logger.info(f"[ToolIntegration] Removed invalid tool from registry: {tool_name}")
        
        result = {
            **sync_result,
            'valid_tools': valid_tools,
            'invalid_tools_count': len(invalid_tools),
            'invalid_tools': invalid_tools,
            'final_registered_count': len(self.registry.get_all_registered_tools())
        }
        
        logger.info(f"[ToolIntegration] Refresh and validation completed: {result}")
        return result
    
    def get_tool_status(self, tool_name: str) -> Dict[str, Any]:
        """
        Get comprehensive status of a tool including registration, availability, and usability.
        """
        status = {
            'tool_name': tool_name,
            'registered': self.registry.is_tool_registered(tool_name),
            'registered_info': None,
            'available': is_tool_available(tool_name, self.ssh_client),
            'timestamp': datetime.now().isoformat()
        }
        
        if status['registered']:
            status['registered_info'] = self.registry.get_tool_info(tool_name)
        
        return status


# Global coordinator instance
_integration_coordinator: Optional[ToolIntegrationCoordinator] = None


def get_tool_integration_coordinator(ssh_client=None) -> ToolIntegrationCoordinator:
    """Get or create singleton tool integration coordinator instance"""
    global _integration_coordinator
    if _integration_coordinator is None:
        _integration_coordinator = ToolIntegrationCoordinator(ssh_client)
    elif ssh_client and _integration_coordinator.ssh_client != ssh_client:
        # Update SSH client if needed
        _integration_coordinator.ssh_client = ssh_client
    return _integration_coordinator


def sync_all_tools(ssh_client=None) -> Dict[str, Any]:
    """Convenience function to sync all tools"""
    coordinator = get_tool_integration_coordinator(ssh_client)
    return coordinator.sync_tools()


def ensure_tool_exists(tool_name: str, ssh_client=None) -> bool:
    """Convenience function to ensure a tool exists in the registry"""
    coordinator = get_tool_integration_coordinator(ssh_client)
    return coordinator.ensure_tool_availability(tool_name)


def generate_tool_command(tool_name: str, target: str, 
                         context: Dict[str, Any] = None, ssh_client=None) -> Optional[str]:
    """Convenience function to generate a command for a tool"""
    coordinator = get_tool_integration_coordinator(ssh_client)
    return coordinator.generate_command_for_tool(tool_name, target, context)


def refresh_tool_registry(ssh_client=None) -> Dict[str, Any]:
    """Convenience function to refresh and validate the entire tool registry"""
    coordinator = get_tool_integration_coordinator(ssh_client)
    return coordinator.refresh_and_validate()