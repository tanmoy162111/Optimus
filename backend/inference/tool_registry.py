"""
Tool Registry System - Centralized ground-truth registry for all available tools
"""
import json
import logging
import sqlite3
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager
from datetime import datetime
import re

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Centralized registry for all available tools with ground-truth verification.
    All tool commands must come from this registry to ensure security and reliability.
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent / 'data' / 'tool_registry.db'
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        logger.info(f"[ToolRegistry] Initialized at {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize the tool registry database"""
        with self._get_connection() as conn:
            # Tool registry table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tool_registry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    path TEXT NOT NULL,
                    version TEXT,
                    category TEXT,
                    description TEXT,
                    verified BOOLEAN DEFAULT 0,
                    last_verified TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    metadata TEXT  -- JSON metadata for additional tool info
                )
            ''')
            
            # Metasploit modules table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS metasploit_modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT,
                    path TEXT,
                    description TEXT,
                    verified BOOLEAN DEFAULT 0,
                    last_verified TEXT,
                    created_at TEXT,
                    UNIQUE(name, type)
                )
            ''')
            
            # Tool categories table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tool_categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT
                )
            ''')
            
            # Indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_registry_name ON tool_registry(name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_registry_verified ON tool_registry(verified)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_modules_name ON metasploit_modules(name)')
            
            # Insert default categories
            categories = [
                ('scanner', 'Network and vulnerability scanners'),
                ('exploitation', 'Exploitation tools'),
                ('password', 'Password cracking tools'),
                ('web', 'Web application tools'),
                ('network', 'Network analysis tools'),
                ('wireless', 'Wireless security tools'),
                ('forensics', 'Digital forensics tools'),
                ('misc', 'Miscellaneous tools'),
                ('metasploit', 'Metasploit framework modules')
            ]
            
            for name, description in categories:
                try:
                    conn.execute('''
                        INSERT OR IGNORE INTO tool_categories (name, description)
                        VALUES (?, ?)
                    ''', (name, description))
                except Exception:
                    pass
    
    def register_tool(self, name: str, path: str, version: str = "", 
                     category: str = "misc", description: str = "", 
                     metadata: Dict[str, Any] = None) -> bool:
        """
        Register a tool in the registry after verification.
        This is the only way tools can be added to the system.
        """
        if not self._verify_tool_at_path(name, path):
            logger.warning(f"[ToolRegistry] Tool {name} not found at {path}, not registering")
            return False
        
        metadata_json = json.dumps(metadata or {})
        now = datetime.now().isoformat()
        
        try:
            with self._get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO tool_registry 
                    (name, path, version, category, description, verified, last_verified, updated_at, created_at, metadata)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ''', (name, path, version, category, description, now, now, now, metadata_json))
            
            logger.info(f"[ToolRegistry] Registered tool: {name} at {path}")
            return True
        except Exception as e:
            logger.error(f"[ToolRegistry] Failed to register tool {name}: {e}")
            return False
    
    def register_metasploit_module(self, name: str, module_type: str, path: str, 
                                 description: str = "") -> bool:
        """Register a Metasploit module in the registry"""
        now = datetime.now().isoformat()
        
        try:
            with self._get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO metasploit_modules
                    (name, type, path, description, verified, last_verified, created_at)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                ''', (name, module_type, path, description, now, now))
            
            logger.info(f"[ToolRegistry] Registered Metasploit module: {name}")
            return True
        except Exception as e:
            logger.error(f"[ToolRegistry] Failed to register Metasploit module {name}: {e}")
            return False
    
    def _verify_tool_at_path(self, name: str, path: str) -> bool:
        """Verify that a tool actually exists and is executable at the given path"""
        try:
            # For local tools, check file existence and executability
            if not path.startswith('ssh://'):  # Local path
                if os.path.exists(path) and os.access(path, os.X_OK):
                    return True
                # Also check if it's in PATH
                if os.path.basename(path) == path:  # Just a command name
                    result = subprocess.run(['which', path], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout.strip():
                        return True
            else:
                # For remote tools via SSH, we'd need to check via SSH client
                # This would be implemented when we have SSH integration
                logger.debug(f"[ToolRegistry] Remote tool verification needed for {path}")
                return True  # For now, assume remote tools are valid if they reach here
            
            return False
        except Exception as e:
            logger.debug(f"[ToolRegistry] Tool verification failed for {name} at {path}: {e}")
            return False
    
    def is_tool_registered(self, name: str) -> bool:
        """Check if a tool is registered in the ground-truth registry"""
        with self._get_connection() as conn:
            cursor = conn.execute('''
                SELECT COUNT(*) as count FROM tool_registry 
                WHERE name = ? AND verified = 1
            ''', (name,))
            return cursor.fetchone()['count'] > 0
    
    def get_tool_path(self, name: str) -> Optional[str]:
        """Get the registered path for a tool"""
        with self._get_connection() as conn:
            cursor = conn.execute('''
                SELECT path FROM tool_registry 
                WHERE name = ? AND verified = 1
            ''', (name,))
            row = cursor.fetchone()
            return row['path'] if row else None
    
    def get_tool_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get complete information about a registered tool"""
        with self._get_connection() as conn:
            cursor = conn.execute('''
                SELECT name, path, version, category, description, metadata 
                FROM tool_registry 
                WHERE name = ? AND verified = 1
            ''', (name,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                if result['metadata']:
                    result['metadata'] = json.loads(result['metadata'])
                return result
        return None
    
    def get_all_registered_tools(self) -> List[Dict[str, Any]]:
        """Get all registered tools"""
        with self._get_connection() as conn:
            cursor = conn.execute('''
                SELECT name, path, version, category, description, metadata 
                FROM tool_registry 
                WHERE verified = 1
                ORDER BY name
            ''')
            tools = []
            for row in cursor:
                tool = dict(row)
                if tool['metadata']:
                    tool['metadata'] = json.loads(tool['metadata'])
                tools.append(tool)
            return tools
    
    def get_tools_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get tools by category"""
        with self._get_connection() as conn:
            cursor = conn.execute('''
                SELECT name, path, version, category, description, metadata 
                FROM tool_registry 
                WHERE category = ? AND verified = 1
                ORDER BY name
            ''', (category,))
            tools = []
            for row in cursor:
                tool = dict(row)
                if tool['metadata']:
                    tool['metadata'] = json.loads(tool['metadata'])
                tools.append(tool)
            return tools
    
    def remove_tool(self, name: str) -> bool:
        """Remove a tool from the registry"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute('DELETE FROM tool_registry WHERE name = ?', (name,))
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"[ToolRegistry] Failed to remove tool {name}: {e}")
            return False
    
    def refresh_registry(self, tool_discoverer) -> Dict[str, Any]:
        """
        Refresh the registry by scanning the system for available tools.
        This is the only method that should update the registry from system discovery.
        """
        logger.info("[ToolRegistry] Refreshing tool registry...")
        
        # Get discovered tools
        discovered_tools = tool_discoverer.scan_for_tools()
        
        # Track changes
        registered_count = 0
        updated_count = 0
        
        for tool_info in discovered_tools:
            name = tool_info.get('name', '')
            path = tool_info.get('path', '')
            
            if name and path:
                # Get existing tool info to preserve some data
                existing_info = self.get_tool_info(name)
                
                # Use existing description/version if available, otherwise use new
                description = tool_info.get('description', '')
                if existing_info and existing_info.get('description'):
                    description = existing_info['description']
                
                version = tool_info.get('version', '')
                if existing_info and existing_info.get('version'):
                    version = existing_info['version']
                
                category = tool_info.get('category', 'misc')
                if existing_info and existing_info.get('category'):
                    category = existing_info['category']
                
                metadata = tool_info.get('metadata', {})
                if existing_info and existing_info.get('metadata'):
                    # Merge metadata, giving preference to new discovery info
                    existing_metadata = existing_info['metadata'] or {}
                    metadata = {**existing_metadata, **metadata}
                
                # Register or update the tool
                if self.register_tool(
                    name=name,
                    path=path,
                    version=version,
                    category=category,
                    description=description,
                    metadata=metadata
                ):
                    registered_count += 1
                else:
                    logger.warning(f"[ToolRegistry] Failed to register/update tool: {name}")
        
        # Get all registered tools to compare with discovered tools
        registered_tools = {tool['name'] for tool in self.get_all_registered_tools()}
        discovered_tool_names = {tool.get('name', '') for tool in discovered_tools if tool.get('name')}
        
        # Remove tools that are no longer available
        removed_tools = registered_tools - discovered_tool_names
        for tool_name in removed_tools:
            if self.remove_tool(tool_name):
                logger.info(f"[ToolRegistry] Removed unavailable tool: {tool_name}")
        
        result = {
            'registered_count': registered_count,
            'updated_count': updated_count,
            'removed_count': len(removed_tools),
            'total_registered': len(self.get_all_registered_tools())
        }
        
        logger.info(f"[ToolRegistry] Refresh completed: {result}")
        return result
    
    def validate_command_for_tool(self, tool_name: str, command: str) -> bool:
        """
        Validate that a command uses only registered tools.
        This is critical for security - only commands from registered tools should be allowed.
        """
        # Extract the main command from the full command string
        # This handles cases like "nmap -p 80 example.com" where we extract "nmap"
        match = re.match(r'^(\S+)', command.split('|')[0].split(';')[0].split('&')[0])  # Handle pipes and command separators
        if not match:
            logger.warning(f"[ToolRegistry] Could not extract tool name from command: {command}")
            return False
        
        extracted_tool = match.group(1).split('/')[-1]  # Get basename in case of full path
        
        # Check if the extracted tool is registered
        if not self.is_tool_registered(extracted_tool):
            logger.warning(f"[ToolRegistry] Command uses unregistered tool: {extracted_tool} in '{command}'")
            return False
        
        # Additional check: if the tool name parameter doesn't match the command, verify consistency
        if tool_name != extracted_tool:
            # This might be a legitimate case where we're using an alternative path for the same tool
            # In this case, check if the original tool name is registered
            if not self.is_tool_registered(tool_name):
                logger.warning(f"[ToolRegistry] Tool parameter '{tool_name}' is not registered: {command}")
                return False
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics"""
        with self._get_connection() as conn:
            # Tool count by category
            cursor = conn.execute('''
                SELECT category, COUNT(*) as count 
                FROM tool_registry 
                WHERE verified = 1 
                GROUP BY category
            ''')
            category_counts = {row['category']: row['count'] for row in cursor}
            
            total_tools = sum(category_counts.values())
            
            # Metasploit modules count
            msf_cursor = conn.execute('SELECT COUNT(*) as count FROM metasploit_modules WHERE verified = 1')
            msf_count = msf_cursor.fetchone()['count']
            
            return {
                'total_tools': total_tools,
                'category_counts': category_counts,
                'metasploit_modules': msf_count,
                'registry_path': str(self.db_path)
            }


# Global instance
_tool_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get or create singleton tool registry instance"""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
    return _tool_registry


def is_tool_registered(name: str) -> bool:
    """Convenience function to check if a tool is registered"""
    registry = get_tool_registry()
    return registry.is_tool_registered(name)


def get_registered_tool_path(name: str) -> Optional[str]:
    """Convenience function to get registered tool path"""
    registry = get_tool_registry()
    return registry.get_tool_path(name)


def validate_command_tool(command: str) -> bool:
    """Convenience function to validate command uses registered tools"""
    registry = get_tool_registry()
    # Extract tool name from command for validation
    match = re.match(r'^(\S+)', command.split('|')[0].split(';')[0].split('&')[0])
    if match:
        tool_name = match.group(1).split('/')[-1]
        return registry.validate_command_for_tool(tool_name, command)
    return False

def get_command_validator():
    """Get the command safety validator for use in tool execution"""
    from .command_safety import safe_executor
    return safe_executor
