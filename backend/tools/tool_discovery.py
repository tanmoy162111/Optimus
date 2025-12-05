"""
Tool Discovery System
"""
import logging
import os
import subprocess
from typing import List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class ToolDiscovery:
    """Discover tools available on the system"""
    
    # Common tool paths to check
    COMMON_PATHS = [
        "/usr/bin",
        "/bin",
        "/usr/local/bin",
        "/sbin",
        "/usr/sbin",
        "/usr/local/sbin"
    ]
    
    # Common security tools to look for
    SECURITY_TOOLS = [
        # Scanners
        "nmap", "nikto", "sqlmap", "nuclei", "wpscan", "gobuster", "ffuf", "dirb",
        # Network tools
        "netcat", "nc", "tcpdump", "wireshark",
        # Password tools
        "john", "hashcat", "hydra",
        # Exploitation
        "metasploit", "msfconsole", "burpsuite",
        # Wireless
        "aircrack-ng", "kismet",
        # Forensics
        "volatility", "autopsy",
        # Miscellaneous
        "curl", "wget", "openssl"
    ]
    
    def __init__(self, ssh_client=None):
        self.ssh_client = ssh_client
        self.found_tools = []
    
    def scan_for_tools(self) -> List[Dict[str, Any]]:
        """Scan system for security tools"""
        tools = []
        
        # If we have SSH client, scan remote system
        if self.ssh_client:
            tools.extend(self._scan_remote_system())
        else:
            # Scan local system
            tools.extend(self._scan_local_system())
        
        self.found_tools = tools
        return tools
    
    def _scan_remote_system(self) -> List[Dict[str, Any]]:
        """Scan remote system via SSH"""
        tools = []
        
        try:
            # Check which tools are available
            for tool in self.SECURITY_TOOLS:
                result = self.ssh_client.execute_command(f"which {tool}")
                if result and result.get('success', False):
                    path = result.get('stdout', '').strip()
                    if path:
                        tools.append({
                            "name": tool,
                            "path": path,
                            "available": True,
                            "source": "remote"
                        })
        except Exception as e:
            logger.error(f"Remote tool scan failed: {e}")
        
        return tools
    
    def _scan_local_system(self) -> List[Dict[str, Any]]:
        """Scan local system"""
        tools = []
        
        # Check common paths
        for path in self.COMMON_PATHS:
            if os.path.exists(path):
                try:
                    for tool in self.SECURITY_TOOLS:
                        tool_path = os.path.join(path, tool)
                        if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
                            # Check if it's already in our list
                            if not any(t["name"] == tool for t in tools):
                                tools.append({
                                    "name": tool,
                                    "path": tool_path,
                                    "available": True,
                                    "source": "local"
                                })
                except Exception as e:
                    logger.debug(f"Error scanning {path}: {e}")
        
        # Also check PATH
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        for path_dir in path_dirs:
            try:
                if os.path.exists(path_dir):
                    for tool in self.SECURITY_TOOLS:
                        tool_path = os.path.join(path_dir, tool)
                        if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
                            # Check if it's already in our list
                            if not any(t["name"] == tool for t in tools):
                                tools.append({
                                    "name": tool,
                                    "path": tool_path,
                                    "available": True,
                                    "source": "path"
                                })
            except Exception as e:
                logger.debug(f"Error scanning PATH directory {path_dir}: {e}")
        
        return tools
    
    def get_tool_help(self, tool_name: str) -> str:
        """Get help text for a tool"""
        try:
            # Try different help flags
            help_flags = ["--help", "-h", "help"]
            
            for flag in help_flags:
                try:
                    # For local tools
                    if not self.ssh_client:
                        result = subprocess.run(
                            [tool_name, flag],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if result.returncode == 0 or result.returncode == 1:  # Help usually returns 1
                            return result.stdout
                    else:
                        # For remote tools
                        result = self.ssh_client.execute_command(f"{tool_name} {flag}")
                        if result and result.get('success', False):
                            return result.get('stdout', '')
                except Exception:
                    continue
            
            return ""
        except Exception as e:
            logger.error(f"Error getting help for {tool_name}: {e}")
            return ""
    
    def get_tool_version(self, tool_name: str) -> str:
        """Get version information for a tool"""
        try:
            # Try different version flags
            version_flags = ["--version", "-v", "version"]
            
            for flag in version_flags:
                try:
                    # For local tools
                    if not self.ssh_client:
                        result = subprocess.run(
                            [tool_name, flag],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if result.returncode == 0:
                            return result.stdout.split('\n')[0]  # First line usually has version
                    else:
                        # For remote tools
                        result = self.ssh_client.execute_command(f"{tool_name} {flag}")
                        if result and result.get('success', False):
                            return result.get('stdout', '').split('\n')[0]
                except Exception:
                    continue
            
            return "Unknown"
        except Exception as e:
            logger.error(f"Error getting version for {tool_name}: {e}")
            return "Unknown"
    
    def categorize_tool(self, tool_name: str) -> str:
        """Categorize a tool based on its name"""
        tool_lower = tool_name.lower()
        
        # Scanner category
        if any(scanner in tool_lower for scanner in ["nmap", "nikto", "nuclei", "wpscan", "gobuster", "ffuf", "dirb", "scan"]):
            return "scanner"
        
        # Password category
        if any(password in tool_lower for password in ["john", "hashcat", "hydra", "password"]):
            return "password"
        
        # Exploitation category
        if any(exploit in tool_lower for exploit in ["metasploit", "msf", "exploit", "sqlmap"]):
            return "exploitation"
        
        # Network category
        if any(network in tool_lower for network in ["netcat", "nc", "tcpdump", "wireshark", "network"]):
            return "network"
        
        # Wireless category
        if any(wireless in tool_lower for wireless in ["aircrack", "kismet", "wireless"]):
            return "wireless"
        
        # Forensics category
        if any(forensics in tool_lower for forensics in ["volatility", "autopsy", "forensic"]):
            return "forensics"
        
        # Web category
        if any(web in tool_lower for web in ["curl", "wget", "burp", "zap", "web"]):
            return "web"
        
        return "misc"
    
    def enrich_tool_info(self, tool: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich tool information with help text, version, and category"""
        tool_name = tool["name"]
        
        # Get help text
        help_text = self.get_tool_help(tool_name)
        tool["help_text"] = help_text[:2000] if help_text else ""  # Limit size
        
        # Get version
        version = self.get_tool_version(tool_name)
        tool["version"] = version
        
        # Categorize
        category = self.categorize_tool(tool_name)
        tool["category"] = category
        
        return tool

# Convenience function
def discover_tools(ssh_client=None) -> List[Dict[str, Any]]:
    """Discover tools on the system"""
    discovery = ToolDiscovery(ssh_client)
    tools = discovery.scan_for_tools()
    
    # Enrich tool information
    enriched_tools = []
    for tool in tools:
        enriched_tool = discovery.enrich_tool_info(tool)
        enriched_tools.append(enriched_tool)
    
    return enriched_tools