"""
Tool Discovery System - Enhanced for executables, Metasploit modules, and version scanning
"""
import logging
import os
import subprocess
import re
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
        "/usr/local/sbin",
        "/opt",
        "/home/kali/go/bin",
        "/root/go/bin"
    ]
    
    # Extended security tools to look for
    SECURITY_TOOLS = [
        # Scanners
        "nmap", "nikto", "sqlmap", "nuclei", "wpscan", "gobuster", "ffuf", "dirb",
        "masscan", "rustscan", "subfinder", "amass", "sublist3r", "httprobe",
        "httpx", "katana", "gospider", "arjun", "netlas", "onyphe", "xsser",
        "dalfox", "commix", "zap", "burpsuite", "nessus", "openvas",
        # Network tools
        "netcat", "nc", "tcpdump", "wireshark", "tshark", "nmap", "masscan",
        "arping", "hping3", "scapy", "ettercap", "mitmproxy",
        # Password tools
        "john", "hashcat", "hydra", "medusa", "cewl", "wordlists",
        # Exploitation
        "metasploit", "msfconsole", "msfvenom", "armitage", "cain",
        # Wireless
        "aircrack-ng", "kismet", "reaver", "bully", "mdk3",
        # Forensics
        "volatility", "autopsy", "sleuthkit", "testdisk", "photorec",
        # Web tools
        "curl", "wget", "whatweb", "wafw00f", "dirb", "gobuster", "ffuf",
        # DNS tools
        "dig", "nslookup", "host", "fierce", "dnsenum", "dnsrecon",
        # Miscellaneous
        "openssl", "ssh", "nbtscan", "enum4linux", "smbclient",
        "sslscan", "testssl", "nikto", "dirbuster"
    ]
    
    # Metasploit module types to look for
    METASPLOIT_MODULE_TYPES = [
        "exploit", "auxiliary", "post", "payload", "encoder", "nop"
    ]
    
    def __init__(self, ssh_client=None):
        self.ssh_client = ssh_client
        self.found_tools = []
        self.found_metasploit_modules = []
    
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
    
    def scan_for_metasploit_modules(self) -> List[Dict[str, Any]]:
        """Scan for Metasploit modules"""
        modules = []
        
        if self.ssh_client:
            modules.extend(self._scan_remote_metasploit_modules())
        else:
            modules.extend(self._scan_local_metasploit_modules())
        
        self.found_metasploit_modules = modules
        return modules
    
    def scan_for_executables(self) -> List[Dict[str, Any]]:
        """Scan for all executables in common security directories"""
        executables = []
        
        # Define security-related directories to scan
        security_dirs = [
            "/usr/bin", "/bin", "/usr/local/bin",
            "/opt", "/opt/metasploit", "/opt/nmap", "/opt/nikto",
            "/home/kali/go/bin", "/root/go/bin",
            "/usr/share", "/usr/lib"
        ]
        
        for directory in security_dirs:
            if self.ssh_client:
                executables.extend(self._scan_remote_executables_in_dir(directory))
            else:
                executables.extend(self._scan_local_executables_in_dir(directory))
        
        return executables
    
    def _scan_remote_system(self) -> List[Dict[str, Any]]:
        """Scan remote system via SSH"""
        tools = []
        
        try:
            # Check which tools are available using which command
            for tool in self.SECURITY_TOOLS:
                result = self.ssh_client.execute_command(f"command -v {tool} || which {tool}")
                if result and result.get('success', False) and result.get('stdout', '').strip():
                    path = result.get('stdout', '').strip()
                    if path:
                        # Get version info
                        version = self._get_remote_tool_version(tool)
                        tools.append({
                            "name": tool,
                            "path": path,
                            "version": version,
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
                                version = self._get_local_tool_version(tool)
                                tools.append({
                                    "name": tool,
                                    "path": tool_path,
                                    "version": version,
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
                                version = self._get_local_tool_version(tool)
                                tools.append({
                                    "name": tool,
                                    "path": tool_path,
                                    "version": version,
                                    "available": True,
                                    "source": "path"
                                })
            except Exception as e:
                logger.debug(f"Error scanning PATH directory {path_dir}: {e}")
        
        return tools
    
    def _get_remote_tool_version(self, tool_name: str) -> str:
        """Get version information for a remote tool"""
        try:
            # Try different version flags
            version_flags = ["--version", "-v", "-V", "version", "--V"]
            
            for flag in version_flags:
                try:
                    # For remote tools
                    result = self.ssh_client.execute_command(f"{tool_name} {flag}")
                    if result and result.get('success', False):
                        output = result.get('stdout', '').split('\n')[0]
                        # Extract version from common patterns
                        version_match = re.search(r'(\d+\.\d+(\.\d+)?(\.\d+)?)|([\w\d\.\-]+)', output)
                        if version_match:
                            return version_match.group(0)
                        return output.strip()[:100]  # Limit length
                except Exception:
                    continue
            
            # Try alternative methods
            if tool_name == 'nmap':
                result = self.ssh_client.execute_command(f"{tool_name} --version")
                if result and result.get('success', False):
                    output = result.get('stdout', '')
                    version_match = re.search(r'Nmap version (\d+\.\d+)', output)
                    if version_match:
                        return version_match.group(1)
            
            return "Unknown"
        except Exception as e:
            logger.debug(f"Error getting version for remote {tool_name}: {e}")
            return "Unknown"
    
    def _get_local_tool_version(self, tool_name: str) -> str:
        """Get version information for a local tool"""
        try:
            # Try different version flags
            version_flags = ["--version", "-v", "-V", "version", "--V"]
            
            for flag in version_flags:
                try:
                    result = subprocess.run(
                        [tool_name, flag],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0 or result.returncode == 1:  # Help usually returns 1
                        output = result.stdout.split('\n')[0]
                        # Extract version from common patterns
                        version_match = re.search(r'(\d+\.\d+(\.\d+)?(\.\d+)?)|([\w\d\.\-]+)', output)
                        if version_match:
                            return version_match.group(0)
                        return output.strip()[:100]  # Limit length
                except Exception:
                    continue
            
            # Try alternative methods
            if tool_name == 'nmap':
                result = subprocess.run([tool_name, '--version'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
                    if version_match:
                        return version_match.group(1)
            
            return "Unknown"
        except Exception as e:
            logger.debug(f"Error getting version for local {tool_name}: {e}")
            return "Unknown"
    
    def _scan_remote_metasploit_modules(self) -> List[Dict[str, Any]]:
        """Scan for Metasploit modules on remote system"""
        modules = []
        
        try:
            # Check if msfconsole is available
            result = self.ssh_client.execute_command("which msfconsole")
            if result and result.get('success', False):
                # List available modules using msfconsole
                for module_type in self.METASPLOIT_MODULE_TYPES:
                    cmd = f"msfconsole -q -x 'grep -r . /usr/share/metasploit-framework/modules/{module_type}/ 2>/dev/null | head -20'"
                    result = self.ssh_client.execute_command(cmd)
                    if result and result.get('success', False):
                        output = result.get('stdout', '')
                        # Parse module names from output
                        module_paths = output.split('\n')
                        for path in module_paths:
                            if path.strip() and ':' in path:
                                module_path = path.split(':')[0]
                                module_name = os.path.basename(module_path).replace('.rb', '')
                                modules.append({
                                    "name": module_name,
                                    "type": module_type,
                                    "path": module_path,
                                    "available": True,
                                    "source": "remote"
                                })
            
        except Exception as e:
            logger.error(f"Remote Metasploit module scan failed: {e}")
        
        return modules
    
    def _scan_local_metasploit_modules(self) -> List[Dict[str, Any]]:
        """Scan for Metasploit modules on local system"""
        modules = []
        
        try:
            # Check common Metasploit module directories
            msf_dirs = [
                "/usr/share/metasploit-framework/modules",
                "/opt/metasploit-framework/embedded/framework/modules"
            ]
            
            for base_dir in msf_dirs:
                if os.path.exists(base_dir):
                    for module_type in self.METASPLOIT_MODULE_TYPES:
                        type_dir = os.path.join(base_dir, module_type)
                        if os.path.exists(type_dir):
                            for root, dirs, files in os.walk(type_dir):
                                for file in files:
                                    if file.endswith('.rb'):
                                        module_name = file.replace('.rb', '')
                                        module_path = os.path.join(root, file)
                                        modules.append({
                                            "name": module_name,
                                            "type": module_type,
                                            "path": module_path,
                                            "available": True,
                                            "source": "local"
                                        })
        
        except Exception as e:
            logger.error(f"Local Metasploit module scan failed: {e}")
        
        return modules
    
    def _scan_remote_executables_in_dir(self, directory: str) -> List[Dict[str, Any]]:
        """Scan for executables in a specific directory on remote system"""
        executables = []
        
        try:
            # List files in directory and check for executables
            result = self.ssh_client.execute_command(f"find {directory} -type f -executable -name '*[a-z]*' 2>/dev/null | head -50")
            if result and result.get('success', False):
                output = result.get('stdout', '')
                for line in output.split('\n'):
                    if line.strip():
                        # Extract tool name from path
                        tool_name = os.path.basename(line.strip())
                        executables.append({
                            "name": tool_name,
                            "path": line.strip(),
                            "type": "executable",
                            "source": "remote"
                        })
        
        except Exception as e:
            logger.debug(f"Error scanning remote directory {directory}: {e}")
        
        return executables
    
    def _scan_local_executables_in_dir(self, directory: str) -> List[Dict[str, Any]]:
        """Scan for executables in a specific directory on local system"""
        executables = []
        
        try:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.access(file_path, os.X_OK) and os.path.isfile(file_path):
                            executables.append({
                                "name": file,
                                "path": file_path,
                                "type": "executable",
                                "source": "local"
                            })
        
        except Exception as e:
            logger.debug(f"Error scanning local directory {directory}: {e}")
        
        return executables
    
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

# Convenience functions
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
def discover_metasploit_modules(ssh_client=None) -> List[Dict[str, Any]]:
    """Discover Metasploit modules on the system"""
    discovery = ToolDiscovery(ssh_client)
    return discovery.scan_for_metasploit_modules()

def discover_executables(ssh_client=None) -> List[Dict[str, Any]]:
    """Discover all executables in security-related directories"""
    discovery = ToolDiscovery(ssh_client)
    return discovery.scan_for_executables()