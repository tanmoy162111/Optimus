"""
Unified Target Schema - Defines a single ValidatedTarget object for consistent target handling
"""
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class ValidatedTarget:
    """
    Unified target schema that contains all necessary target information
    and is passed intact from TargetIntegrityGate → Tool selection → Command execution
    """
    raw: str  # Raw target input
    normalized: str  # Normalized target format
    hostname: str  # Target hostname
    scheme: str  # Protocol (http, https, etc.)
    port: int  # Target port
    resolved_ip: str  # Resolved IP address
    is_authorized: bool  # Whether the target is authorized for scanning
    is_valid: bool  # Whether the target is valid
    is_ip: Optional[bool] = None  # Whether the target is an IP address
    tool_name: Optional[str] = None  # Tool this target is for (optional)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the target object to a dictionary"""
        return {
            'raw': self.raw,
            'normalized': self.normalized,
            'hostname': self.hostname,
            'scheme': self.scheme,
            'port': self.port,
            'resolved_ip': self.resolved_ip,
            'is_authorized': self.is_authorized,
            'is_valid': self.is_valid,
            'is_ip': self.is_ip,
            'tool_name': self.tool_name
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidatedTarget':
        """Create a ValidatedTarget from a dictionary"""
        return cls(
            raw=data.get('raw', ''),
            normalized=data.get('normalized', ''),
            hostname=data.get('hostname', ''),
            scheme=data.get('scheme', ''),
            port=data.get('port', 80),
            resolved_ip=data.get('resolved_ip', ''),
            is_authorized=data.get('is_authorized', False),
            is_valid=data.get('is_valid', False),
            is_ip=data.get('is_ip'),
            tool_name=data.get('tool_name')
        )
    
    def get_formatted_for_tool(self, tool_name: str) -> str:
        """
        Get the target formatted appropriately for a specific tool
        """
        tool_lower = tool_name.lower()
        
        # CLI network tools that need hostname/IP only (not full URLs)
        cli_network_tools = [
            'nmap', 'nikto', 'gobuster', 'ffuf', 'msfconsole', 'hydra', 'masscan', 'fierce', 'dnsenum', 'dnsrecon',
            'amass', 'sublist3r', 'subfinder', 'sslscan', 'enum4linux', 'sqlmap', 'dirb', 'wpscan'
        ]
        
        # Web tools that need full URL
        web_tools = [
            'whatweb', 'wafw00f', 'nuclei', 'dalfox', 'commix', 'xsser', 'nosqlmap'
        ]
        
        if tool_lower in cli_network_tools:
            # For CLI network tools, use hostname or IP only
            return self.hostname if self.hostname else self.resolved_ip
        elif tool_lower in web_tools:
            # For web tools, use full URL with port
            return self.normalized
        else:
            # Default to normalized target
            return self.normalized