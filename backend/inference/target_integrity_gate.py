"""
Target Integrity Gate - Validates and ensures target integrity throughout the system
"""
import re
import socket
import logging
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import ipaddress
import time

logger = logging.getLogger(__name__)

class TargetIntegrityError(Exception):
    """Raised when target integrity validation fails"""
    pass


class TargetIntegrityGate:
    """
    Validates and ensures target integrity throughout the system.
    Implements a gate that blocks invalid commands and ensures targets are properly handled.
    """
    
    def __init__(self):
        # Authorized target patterns (local/vulnerable lab environments)
        self.authorized_targets = [
            'localhost',
            '127.0.0.1',
            '192.168.',  # Private network ranges
            '10.',       # Private network ranges
            '172.',      # Private network ranges
            '0.0.0.0',
            '::1',
            'juice-shop',  # OWASP Juice Shop container name
            'dvwa',        # DVWA container name
            'metasploitable',  # Metasploitable container name
        ]
        
        # Blacklisted targets (to prevent accidental execution on unauthorized systems)
        self.blacklisted_targets = [
            'google.com',
            'microsoft.com',
            'amazon.com',
            'facebook.com',
            'apple.com',
            'netflix.com',
            'github.com',
            'gitlab.com',
        ]
        
        # IP ranges that should never be scanned
        self.blacklisted_networks = [
            '127.',      # Loopback
            '10.0.0.',   # Some cloud services
        ]
        
        # Common port ranges for different tool types
        self.network_scanning_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080, 8443]
        self.web_scanning_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090]

    def validate_raw_target(self, target: str) -> Dict[str, Any]:
        """
        Validates raw target input before any processing.
        
        Args:
            target: Raw target input
            
        Returns:
            Dict with validation results and processed target information
        """
        if not target or not isinstance(target, str):
            raise TargetIntegrityError("Target must be a non-empty string")
        
        # Strip whitespace
        target = target.strip()
        if not target:
            raise TargetIntegrityError("Target must be a non-empty string")
        
        # Log raw target
        logger.info(f"[TargetIntegrityGate] Raw target: {target}")
        
        # Check for obvious injection attempts
        injection_patterns = [
            r';.*',  # Command injection
            r'&&.*', # Command chaining
            r'\|\|.*', # Command chaining
            r'\$\(.*\)', # Command substitution
            r'`.*`', # Command substitution
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, target):
                raise TargetIntegrityError(f"Potential command injection detected in target: {target}")
        
        return {
            'raw_target': target,
            'is_valid': True,
            'normalized_target': target
        }

    def is_authorized_target(self, target: str) -> bool:
        """
        Check if target is in authorized list.
        
        Args:
            target: Target to check
            
        Returns:
            True if authorized, False otherwise
        """
        target_lower = target.lower().strip()
        
        # Check against blacklisted targets first
        for blacklisted in self.blacklisted_targets:
            if blacklisted in target_lower:
                logger.warning(f"[TargetIntegrityGate] Unauthorized target blocked: {target}")
                return False
        
        # Check if target matches any authorized patterns
        for auth_target in self.authorized_targets:
            if auth_target in target_lower or target_lower.startswith(auth_target.replace('.', '')):
                return True
        
        # Check if it's a localhost or private IP
        if target_lower in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
            return True
        
        # Check for private IP ranges
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private or ip.is_loopback:
                return True
        except ValueError:
            # Not an IP address, continue with hostname checks
            pass
        
        # Check if hostname resolves to private IP
        try:
            resolved_ip = socket.gethostbyname(target)
            ip = ipaddress.ip_address(resolved_ip)
            if ip.is_private or ip.is_loopback:
                return True
        except (socket.gaierror, ValueError):
            # Cannot resolve hostname, assume not authorized
            pass
        
        logger.warning(f"[TargetIntegrityGate] Unauthorized target: {target}")
        return False

    def resolve_hostname_to_ip(self, hostname: str) -> Tuple[str, str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            Tuple of (resolved_ip, original_hostname)
        """
        try:
            resolved_ip = socket.gethostbyname(hostname)
            logger.info(f"[TargetIntegrityGate] Resolved {hostname} to {resolved_ip}")
            return resolved_ip, hostname
        except socket.gaierror as e:
            logger.error(f"[TargetIntegrityGate] DNS resolution failed for {hostname}: {e}")
            raise TargetIntegrityError(f"Cannot resolve hostname: {hostname}")
        except Exception as e:
            logger.error(f"[TargetIntegrityGate] DNS resolution error for {hostname}: {e}")
            raise TargetIntegrityError(f"DNS resolution error: {e}")

    def validate_target_format(self, target: str) -> Dict[str, Any]:
        """
        Validate target format and extract components.
        
        Args:
            target: Target string to validate
            
        Returns:
            Dict with target components
        """
        # Handle different target formats
        original_target = target
        
        # Remove URL fragments
        target = re.sub(r'#.*$', '', target)
        
        # Remove trailing slashes
        target = target.rstrip('/')
        
        # Parse URL if it has protocol
        parsed = None
        try:
            if '://' not in target:
                # Assume http if no protocol specified
                temp_target = f'http://{target}'
                parsed = urlparse(temp_target)
            else:
                parsed = urlparse(target)
        except Exception:
            # If parsing fails, treat as hostname/IP
            pass
        
        if parsed and parsed.netloc:
            hostname = parsed.hostname or parsed.netloc.split(':')[0]
            port = parsed.port
            scheme = parsed.scheme
        else:
            # Try to extract hostname:port pattern
            if ':' in target and not target.startswith('http'):
                parts = target.split(':', 1)
                hostname = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    hostname = target
                    port = None
            else:
                hostname = target
                port = None
            
            scheme = 'http' if port in [80, 8080] else 'https' if port in [443, 8443] else 'http'
        
        # Validate hostname format
        if not hostname or len(hostname) > 255:
            raise TargetIntegrityError(f"Invalid hostname format: {hostname}")
        
        # Check for valid hostname characters
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-.]*[a-zA-Z0-9]$', hostname) and \
           not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
            raise TargetIntegrityError(f"Invalid hostname format: {hostname}")
        
        # Validate IP format if it's an IP
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
            ip_parts = hostname.split('.')
            if any(int(part) > 255 for part in ip_parts if part):
                raise TargetIntegrityError(f"Invalid IP address: {hostname}")
        
        # Determine if it's an IP or hostname
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
        
        # Set default port if not provided
        if port is None:
            if scheme == 'https':
                port = 443
            else:
                port = 80
        
        result = {
            'original_target': original_target,
            'hostname': hostname,
            'port': port,
            'scheme': scheme,
            'is_ip': is_ip,
            'is_valid': True,
            'normalized': f"{scheme}://{hostname}:{port}" if port not in [80, 443] else f"{scheme}://{hostname}"
        }
        
        logger.info(f"[TargetIntegrityGate] Validated target format: {result}")
        return result

    def apply_target_integrity_gate(self, target: str, tool_name: str = None) -> Dict[str, Any]:
        """
        Apply comprehensive target integrity validation.
        
        Args:
            target: Target to validate
            tool_name: Name of tool that will use this target (optional)
            
        Returns:
            Dict with validated target information
        """
        logger.info(f"[TargetIntegrityGate] Raw target: {target}")
        logger.info(f"[TargetIntegrityGate] Applying integrity gate for target: {target}, tool: {tool_name}")
        
        # Step 1: Validate raw target
        raw_validation = self.validate_raw_target(target)
        raw_target = raw_validation['raw_target']
        
        # Step 2: Validate target format
        format_validation = self.validate_target_format(raw_target)
        hostname = format_validation['hostname']
        port = format_validation['port']
        is_ip = format_validation['is_ip']
        
        # Log normalized target
        normalized_target = format_validation['normalized']
        logger.info(f"[TargetIntegrityGate] Normalized target: {normalized_target}")
        
        # Step 3: Check authorization
        if not self.is_authorized_target(hostname):
            raise TargetIntegrityError(f"Unauthorized target: {hostname}. Only local/vulnerable lab targets are allowed.")
        
        # Step 4: Resolve hostname to IP if it's not already an IP
        if not is_ip:
            resolved_ip, _ = self.resolve_hostname_to_ip(hostname)
        else:
            resolved_ip = hostname
            
        logger.info(f"[TargetIntegrityGate] Resolved IP: {resolved_ip}")
        
        # Step 5: Validate port based on tool type
        if tool_name:
            if tool_name.lower() in ['nmap', 'masscan'] and port not in self.network_scanning_ports:
                logger.warning(f"[TargetIntegrityGate] Non-standard port {port} for network scanner {tool_name}")
            elif tool_name.lower() in ['nikto', 'sqlmap', 'nuclei'] and port not in self.web_scanning_ports:
                logger.warning(f"[TargetIntegrityGate] Non-standard port {port} for web scanner {tool_name}")
        
        # Final result with all target information
        result = {
            'raw_target': raw_target,
            'normalized_target': normalized_target,
            'hostname': hostname,
            'port': port,
            'resolved_ip': resolved_ip,
            'is_ip': is_ip,
            'is_authorized': True,
            'is_valid': True,
            'tool_name': tool_name
        }
        
        logger.info(f"[TargetIntegrityGate] Target integrity validation PASSED: {result}")
        logger.info(f"[TargetIntegrityGate] Debug - Raw: {raw_target}, Normalized: {normalized_target}, Resolved IP: {resolved_ip}")
        return result

    def validate_and_prepare_for_execution(self, target: str, tool_name: str) -> str:
        """
        Validate target and return the appropriate format for tool execution.
        
        Args:
            target: Target to validate and format
            tool_name: Name of tool that will execute
            
        Returns:
            Formatted target string appropriate for the tool
        """
        # Apply integrity gate
        validation_result = self.apply_target_integrity_gate(target, tool_name)
        
        # Format target based on tool type
        tool_lower = tool_name.lower()
        
        # Tools that need hostname only (network tools)
        hostname_tools = [
            'nmap', 'masscan', 'fierce', 'dnsenum', 'dnsrecon',
            'amass', 'sublist3r', 'subfinder', 'sslscan', 'enum4linux'
        ]
        
        # Tools that need URL (web tools)
        url_tools = [
            'nikto', 'nuclei', 'whatweb', 'gobuster', 'ffuf', 'dirb',
            'wpscan', 'dalfox', 'commix', 'xsser'
        ]
        
        # Tools that need URL with parameters (for injection testing)
        injection_tools = ['sqlmap', 'commix', 'dalfox', 'xsser', 'nosqlmap']
        
        if tool_lower in hostname_tools:
            # For network tools, use resolved IP or hostname
            formatted_target = validation_result['resolved_ip'] if validation_result['is_ip'] else validation_result['hostname']
        elif tool_lower in injection_tools:
            # For injection tools, use full URL with port
            if validation_result['port'] not in [80, 443]:
                formatted_target = f"{validation_result['normalized_target']}"
            else:
                formatted_target = f"{validation_result['scheme']}://{validation_result['hostname']}"
        elif tool_lower in url_tools:
            # For web tools, use full URL with port
            formatted_target = validation_result['normalized_target']
        else:
            # Default to normalized target
            formatted_target = validation_result['normalized_target']
        
        # Log the final rendered target for debugging
        logger.info(f"[TargetIntegrityGate] Final rendered target for {tool_name}: {formatted_target}")
        logger.info(f"[TargetIntegrityGate] Debug - Raw: {validation_result['raw_target']}, Normalized: {validation_result['normalized_target']}, Final: {formatted_target}, Resolved IP: {validation_result['resolved_ip']}")
        
        return formatted_target


# Singleton instance
_target_integrity_gate = None


def get_target_integrity_gate() -> TargetIntegrityGate:
    """Get singleton target integrity gate instance"""
    global _target_integrity_gate
    if _target_integrity_gate is None:
        _target_integrity_gate = TargetIntegrityGate()
    return _target_integrity_gate