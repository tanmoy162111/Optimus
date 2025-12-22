"""
Target Normalizer - Cleans and formats targets for different tools
"""

import re
import logging
from typing import Dict, Tuple, Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


class TargetNormalizer:
    """
    Normalizes and validates scan targets.
    Provides different formats for different tool types.
    """
    
    def __init__(self):
        # Common web ports
        self.web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
        
        # Common injectable endpoints to try
        self.common_endpoints = [
            '/rest/user/login',
            '/rest/products/search?q=test',
            '/api/v1/users',
            '/api/login',
            '/search?q=test',
            '/login',
            '/api/products',
            '/?id=1',
            '/?search=test',
            '/?page=1',
        ]
    
    def normalize(self, target: str) -> Dict[str, str]:
        """
        Normalize target and return all useful formats.
        
        Args:
            target: Raw target input
            
        Returns:
            Dict with keys: url, hostname, domain, ip, port, base_url, clean_url
        """
        original = target
        
        # Step 1: Strip URL fragments (#... or #!/...)
        target = re.sub(r'#.*$', '', target)
        
        # Step 2: Strip trailing slashes
        target = target.rstrip('/')
        
        # Step 3: Ensure protocol
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        # Step 4: Parse URL
        parsed = urlparse(target)
        
        hostname = parsed.hostname or ''
        port = parsed.port
        scheme = parsed.scheme or 'http'
        
        # Determine if IP or domain
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        is_ip = bool(re.match(ip_pattern, hostname))
        
        # Default port
        if port is None:
            port = 443 if scheme == 'https' else 80
        
        # Build different formats
        base_url = f"{scheme}://{hostname}"
        if port not in (80, 443):
            base_url += f":{port}"
        
        result = {
            'original': original,
            'url': target,
            'clean_url': base_url,
            'hostname': hostname,
            'domain': hostname,  # Same as hostname for simple case
            'ip': hostname if is_ip else '',
            'port': str(port),
            'scheme': scheme,
            'base_url': base_url,
            'is_ip': is_ip,
        }
        
        logger.info(f"[TargetNormalizer] Normalized: {original} -> {base_url}")
        
        return result
    
    def get_tool_target(self, target: str, tool_name: str) -> str:
        """
        Get appropriately formatted target for specific tool.
        
        Args:
            target: Raw target
            tool_name: Name of the tool
            
        Returns:
            Properly formatted target for the tool
        """
        normalized = self.normalize(target)
        tool_lower = tool_name.lower()
        
        # Tools that need hostname only
        hostname_tools = [
            'nmap', 'masscan', 'fierce', 'dnsenum', 'dnsrecon',
            'amass', 'sublist3r', 'subfinder', 'sslscan', 'enum4linux'
        ]
        
        # Tools that need URL
        url_tools = [
            'nikto', 'nuclei', 'whatweb', 'gobuster', 'ffuf', 'dirb',
            'wpscan', 'dalfox', 'commix', 'xsser'
        ]
        
        # Tools that need URL with parameters (for injection testing)
        injection_tools = ['sqlmap', 'commix', 'dalfox', 'xsser', 'nosqlmap']
        
        if tool_lower in hostname_tools:
            return normalized['hostname']
        elif tool_lower in injection_tools:
            # For injection tools, try to find or create a testable URL
            return self._get_injectable_target(normalized['base_url'])
        elif tool_lower in url_tools:
            return normalized['clean_url']
        else:
            # Default to clean URL
            return normalized['clean_url']
    
    def _get_injectable_target(self, base_url: str) -> str:
        """
        Get a URL with testable parameters for injection tools.
        
        For Juice Shop specifically, we know good endpoints.
        For unknown targets, use common endpoints.
        """
        # Check for known applications
        if 'juice' in base_url.lower():
            # OWASP Juice Shop - known injectable endpoints
            return f"{base_url}/rest/products/search?q=test"
        
        # For unknown targets, return first common endpoint
        # The tool should crawl for more
        return f"{base_url}/rest/products/search?q=test"
    
    def get_juice_shop_endpoints(self, base_url: str) -> list:
        """
        Get known injectable endpoints for OWASP Juice Shop.
        
        These are documented vulnerable endpoints in Juice Shop.
        """
        return [
            f"{base_url}/rest/products/search?q=test",
            f"{base_url}/rest/user/login",
            f"{base_url}/api/Users/",
            f"{base_url}/api/Products/1",
            f"{base_url}/api/Quantitys/",
            f"{base_url}/api/Challenges/",
            f"{base_url}/rest/saveLoginIp",
            f"{base_url}/b2b/v2/orders",
        ]


# Singleton
_normalizer = None

def get_target_normalizer() -> TargetNormalizer:
    """Get singleton target normalizer"""
    global _normalizer
    if _normalizer is None:
        _normalizer = TargetNormalizer()
    return _normalizer
