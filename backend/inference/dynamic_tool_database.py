"""Dynamic Tool Database - Comprehensive tool metadata and requirements"""

from typing import Dict, Any, List, Optional

class DynamicToolDatabase:
    """Comprehensive database of security tools with metadata and requirements"""

    def __init__(self):
        self.tools = self._initialize_tool_database()
        # Initialize tool success tracking
        self.tool_success_stats = {}

    def _initialize_tool_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Comprehensive tool database with:
        - Tool metadata (name, category, purpose)
        - Vulnerability detection capabilities
        - Platform compatibility
        - Execution requirements
        - Success indicators
        """
        return {
            # Web Application Tools
            'nikto': {
                'category': 'web_scanner',
                'capabilities': ['web_vuln_detection', 'misconfig_detection', 'outdated_software'],
                'detects': ['xss', 'sql_injection', 'path_traversal', 'info_disclosure'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'low',
                'prerequisites': ['http_service'],
                'output_parser': 'nikto',
            },
            'sqlmap': {
                'category': 'sql_exploitation',
                'capabilities': ['sql_injection_detection', 'database_extraction', 'os_command_execution'],
                'detects': ['sql_injection', 'database_errors'],
                'platform': 'any',
                'speed': 'slow',
                'stealth': 'low',
                'prerequisites': ['http_service', 'database_backend'],
                'output_parser': 'sqlmap',
            },
            'dalfox': {
                'category': 'xss_scanner',
                'capabilities': ['xss_detection', 'dom_based_xss', 'reflected_xss'],
                'detects': ['xss', 'dom_xss'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'medium',
                'prerequisites': ['http_service'],
                'output_parser': 'dalfox',
            },
            'commix': {
                'category': 'command_injection',
                'capabilities': ['command_injection_detection', 'os_command_execution'],
                'detects': ['command_injection', 'rce'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'medium',
                'prerequisites': ['http_service'],
                'output_parser': 'commix',
            },
            'nuclei': {
                'category': 'vulnerability_scanner',
                'capabilities': ['template_based_scanning', 'cve_detection', 'misconfig_detection'],
                'detects': ['cve', 'misconfigurations', 'exposures'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'medium',
                'prerequisites': ['http_service'],
                'output_parser': 'nuclei',
            },
            
            # Network Scanners
            'nmap': {
                'category': 'network_scanner',
                'capabilities': ['port_scanning', 'service_detection', 'os_fingerprinting'],
                'detects': ['open_ports', 'services', 'os_info'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'medium',
                'prerequisites': ['network_access'],
                'output_parser': 'nmap',
            },
            'masscan': {
                'category': 'network_scanner',
                'capabilities': ['high_speed_port_scanning'],
                'detects': ['open_ports'],
                'platform': 'any',
                'speed': 'very_fast',
                'stealth': 'low',
                'prerequisites': ['network_access'],
                'output_parser': 'masscan',
            },
            
            # Subdomain Enumeration
            'sublist3r': {
                'category': 'subdomain_enum',
                'capabilities': ['passive_subdomain_discovery'],
                'detects': ['subdomains'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'sublist3r',
                'requires_api': False,  # Does not require API keys
            },
            'subfinder': {
                'category': 'subdomain_enum',
                'capabilities': ['passive_subdomain_discovery', 'active_subdomain_bruteforcing'],
                'detects': ['subdomains'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'subfinder',
                'requires_api': True,  # May require API keys for some sources
                'api_keys': ['SUBFINDER_API_KEY'],
                'fallback_tools': ['sublist3r'],
            },
            'amass': {
                'category': 'subdomain_enum',
                'capabilities': ['in_depth_subdomain_enumeration', 'dns_analysis'],
                'detects': ['subdomains', 'dns_info'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'amass',
                'requires_api': True,  # May require API keys for some sources
                'api_keys': ['AMASS_API_KEY'],
                'fallback_tools': ['sublist3r'],
            },
            'theHarvester': {
                'category': 'email_enum',
                'capabilities': ['email_discovery', 'employee_discovery'],
                'detects': ['emails', 'employees'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'theHarvester',
                'requires_api': True,  # Requires API keys for most sources
                'api_keys': ['SHODAN_API_KEY'],  # Example - could have more
                'fallback_tools': ['sublist3r'],
            },
            
            # Web Crawlers
            'gospider': {
                'category': 'web_crawler',
                'capabilities': ['link_crawling', 'javascript_parsing'],
                'detects': ['urls', 'endpoints'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'medium',
                'prerequisites': ['http_service'],
                'output_parser': 'gospider',
            },
            'katana': {
                'category': 'web_crawler',
                'capabilities': ['advanced_crawling', 'headless_scraping'],
                'detects': ['urls', 'forms', 'endpoints'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'medium',
                'prerequisites': ['http_service'],
                'output_parser': 'katana',
            },
            
            # Fuzzing Tools
            'ffuf': {
                'category': 'fuzzer',
                'capabilities': ['directory_fuzzing', 'parameter_fuzzing'],
                'detects': ['hidden_directories', 'parameters'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'medium',
                'prerequisites': ['http_service'],
                'output_parser': 'ffuf',
            },
            'wfuzz': {
                'category': 'fuzzer',
                'capabilities': ['web_fuzzing', 'brute_force'],
                'detects': ['directories', 'parameters', 'vulns'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'medium',
                'prerequisites': ['http_service'],
                'output_parser': 'wfuzz',
            },
            
            # CMS Scanners
            'wpscan': {
                'category': 'cms_scanner',
                'capabilities': ['wordpress_vuln_scanning', 'plugin_detection'],
                'detects': ['wp_vulns', 'plugins', 'themes'],
                'platform': 'any',
                'speed': 'medium',
                'stealth': 'low',
                'prerequisites': ['wordpress_site'],
                'output_parser': 'wpscan',
            },
            
            # Parameter Discovery
            'arjun': {
                'category': 'parameter_discovery',
                'capabilities': ['parameter_identification'],
                'detects': ['hidden_parameters'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['http_service'],
                'output_parser': 'arjun',
            },
            
            # Additional Tools
            'whatweb': {
                'category': 'web_profiler',
                'capabilities': ['technology_detection', 'fingerprinting'],
                'detects': ['technologies', 'versions'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['http_service'],
                'output_parser': 'whatweb',
            },
            'httprobe': {
                'category': 'http_verifier',
                'capabilities': ['http_endpoint_verification'],
                'detects': ['live_hosts'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['hosts_list'],
                'output_parser': 'httprobe',
            },
            'shodan': {
                'category': 'network_scanner',
                'capabilities': ['internet_scanning', 'service_detection'],
                'detects': ['services', 'vulnerabilities'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'shodan',
                'requires_api': True,
                'api_keys': ['SHODAN_API_KEY'],
                'api_optional': False,
                'fallback_tools': ['nmap'],
            },
            'netlas': {
                'category': 'network_scanner',
                'capabilities': ['internet_scanning', 'service_detection'],
                'detects': ['services', 'vulnerabilities'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'netlas',
                'requires_api': True,
                'api_keys': ['NETLAS_API_KEY'],
                'api_optional': False,
                'fallback_tools': ['nmap'],
            },
            'onyphe': {
                'category': 'network_scanner',
                'capabilities': ['internet_scanning', 'service_detection'],
                'detects': ['services', 'vulnerabilities'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'onyphe',
                'requires_api': True,
                'api_keys': ['ONYPHE_API_KEY'],
                'api_optional': False,
                'fallback_tools': ['nmap'],
            }
        }

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tool"""
        return self.tools.get(tool_name)

    def get_tools_requiring_api(self) -> List[str]:
        """Get list of tools that require API keys"""
        return [tool for tool, info in self.tools.items() if info.get('requires_api', False)]

    def get_api_requirements(self, tool_name: str) -> Optional[List[str]]:
        """Get API key requirements for a specific tool"""
        tool_info = self.tools.get(tool_name)
        if tool_info and tool_info.get('requires_api', False):
            return tool_info.get('api_keys', [])
        return None

    def record_tool_success(self, tool_name: str, success: bool):
        """
        Record tool execution success/failure for learning purposes
        
        Args:
            tool_name: Name of the tool executed
            success: Whether the tool successfully found vulnerabilities
        """
        if tool_name not in self.tool_success_stats:
            self.tool_success_stats[tool_name] = {
                'executions': 0,
                'successes': 0,
                'success_rate': 0.0
            }
        
        stats = self.tool_success_stats[tool_name]
        stats['executions'] += 1
        if success:
            stats['successes'] += 1
        
        # Update success rate
        if stats['executions'] > 0:
            stats['success_rate'] = stats['successes'] / stats['executions']

    def get_tool_success_rate(self, tool_name: str) -> float:
        """
        Get the success rate of a tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Success rate as a float between 0.0 and 1.0
        """
        if tool_name in self.tool_success_stats:
            return self.tool_success_stats[tool_name]['success_rate']
        return 0.0

    def get_all_tool_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get statistics for all tools
        
        Returns:
            Dictionary of tool statistics
        """
        return self.tool_success_stats