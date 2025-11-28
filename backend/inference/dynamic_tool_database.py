"""
Dynamic Tool Database
Maintains comprehensive tool knowledge with capabilities, detection signatures, and usage patterns
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class DynamicToolDatabase:
    """
    Central repository of all penetration testing tools with AI-driven selection
    """

    def __init__(self):
        self.tools = self._initialize_tool_database()
        self.tool_capabilities = self._map_tool_capabilities()
        self.tool_success_history = {}  # Track tool effectiveness

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
            'subfinder': {
                'category': 'subdomain_enum',
                'capabilities': ['passive_subdomain_discovery', 'active_subdomain_bruteforcing'],
                'detects': ['subdomains'],
                'platform': 'any',
                'speed': 'fast',
                'stealth': 'high',
                'prerequisites': ['domain_target'],
                'output_parser': 'subfinder',
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
            }
        }

    def _map_tool_capabilities(self) -> Dict[str, List[str]]:
        """
        Create a reverse mapping from capabilities to tools
        """
        capability_map = {}
        for tool_name, tool_info in self.tools.items():
            for capability in tool_info.get('capabilities', []):
                if capability not in capability_map:
                    capability_map[capability] = []
                capability_map[capability].append(tool_name)
        return capability_map

    def get_tools_for_context(self, scan_context: Dict) -> List[str]:
        """
        AI-driven tool selection based on scan context
        Returns ranked list of recommended tools
        """
        # Analyze context
        phase = scan_context.get('phase')
        findings = scan_context.get('findings', [])
        target_type = scan_context.get('target_type')
        technologies = scan_context.get('technologies_detected', [])
        
        # Filter tools by prerequisites
        applicable_tools = self._filter_by_prerequisites(scan_context)
        
        # Score tools by relevance
        tool_scores = self._score_tools(applicable_tools, scan_context)
        
        # Sort by score and return top N
        ranked_tools = sorted(tool_scores.items(), key=lambda x: x[1], reverse=True)
        
        return [tool for tool, score in ranked_tools[:10]]

    def _filter_by_prerequisites(self, scan_context: Dict) -> List[str]:
        """
        Filter tools based on whether their prerequisites are met
        """
        applicable_tools = []
        findings = scan_context.get('findings', [])
        target_type = scan_context.get('target_type')
        technologies = scan_context.get('technologies_detected', [])
        
        # Create a set of satisfied prerequisites based on context
        satisfied_prerequisites = set(['any'])
        
        # Add target type as prerequisite if available
        if target_type:
            satisfied_prerequisites.add(target_type)
            
        # Add detected technologies as prerequisites
        satisfied_prerequisites.update(technologies)
        
        # Add findings-based prerequisites
        for finding in findings:
            finding_type = finding.get('type')
            if finding_type:
                satisfied_prerequisites.add(finding_type)
                
        # Check which tools have all prerequisites satisfied
        for tool_name, tool_info in self.tools.items():
            prerequisites = tool_info.get('prerequisites', ['any'])
            if all(prereq in satisfied_prerequisites for prereq in prerequisites):
                applicable_tools.append(tool_name)
                
        return applicable_tools

    def _score_tools(self, applicable_tools: List[str], scan_context: Dict) -> Dict[str, float]:
        """
        Score tools based on relevance to current scan context
        """
        tool_scores = {}
        phase = scan_context.get('phase')
        findings = scan_context.get('findings', [])
        technologies = scan_context.get('technologies_detected', [])
        
        # Get recently used tools to avoid repetition
        recently_used = scan_context.get('recently_used_tools', [])
        
        for tool_name in applicable_tools:
            tool_info = self.tools.get(tool_name, {})
            score = 0.0
            
            # Phase relevance scoring
            if phase and tool_info.get('category'):
                if phase == 'reconnaissance' and tool_info['category'] in ['subdomain_enum', 'web_crawler']:
                    score += 2.0
                elif phase == 'scanning' and tool_info['category'] in ['web_scanner', 'network_scanner', 'fuzzer']:
                    score += 2.0
                elif phase == 'exploitation' and tool_info['category'] in ['sql_exploitation', 'xss_scanner', 'command_injection']:
                    score += 2.0
                    
            # Technology matching bonus
            tool_detects = tool_info.get('detects', [])
            matched_techs = set(technologies) & set(tool_detects)
            score += len(matched_techs) * 1.5
            
            # Recent usage penalty to encourage variety
            if tool_name in recently_used:
                score *= 0.7  # 30% penalty for recently used tools
                
            # Success history bonus
            if tool_name in self.tool_success_history:
                success_rate = self.tool_success_history[tool_name].get('success_rate', 0)
                score += success_rate * 2.0
                
            tool_scores[tool_name] = score
            
        return tool_scores

    def record_tool_success(self, tool_name: str, success: bool):
        """
        Record tool execution success/failure for learning
        """
        if tool_name not in self.tool_success_history:
            self.tool_success_history[tool_name] = {
                'total_runs': 0,
                'successful_runs': 0,
                'success_rate': 0.0
            }
            
        self.tool_success_history[tool_name]['total_runs'] += 1
        if success:
            self.tool_success_history[tool_name]['successful_runs'] += 1
            
        # Calculate success rate
        total = self.tool_success_history[tool_name]['total_runs']
        successful = self.tool_success_history[tool_name]['successful_runs']
        self.tool_success_history[tool_name]['success_rate'] = successful / total if total > 0 else 0.0

    def get_tool_info(self, tool_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific tool
        """
        return self.tools.get(tool_name, {})