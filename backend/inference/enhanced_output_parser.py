"""
Enhanced Output Parser - Multi-Strategy Approach
Handles any tool output through multiple parsing strategies:
1. Structured output (JSON/XML) - most reliable
2. Tool-specific parsers - customized per tool
3. LLM-assisted parsing - for complex/unknown outputs
4. Pattern-based extraction - fallback with enhanced patterns
5. Heuristic analysis - last resort
"""

import re
import json
import xml.etree.ElementTree as ET
import uuid
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ParseConfidence(Enum):
    """Confidence level in parsing results"""
    HIGH = "high"        # Structured output (JSON/XML)
    MEDIUM = "medium"    # Tool-specific parser
    LOW = "low"          # Pattern matching
    UNCERTAIN = "uncertain"  # Heuristic/LLM


@dataclass
class ParsedFinding:
    """Standardized finding structure"""
    id: str
    type: str
    name: str
    severity: float
    confidence: float
    location: str
    evidence: str
    exploitable: bool
    tool: str
    raw_data: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'type': self.type,
            'name': self.name,
            'severity': self.severity,
            'confidence': self.confidence,
            'location': self.location,
            'evidence': self.evidence,
            'exploitable': self.exploitable,
            'tool': self.tool,
            'raw_data': self.raw_data
        }


class EnhancedOutputParser:
    """
    Multi-strategy output parser that can handle any tool output.
    
    Strategies (in order of preference):
    1. Structured Output - Parse JSON/XML if available
    2. Tool-Specific - Use customized parser for known tools
    3. LLM-Assisted - Use LLM to extract findings (if available)
    4. Pattern-Based - Enhanced regex patterns
    5. Heuristic - Analyze output structure and content
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.tool_parsers = self._register_tool_parsers()
        self.severity_keywords = self._build_severity_map()
        self.vuln_patterns = self._build_pattern_library()
        
        # Statistics for learning
        self.parse_stats = {
            'total': 0,
            'structured': 0,
            'tool_specific': 0,
            'llm_assisted': 0,
            'pattern_based': 0,
            'heuristic': 0,
            'failed': 0
        }
    
    def parse(self, tool_name: str, stdout: str, stderr: str, 
              command: str = "", target: str = "") -> Dict[str, Any]:
        """
        Main parsing entry point - tries multiple strategies.
            
        Args:
            tool_name: Name of the tool that produced the output
            stdout: Standard output from the tool
            stderr: Standard error from the tool
            command: The command that was executed (for context)
            target: The target that was scanned (for context)
            
        Returns:
            Parsed results with vulnerabilities, hosts, services
        """
        self.parse_stats['total'] += 1
            
        # Sanitize input to remove terminal escape codes and other artifacts
        stdout = self._sanitize_output(stdout)
        stderr = self._sanitize_output(stderr)
        
        # Check for tool/command not found errors FIRST
        combined_output = f"{stdout}\n{stderr}".lower()
        tool_error_indicators = [
            'command not found',
            'not found',
            '[tool_not_found]',
            'no such file or directory',
            'permission denied',
            'cannot execute',
            'not recognized as',
            'is not recognized',
            'unable to locate',
        ]
        
        for indicator in tool_error_indicators:
            if indicator in combined_output:
                logger.warning(f"[Parser] Tool error detected for {tool_name}: {indicator}")
                return {
                    'vulnerabilities': [],
                    'hosts': [],
                    'services': [],
                    'raw_output': stdout,
                    'parse_method': 'tool_error',
                    'parse_confidence': 'none',
                    'parse_note': f'Tool execution error: {indicator}',
                    'tool_error': True,
                    'error_type': indicator
                }
            
        context = {
            'tool': tool_name,
            'command': command,
            'target': target,
            'stdout_length': len(stdout),
            'stderr_length': len(stderr)
        }
            
        # Strategy 1: Try structured output first (most reliable)
        result = self._try_structured_parse(stdout, stderr, context)
        if result and result.get('vulnerabilities'):
            self.parse_stats['structured'] += 1
            result['parse_method'] = 'structured'
            result['parse_confidence'] = ParseConfidence.HIGH.value
            return result
        
        # Strategy 2: Use tool-specific parser if available
        tool_lower = tool_name.lower().replace('.sh', '').replace('.py', '')
        if tool_lower in self.tool_parsers:
            result = self.tool_parsers[tool_lower](stdout, stderr, context)
            if result and (result.get('vulnerabilities') or result.get('services') or result.get('hosts')):
                self.parse_stats['tool_specific'] += 1
                result['parse_method'] = 'tool_specific'
                result['parse_confidence'] = ParseConfidence.MEDIUM.value
                return result
        
        # Strategy 3: LLM-assisted parsing (if available and output is complex)
        if self.llm_client and len(stdout) > 100:
            result = self._try_llm_parse(stdout, stderr, context)
            if result and result.get('vulnerabilities'):
                self.parse_stats['llm_assisted'] += 1
                result['parse_method'] = 'llm_assisted'
                result['parse_confidence'] = ParseConfidence.MEDIUM.value
                return result
        
        # Strategy 4: Enhanced pattern-based extraction
        result = self._pattern_based_parse(stdout, stderr, context)
        if result and result.get('vulnerabilities'):
            self.parse_stats['pattern_based'] += 1
            result['parse_method'] = 'pattern_based'
            result['parse_confidence'] = ParseConfidence.LOW.value
            return result
        
        # Strategy 5: Heuristic analysis
        result = self._heuristic_parse(stdout, stderr, context)
        if result:
            self.parse_stats['heuristic'] += 1
            result['parse_method'] = 'heuristic'
            result['parse_confidence'] = ParseConfidence.UNCERTAIN.value
            return result
        
        # Nothing found
        self.parse_stats['failed'] += 1
        return {
            'vulnerabilities': [],
            'hosts': [],
            'services': [],
            'raw_output': stdout,
            'parse_method': 'none',
            'parse_confidence': 'none',
            'parse_note': 'No findings extracted from output'
        }
    
    # =========================================================================
    # Strategy 1: Structured Output Parsing
    # =========================================================================
    
    def _try_structured_parse(self, stdout: str, stderr: str, 
                               context: Dict) -> Optional[Dict]:
        """Try to parse as JSON or XML"""
        
        # Try JSON first
        json_result = self._try_json_parse(stdout)
        if json_result:
            return self._normalize_json_findings(json_result, context)
        
        # Try XML
        xml_result = self._try_xml_parse(stdout)
        if xml_result:
            return self._normalize_xml_findings(xml_result, context)
        
        # Check for embedded JSON in output (some tools mix text and JSON)
        embedded_json = self._extract_embedded_json(stdout)
        if embedded_json:
            return self._normalize_json_findings(embedded_json, context)
        
        return None
    
    def _try_json_parse(self, output: str) -> Optional[Dict]:
        """Attempt to parse output as JSON"""
        output = output.strip()
        
        # Direct JSON
        if output.startswith('{') or output.startswith('['):
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                pass
        
        # JSONL (JSON Lines) - common for streaming tools
        if '\n' in output:
            lines = output.strip().split('\n')
            json_objects = []
            for line in lines:
                line = line.strip()
                if line.startswith('{'):
                    try:
                        json_objects.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            if json_objects:
                return {'items': json_objects}
        
        return None
    
    def _try_xml_parse(self, output: str) -> Optional[ET.Element]:
        """Attempt to parse output as XML"""
        output = output.strip()
        
        if output.startswith('<?xml') or output.startswith('<'):
            try:
                return ET.fromstring(output)
            except ET.ParseError:
                # Try to find XML within the output
                xml_match = re.search(r'<\?xml.*?\?>\s*<\w+.*?</\w+>', output, re.DOTALL)
                if xml_match:
                    try:
                        return ET.fromstring(xml_match.group(0))
                    except ET.ParseError:
                        pass
        return None
    
    def _extract_embedded_json(self, output: str) -> Optional[Dict]:
        """Extract JSON embedded in text output"""
        # Look for JSON objects
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        matches = re.findall(json_pattern, output)
        
        for match in matches:
            try:
                parsed = json.loads(match)
                # Check if it looks like vulnerability data
                if any(key in str(parsed).lower() for key in 
                       ['vulnerability', 'vuln', 'cve', 'finding', 'severity', 'risk']):
                    return parsed
            except json.JSONDecodeError:
                continue
        
        return None
    
    def _normalize_json_findings(self, data: Dict, context: Dict) -> Dict:
        """Normalize JSON data into standard finding format"""
        vulnerabilities = []
        hosts = []
        services = []
        
        # Handle different JSON structures
        items = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Common keys for findings arrays
            for key in ['vulnerabilities', 'findings', 'results', 'items', 
                        'issues', 'alerts', 'matches', 'data']:
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    break
            if not items:
                items = [data]
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            # Extract vulnerability information
            vuln = self._extract_vuln_from_dict(item, context)
            if vuln:
                vulnerabilities.append(vuln)
            
            # Extract host information
            host = item.get('host') or item.get('ip') or item.get('target')
            if host and host not in hosts:
                hosts.append(host)
            
            # Extract service information
            if 'port' in item or 'service' in item:
                services.append({
                    'port': item.get('port'),
                    'protocol': item.get('protocol', 'tcp'),
                    'service': item.get('service', 'unknown'),
                    'version': item.get('version', '')
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': hosts,
            'services': services,
            'raw_output': json.dumps(data)[:5000]
        }
    
    def _extract_vuln_from_dict(self, item: Dict, context: Dict) -> Optional[Dict]:
        """Extract vulnerability from a dictionary"""
        # Common field names for vulnerability data
        name_keys = ['name', 'title', 'vulnerability', 'finding', 'issue', 
                     'template-id', 'matched-at', 'info.name']
        severity_keys = ['severity', 'risk', 'level', 'priority', 'cvss', 
                        'info.severity', 'score']
        type_keys = ['type', 'category', 'class', 'template-id', 'matcher-name']
        location_keys = ['url', 'host', 'target', 'matched-at', 'location', 'path']
        evidence_keys = ['evidence', 'proof', 'extracted-results', 'matched', 
                        'description', 'curl-command']
        
        def get_nested(d, key):
            """Get nested key like 'info.name'"""
            keys = key.split('.')
            val = d
            for k in keys:
                if isinstance(val, dict) and k in val:
                    val = val[k]
                else:
                    return None
            return val
        
        # Extract fields
        name = None
        for key in name_keys:
            name = get_nested(item, key)
            if name:
                break
        
        if not name:
            # Try to construct name from other fields
            name = item.get('template-id') or item.get('type') or 'Unknown Finding'
        
        severity = 5.0  # Default medium
        for key in severity_keys:
            sev = get_nested(item, key)
            if sev:
                severity = self._normalize_severity(sev)
                break
        
        vuln_type = 'unknown'
        for key in type_keys:
            t = get_nested(item, key)
            if t:
                vuln_type = str(t).lower().replace('-', '_').replace(' ', '_')
                break
        
        location = context.get('target', 'Unknown')
        for key in location_keys:
            loc = get_nested(item, key)
            if loc:
                location = str(loc)
                break
        
        evidence = ''
        for key in evidence_keys:
            ev = get_nested(item, key)
            if ev:
                evidence = str(ev)[:500]
                break
        
        if not evidence:
            evidence = json.dumps(item)[:500]
        
        return {
            'id': str(uuid.uuid4()),
            'type': vuln_type,
            'name': str(name)[:200],
            'severity': severity,
            'confidence': 0.9,  # High confidence for structured data
            'location': location,
            'evidence': evidence,
            'exploitable': severity >= 7.0,
            'tool': context.get('tool', 'unknown'),
            'raw_data': item
        }
    
    def _sanitize_output(self, output: str) -> str:
        """Remove terminal escape codes and other artifacts from output"""
        if not output:
            return output
        
        # Remove ANSI escape codes (terminal color codes)
        ansi_escape = re.compile(r'\x1B\[([0-9;]*[A-Za-z])|\x9b([0-9;]*[A-Za-z])')
        output = ansi_escape.sub('', output)
        
        # Remove other common escape sequences
        output = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', output)  # ESC[...format
        output = re.sub(r'\x9b[0-9;]*[a-zA-Z]', '', output)   # Alternative CSI format
        
        # Remove common terminal artifacts
        output = re.sub(r'\x08+', '', output)  # Remove backspaces
        output = re.sub(r'\r\n', '\n', output)  # Normalize line endings
        
        # Remove common artifacts like .bash_history if it appears inappropriately
        output = re.sub(r'\.bash_history', '', output)
        
        # Clean up multiple consecutive newlines
        output = re.sub(r'\n\s*\n', '\n\n', output)
        
        return output
    
    def _normalize_severity(self, value: Any) -> float:
        """Normalize severity to 0-10 scale"""
        if isinstance(value, (int, float)):
            if value <= 10:
                return float(value)
            elif value <= 100:
                return value / 10.0
            return 5.0
        
        if isinstance(value, str):
            value_lower = value.lower()
            severity_map = {
                'critical': 9.5,
                'high': 7.5,
                'medium': 5.0,
                'moderate': 5.0,
                'low': 2.5,
                'info': 1.0,
                'informational': 1.0,
                'none': 0.0
            }
            for key, score in severity_map.items():
                if key in value_lower:
                    return score
            
            # Try to extract number
            num_match = re.search(r'(\d+\.?\d*)', value)
            if num_match:
                return min(10.0, float(num_match.group(1)))
        
        return 5.0
    
    def _normalize_xml_findings(self, root: ET.Element, context: Dict) -> Dict:
        """Normalize XML data into standard finding format"""
        vulnerabilities = []
        hosts = []
        services = []
        
        # Common XML structures for security tools
        # Nmap XML format
        for host in root.findall('.//host'):
            addr = host.find('.//address')
            if addr is not None:
                hosts.append(addr.get('addr', ''))
            
            for port in host.findall('.//port'):
                port_id = port.get('portid', '')
                protocol = port.get('protocol', 'tcp')
                state = port.find('state')
                service = port.find('service')
                
                if state is not None and state.get('state') == 'open':
                    svc_name = service.get('name', 'unknown') if service is not None else 'unknown'
                    svc_version = service.get('product', '') if service is not None else ''
                    
                    services.append({
                        'port': port_id,
                        'protocol': protocol,
                        'service': svc_name,
                        'version': svc_version
                    })
                    
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'open_port',
                        'name': f'Open Port: {port_id}/{protocol} ({svc_name})',
                        'severity': 4.0,
                        'confidence': 0.95,
                        'location': f'Port {port_id}',
                        'evidence': f'{port_id}/{protocol} open {svc_name} {svc_version}',
                        'exploitable': svc_name in ['http', 'https', 'ssh', 'ftp', 'smb'],
                        'tool': context.get('tool', 'unknown')
                    })
        
        # Look for script output (NSE scripts)
        for script in root.findall('.//script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            
            if any(word in output.lower() for word in ['vulnerable', 'vuln', 'cve']):
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'script_finding',
                    'name': f'Script Finding: {script_id}',
                    'severity': 7.0,
                    'confidence': 0.85,
                    'location': 'NSE Script',
                    'evidence': output[:500],
                    'exploitable': True,
                    'tool': context.get('tool', 'unknown')
                })
        
        # Generic vulnerability elements
        for vuln in root.findall('.//*[contains(local-name(), "vuln")]'):
            vuln_data = {
                'id': str(uuid.uuid4()),
                'type': vuln.tag,
                'name': vuln.get('name', vuln.text or 'Unknown')[:200],
                'severity': self._normalize_severity(vuln.get('severity', '5')),
                'confidence': 0.85,
                'location': vuln.get('location', context.get('target', 'Unknown')),
                'evidence': ET.tostring(vuln, encoding='unicode')[:500],
                'exploitable': True,
                'tool': context.get('tool', 'unknown')
            }
            vulnerabilities.append(vuln_data)
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': hosts,
            'services': services,
            'raw_output': ET.tostring(root, encoding='unicode')[:5000]
        }
    
    # =========================================================================
    # Strategy 2: Tool-Specific Parsers
    # =========================================================================
    
    def _register_tool_parsers(self) -> Dict:
        """Register tool-specific parsers"""
        return {
            'nmap': self._parse_nmap,
            'nuclei': self._parse_nuclei,
            'nikto': self._parse_nikto,
            'sqlmap': self._parse_sqlmap,
            'gobuster': self._parse_directory_scanner,
            'ffuf': self._parse_directory_scanner,
            'dirb': self._parse_directory_scanner,
            'dirsearch': self._parse_directory_scanner,
            'whatweb': self._parse_whatweb,
            'wpscan': self._parse_wpscan,
            'sslscan': self._parse_sslscan,
            'sslyze': self._parse_sslscan,
            'testssl': self._parse_sslscan,
            'hydra': self._parse_hydra,
            'medusa': self._parse_hydra,
            'dnsenum': self._parse_dns_tool,
            'dnsrecon': self._parse_dns_tool,
            'fierce': self._parse_dns_tool,
            'sublist3r': self._parse_subdomain_tool,
            'subfinder': self._parse_subdomain_tool,
            'amass': self._parse_subdomain_tool,
            'dalfox': self._parse_xss_tool,
            'xsser': self._parse_xss_tool,
            'xsstrike': self._parse_xss_tool,
            'commix': self._parse_commix,
            'enum4linux': self._parse_enum4linux,
            'smbclient': self._parse_smb_tool,
            'crackmapexec': self._parse_smb_tool,
            'masscan': self._parse_masscan,
        }
    
    def _parse_nmap(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse nmap output"""
        vulnerabilities = []
        services = []
        hosts = []
        
        # Try XML first (if -oX was used)
        xml_result = self._try_xml_parse(stdout)
        if xml_result:
            return self._normalize_xml_findings(xml_result, context)
        
        # Parse text output
        current_host = None
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Host discovery
            host_match = re.search(r'Nmap scan report for\s+(\S+)', line)
            if host_match:
                current_host = host_match.group(1)
                if current_host not in hosts:
                    hosts.append(current_host)
            
            # Port parsing
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?', line)
            if port_match:
                port, protocol, state, service, version = port_match.groups()
                version = version or ''
                
                if state == 'open':
                    services.append({
                        'port': port,
                        'protocol': protocol,
                        'service': service,
                        'version': version
                    })
                    
                    # Determine severity based on service
                    sev = 3.0
                    if service in ['http', 'https']:
                        sev = 4.0
                    elif service in ['ssh', 'ftp', 'telnet']:
                        sev = 5.0
                    elif service in ['mysql', 'mssql', 'postgresql', 'mongodb']:
                        sev = 6.0
                    elif service in ['smb', 'netbios']:
                        sev = 5.5
                    
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'open_port',
                        'name': f'Open Port: {port}/{protocol} ({service})',
                        'severity': sev,
                        'confidence': 0.95,
                        'location': f'{current_host or context.get("target")}:{port}',
                        'evidence': line,
                        'exploitable': service in ['http', 'https', 'ssh', 'ftp', 'smb'],
                        'tool': 'nmap'
                    })
            
            # CVE detection
            cve_matches = re.findall(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
            for cve in cve_matches:
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'cve',
                    'name': f'Known Vulnerability: {cve.upper()}',
                    'severity': 8.0,
                    'confidence': 0.9,
                    'location': current_host or context.get('target'),
                    'evidence': line,
                    'exploitable': True,
                    'tool': 'nmap'
                })
            
            # Vulnerability indicators from NSE scripts
            if 'VULNERABLE' in line.upper() and 'NOT VULNERABLE' not in line.upper():
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'nse_vulnerability',
                    'name': 'NSE Script Vulnerability',
                    'severity': 8.0,
                    'confidence': 0.85,
                    'location': current_host or context.get('target'),
                    'evidence': line[:300],
                    'exploitable': True,
                    'tool': 'nmap'
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'services': services,
            'hosts': hosts,
            'raw_output': stdout
        }
    
    def _parse_nuclei(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse nuclei output (supports both JSON and text)"""
        vulnerabilities = []
        
        # Try JSON lines first
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('{'):
                try:
                    data = json.loads(line)
                    vuln = self._extract_vuln_from_dict(data, {**context, 'tool': 'nuclei'})
                    if vuln:
                        vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    pass
        
        if vulnerabilities:
            return {
                'vulnerabilities': vulnerabilities,
                'hosts': [],
                'services': [],
                'raw_output': stdout
            }
        
        # Parse text output
        # Format: [severity] [template-id] [protocol] [matched-at]
        pattern = r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)'
        
        for line in stdout.split('\n'):
            match = re.search(pattern, line)
            if match:
                severity_str, template_id, protocol, matched_at = match.groups()
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': template_id.replace('-', '_'),
                    'name': f'Nuclei: {template_id}',
                    'severity': self._normalize_severity(severity_str),
                    'confidence': 0.9,
                    'location': matched_at,
                    'evidence': line,
                    'exploitable': severity_str.lower() in ['critical', 'high'],
                    'tool': 'nuclei'
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_nikto(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse nikto output"""
        vulnerabilities = []
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Nikto findings start with +
            if not line.startswith('+'):
                continue
            
            # Skip info lines
            if any(skip in line.lower() for skip in ['target ip:', 'target hostname:', 
                   'target port:', 'start time:', 'end time:', 'host(s) tested']):
                continue
            
            # Extract OSVDB reference if present
            osvdb_match = re.search(r'OSVDB-(\d+)', line)
            osvdb = osvdb_match.group(1) if osvdb_match else None
            
            # Determine severity based on content
            severity = 5.0
            if any(word in line.lower() for word in ['remote code', 'rce', 'command execution']):
                severity = 9.0
            elif any(word in line.lower() for word in ['sql injection', 'xss', 'file inclusion']):
                severity = 8.0
            elif any(word in line.lower() for word in ['directory listing', 'backup', 'sensitive']):
                severity = 6.0
            elif any(word in line.lower() for word in ['information', 'disclosure', 'version']):
                severity = 4.0
            
            # Extract path if present
            path_match = re.search(r'(/[^\s:]+)', line)
            location = path_match.group(1) if path_match else context.get('target', 'Unknown')
            
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': f'osvdb_{osvdb}' if osvdb else 'nikto_finding',
                'name': line[2:102],  # Remove "+ " prefix, limit length
                'severity': severity,
                'confidence': 0.8,
                'location': location,
                'evidence': line[:300],
                'exploitable': severity >= 7.0,
                'tool': 'nikto'
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_sqlmap(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse sqlmap output"""
        vulnerabilities = []
        
        # Combine stdout and stderr (sqlmap uses both)
        output = stdout + '\n' + stderr
        
        # Check for SQL injection confirmation
        if 'sqlmap identified the following injection point' in output.lower():
            # Extract parameter info
            param_match = re.search(r"Parameter:\s*(\S+)\s*\(([^)]+)\)", output)
            param_name = param_match.group(1) if param_match else 'unknown'
            param_type = param_match.group(2) if param_match else 'unknown'
            
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'sql_injection',
                'name': f'SQL Injection in parameter: {param_name}',
                'severity': 9.0,
                'confidence': 0.95,
                'location': context.get('target', 'Unknown'),
                'evidence': f'Parameter: {param_name} ({param_type})',
                'exploitable': True,
                'tool': 'sqlmap'
            })
        
        # Extract injection types
        injection_types = re.findall(r'Type:\s*([^\n]+)', output)
        for inj_type in injection_types:
            if inj_type not in [v['evidence'] for v in vulnerabilities]:
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'sql_injection_technique',
                    'name': f'SQL Injection Technique: {inj_type.strip()}',
                    'severity': 8.5,
                    'confidence': 0.9,
                    'location': context.get('target', 'Unknown'),
                    'evidence': inj_type.strip(),
                    'exploitable': True,
                    'tool': 'sqlmap'
                })
        
        # Check for database enumeration success
        if 'available databases' in output.lower():
            db_match = re.search(r'\[\*\]\s*(\w+)', output)
            if db_match:
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'database_enumeration',
                    'name': 'Database Enumeration Successful',
                    'severity': 8.0,
                    'confidence': 0.95,
                    'location': context.get('target', 'Unknown'),
                    'evidence': f'Database found: {db_match.group(1)}',
                    'exploitable': True,
                    'tool': 'sqlmap'
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_directory_scanner(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse gobuster/ffuf/dirb output"""
        vulnerabilities = []
        found_paths = []
        
        # Common patterns for directory scanners
        patterns = [
            # Gobuster: /path (Status: 200)
            r'(/[^\s]+)\s+\(Status:\s*(\d+)',
            # ffuf: path [Status: 200, Size: 1234]
            r'(\S+)\s+\[Status:\s*(\d+)',
            # dirb: + http://target/path (CODE:200|SIZE:1234)
            r'\+\s+\S+(/[^\s]+)\s+\(CODE:(\d+)',
            # Generic: 200 - /path
            r'(\d{3})\s+-?\s*(/[^\s]+)',
        ]
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    groups = match.groups()
                    if groups[0].startswith('/'):
                        path, status = groups[0], groups[1]
                    else:
                        status, path = groups[0], groups[1]
                    
                    status = int(status)
                    
                    # Skip 404s and common redirects
                    if status in [404, 301, 302]:
                        continue
                    
                    if path in found_paths:
                        continue
                    found_paths.append(path)
                    
                    # Determine severity based on path
                    severity = 3.0
                    if any(s in path.lower() for s in ['.git', '.svn', '.env', 'config', 'backup']):
                        severity = 7.0
                    elif any(s in path.lower() for s in ['admin', 'phpmyadmin', 'wp-admin', 'manager']):
                        severity = 6.0
                    elif any(s in path.lower() for s in ['.bak', '.old', '.sql', '.zip', '.tar']):
                        severity = 6.5
                    elif status == 200:
                        severity = 4.0
                    
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'directory_finding',
                        'name': f'Directory/File Found: {path}',
                        'severity': severity,
                        'confidence': 0.9,
                        'location': f'{context.get("target", "")}{path}',
                        'evidence': f'Status: {status}, Path: {path}',
                        'exploitable': severity >= 5.0,
                        'tool': context.get('tool', 'directory_scanner')
                    })
                    break
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_whatweb(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse whatweb technology fingerprinting output"""
        vulnerabilities = []
        
        # WhatWeb output format: URL [status] technologies
        for line in stdout.split('\n'):
            if not line.strip():
                continue
            
            # Extract technologies (in square brackets)
            techs = re.findall(r'\[([^\]]+)\]', line)
            
            for tech in techs:
                # Skip status codes
                if tech.isdigit():
                    continue
                
                severity = 2.0  # Informational by default
                
                # Check for version info (potential outdated software)
                if re.search(r'\d+\.\d+', tech):
                    severity = 3.0
                
                # Check for potentially vulnerable technologies
                if any(t in tech.lower() for t in ['php/', 'apache/', 'nginx/', 'wordpress', 'joomla', 'drupal']):
                    severity = 4.0
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'technology_detection',
                    'name': f'Technology: {tech}',
                    'severity': severity,
                    'confidence': 0.85,
                    'location': context.get('target', 'Unknown'),
                    'evidence': tech,
                    'exploitable': False,
                    'tool': 'whatweb'
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_wpscan(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse wpscan WordPress scanner output"""
        vulnerabilities = []
        
        # Try JSON first
        json_result = self._try_json_parse(stdout)
        if json_result:
            return self._normalize_json_findings(json_result, context)
        
        # Parse text output
        lines = stdout.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Section headers
            if '[+]' in line:
                current_section = line
            
            # Vulnerability markers
            if '[!]' in line:
                severity = 7.0
                if 'critical' in line.lower():
                    severity = 9.0
                elif 'authenticated' in line.lower():
                    severity = 6.0
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'wordpress_vulnerability',
                    'name': line.replace('[!]', '').strip()[:100],
                    'severity': severity,
                    'confidence': 0.85,
                    'location': context.get('target', 'Unknown'),
                    'evidence': line,
                    'exploitable': True,
                    'tool': 'wpscan'
                })
            
            # Version detection
            if 'WordPress version' in line:
                version_match = re.search(r'(\d+\.\d+\.?\d*)', line)
                if version_match:
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'wordpress_version',
                        'name': f'WordPress Version: {version_match.group(1)}',
                        'severity': 3.0,
                        'confidence': 0.9,
                        'location': context.get('target', 'Unknown'),
                        'evidence': line,
                        'exploitable': False,
                        'tool': 'wpscan'
                    })
            
            # User enumeration
            if re.search(r'User\(s\) Identified|Login:', line, re.IGNORECASE):
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'user_enumeration',
                    'name': f'WordPress User Found',
                    'severity': 4.0,
                    'confidence': 0.9,
                    'location': context.get('target', 'Unknown'),
                    'evidence': line,
                    'exploitable': False,
                    'tool': 'wpscan'
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_sslscan(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse SSL/TLS scanner output (sslscan, sslyze, testssl)"""
        vulnerabilities = []
        
        # Check for common SSL vulnerabilities
        ssl_vulns = [
            ('SSLv2', 'sslv2_enabled', 8.0, 'SSLv2 is obsolete and insecure'),
            ('SSLv3', 'sslv3_enabled', 7.0, 'SSLv3 is vulnerable to POODLE'),
            ('TLSv1.0', 'tlsv1_enabled', 5.0, 'TLSv1.0 is deprecated'),
            ('TLSv1.1', 'tlsv1_1_enabled', 4.0, 'TLSv1.1 is deprecated'),
            ('BEAST', 'beast_vulnerable', 6.0, 'Vulnerable to BEAST attack'),
            ('POODLE', 'poodle_vulnerable', 7.0, 'Vulnerable to POODLE attack'),
            ('HEARTBLEED', 'heartbleed_vulnerable', 9.5, 'Vulnerable to Heartbleed'),
            ('CRIME', 'crime_vulnerable', 6.0, 'Vulnerable to CRIME attack'),
            ('BREACH', 'breach_vulnerable', 5.0, 'Vulnerable to BREACH attack'),
            ('DROWN', 'drown_vulnerable', 8.0, 'Vulnerable to DROWN attack'),
            ('ROBOT', 'robot_vulnerable', 7.0, 'Vulnerable to ROBOT attack'),
            ('weak cipher', 'weak_cipher', 5.0, 'Uses weak cipher suites'),
            ('RC4', 'rc4_enabled', 5.0, 'Uses insecure RC4 cipher'),
            ('DES', 'des_enabled', 6.0, 'Uses insecure DES cipher'),
            ('NULL', 'null_cipher', 9.0, 'Uses NULL cipher (no encryption)'),
            ('expired', 'cert_expired', 7.0, 'Certificate is expired'),
            ('self-signed', 'self_signed', 4.0, 'Self-signed certificate'),
        ]
        
        output_lower = stdout.lower()
        
        for keyword, vuln_type, severity, description in ssl_vulns:
            if keyword.lower() in output_lower:
                # Check it's not negated
                if f'not {keyword.lower()}' not in output_lower and f'{keyword.lower()} disabled' not in output_lower:
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': vuln_type,
                        'name': description,
                        'severity': severity,
                        'confidence': 0.85,
                        'location': context.get('target', 'Unknown'),
                        'evidence': f'{keyword} detected in SSL/TLS configuration',
                        'exploitable': severity >= 6.0,
                        'tool': context.get('tool', 'sslscan')
                    })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_hydra(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse hydra/medusa password cracking output"""
        vulnerabilities = []
        
        # Look for successful logins
        # Hydra format: [PORT][SERVICE] host: HOST   login: USER   password: PASS
        login_pattern = r'\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)'
        
        for match in re.finditer(login_pattern, stdout):
            port, service, host, username, password = match.groups()
            
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'weak_credentials',
                'name': f'Weak Credentials Found: {service}',
                'severity': 9.0,
                'confidence': 0.99,
                'location': f'{host}:{port}',
                'evidence': f'Service: {service}, Username: {username}',
                'exploitable': True,
                'tool': context.get('tool', 'hydra'),
                'raw_data': {'username': username, 'password': password, 'service': service}
            })
        
        # Alternative format
        alt_pattern = r'login:\s*(\S+)\s+password:\s*(\S+)'
        for match in re.finditer(alt_pattern, stdout):
            if not any(match.group(1) in v.get('evidence', '') for v in vulnerabilities):
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'weak_credentials',
                    'name': 'Weak Credentials Found',
                    'severity': 9.0,
                    'confidence': 0.95,
                    'location': context.get('target', 'Unknown'),
                    'evidence': f'Username: {match.group(1)}',
                    'exploitable': True,
                    'tool': context.get('tool', 'hydra')
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_dns_tool(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse DNS enumeration tool output"""
        vulnerabilities = []
        hosts = []
        
        # Extract hostnames/subdomains
        hostname_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,})'
        
        for match in re.finditer(hostname_pattern, stdout):
            hostname = match.group(1)
            if hostname not in hosts:
                hosts.append(hostname)
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'subdomain',
                    'name': f'Subdomain: {hostname}',
                    'severity': 2.0,
                    'confidence': 0.9,
                    'location': hostname,
                    'evidence': hostname,
                    'exploitable': False,
                    'tool': context.get('tool', 'dns_enum')
                })
        
        # Check for zone transfer vulnerability
        if 'zone transfer' in stdout.lower() or 'axfr' in stdout.lower():
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'dns_zone_transfer',
                'name': 'DNS Zone Transfer Allowed',
                'severity': 7.0,
                'confidence': 0.9,
                'location': context.get('target', 'Unknown'),
                'evidence': 'Zone transfer successful',
                'exploitable': True,
                'tool': context.get('tool', 'dns_enum')
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': hosts,
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_subdomain_tool(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse subdomain enumeration output"""
        return self._parse_dns_tool(stdout, stderr, context)
    
    def _parse_xss_tool(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse XSS scanner output"""
        vulnerabilities = []
        
        # Check for XSS findings
        xss_indicators = ['xss found', 'vulnerable', 'reflected', 'stored', 'dom-based', 'payload']
        
        for line in stdout.split('\n'):
            line_lower = line.lower()
            if any(ind in line_lower for ind in xss_indicators):
                # Extract URL if present
                url_match = re.search(r'(https?://[^\s]+)', line)
                location = url_match.group(1) if url_match else context.get('target', 'Unknown')
                
                severity = 7.0
                if 'stored' in line_lower:
                    severity = 8.0
                elif 'dom' in line_lower:
                    severity = 6.5
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'xss',
                    'name': 'Cross-Site Scripting (XSS)',
                    'severity': severity,
                    'confidence': 0.85,
                    'location': location,
                    'evidence': line[:300],
                    'exploitable': True,
                    'tool': context.get('tool', 'xss_scanner')
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_commix(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse commix command injection output"""
        vulnerabilities = []
        
        if 'command injection' in stdout.lower() or 'injectable' in stdout.lower():
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'command_injection',
                'name': 'Command Injection Vulnerability',
                'severity': 9.5,
                'confidence': 0.9,
                'location': context.get('target', 'Unknown'),
                'evidence': 'Command injection confirmed by commix',
                'exploitable': True,
                'tool': 'commix'
            })
        
        # Extract parameter info
        param_match = re.search(r'parameter:\s*(\S+)', stdout, re.IGNORECASE)
        if param_match:
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'command_injection_param',
                'name': f'Vulnerable Parameter: {param_match.group(1)}',
                'severity': 9.0,
                'confidence': 0.9,
                'location': context.get('target', 'Unknown'),
                'evidence': f'Parameter: {param_match.group(1)}',
                'exploitable': True,
                'tool': 'commix'
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    def _parse_enum4linux(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse enum4linux SMB enumeration output"""
        vulnerabilities = []
        services = []
        
        # Null session
        if 'null session' in stdout.lower() and 'allowed' in stdout.lower():
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'null_session',
                'name': 'SMB Null Session Allowed',
                'severity': 6.0,
                'confidence': 0.95,
                'location': context.get('target', 'Unknown'),
                'evidence': 'Null session enumeration successful',
                'exploitable': True,
                'tool': 'enum4linux'
            })
        
        # Shares
        share_pattern = r'//([^/]+)/(\S+)'
        for match in re.finditer(share_pattern, stdout):
            host, share = match.groups()
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'smb_share',
                'name': f'SMB Share: {share}',
                'severity': 4.0 if share not in ['IPC$', 'C$', 'ADMIN$'] else 2.0,
                'confidence': 0.9,
                'location': f'//{host}/{share}',
                'evidence': match.group(0),
                'exploitable': share not in ['IPC$'],
                'tool': 'enum4linux'
            })
        
        # Users
        user_pattern = r'user:\[([^\]]+)\]'
        for match in re.finditer(user_pattern, stdout):
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'user_enumeration',
                'name': f'SMB User: {match.group(1)}',
                'severity': 3.0,
                'confidence': 0.9,
                'location': context.get('target', 'Unknown'),
                'evidence': match.group(0),
                'exploitable': False,
                'tool': 'enum4linux'
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': services,
            'raw_output': stdout
        }
    
    def _parse_smb_tool(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse generic SMB tool output"""
        return self._parse_enum4linux(stdout, stderr, context)
    
    def _parse_masscan(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Parse masscan output"""
        vulnerabilities = []
        services = []
        hosts = []
        
        # Try JSON first
        json_result = self._try_json_parse(stdout)
        if json_result:
            return self._normalize_json_findings(json_result, context)
        
        # Parse text output
        # Format: Discovered open port PORT/PROTOCOL on IP
        pattern = r'Discovered open port (\d+)/(\w+) on (\S+)'
        
        for match in re.finditer(pattern, stdout):
            port, protocol, host = match.groups()
            
            if host not in hosts:
                hosts.append(host)
            
            services.append({
                'port': port,
                'protocol': protocol,
                'service': 'unknown',
                'version': ''
            })
            
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'open_port',
                'name': f'Open Port: {port}/{protocol}',
                'severity': 3.0,
                'confidence': 0.95,
                'location': f'{host}:{port}',
                'evidence': match.group(0),
                'exploitable': False,
                'tool': 'masscan'
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': hosts,
            'services': services,
            'raw_output': stdout
        }
    
    # =========================================================================
    # Strategy 3: LLM-Assisted Parsing
    # =========================================================================
    
    def _try_llm_parse(self, stdout: str, stderr: str, context: Dict) -> Optional[Dict]:
        """Use LLM to extract findings from complex output"""
        if not self.llm_client:
            return None
        
        try:
            prompt = f"""Analyze this security tool output and extract any vulnerabilities or findings.

Tool: {context.get('tool', 'unknown')}
Target: {context.get('target', 'unknown')}

Output:
{stdout[:3000]}

{f"Errors: {stderr[:500]}" if stderr else ""}

Extract findings in this JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability type",
            "name": "finding name",
            "severity": 1-10,
            "location": "where found",
            "evidence": "proof from output",
            "exploitable": true/false
        }}
    ]
}}

Only return valid JSON. If no findings, return {{"vulnerabilities": []}}"""

            response = self.llm_client.generate(prompt)
            
            # Parse LLM response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                
                # Normalize findings
                vulnerabilities = []
                for v in data.get('vulnerabilities', []):
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': v.get('type', 'unknown'),
                        'name': v.get('name', 'LLM Finding'),
                        'severity': float(v.get('severity', 5)),
                        'confidence': 0.7,  # Lower confidence for LLM
                        'location': v.get('location', context.get('target')),
                        'evidence': v.get('evidence', '')[:300],
                        'exploitable': v.get('exploitable', False),
                        'tool': context.get('tool', 'unknown')
                    })
                
                return {
                    'vulnerabilities': vulnerabilities,
                    'hosts': [],
                    'services': [],
                    'raw_output': stdout
                }
        
        except Exception as e:
            logger.warning(f"LLM parsing failed: {e}")
        
        return None
    
    # =========================================================================
    # Strategy 4: Pattern-Based Parsing
    # =========================================================================
    
    def _build_pattern_library(self) -> List[Tuple]:
        """Build comprehensive pattern library for vulnerability detection"""
        return [
            # CVEs
            (r'(CVE-\d{4}-\d+)', 'cve', 8.0, True),
            
            # Critical findings
            (r'(?i)(remote\s*code\s*execution|rce)', 'rce', 9.5, True),
            (r'(?i)(command\s*injection)', 'command_injection', 9.0, True),
            (r'(?i)(arbitrary\s*file\s*upload)', 'file_upload', 9.0, True),
            (r'(?i)(authentication\s*bypass)', 'auth_bypass', 9.0, True),
            
            # High severity
            (r'(?i)(sql\s*injection|sqli)', 'sql_injection', 8.5, True),
            (r'(?i)(cross.?site\s*script|xss)', 'xss', 7.5, True),
            (r'(?i)(local\s*file\s*inclusion|lfi)', 'lfi', 8.0, True),
            (r'(?i)(remote\s*file\s*inclusion|rfi)', 'rfi', 9.0, True),
            (r'(?i)(xml\s*external\s*entity|xxe)', 'xxe', 8.0, True),
            (r'(?i)(server.?side\s*request\s*forgery|ssrf)', 'ssrf', 8.0, True),
            (r'(?i)(insecure\s*deserialization)', 'deserialization', 8.5, True),
            
            # Medium severity
            (r'(?i)(directory\s*traversal|path\s*traversal)', 'path_traversal', 7.0, True),
            (r'(?i)(open\s*redirect)', 'open_redirect', 5.0, True),
            (r'(?i)(information\s*disclosure)', 'info_disclosure', 5.0, False),
            (r'(?i)(sensitive\s*data\s*exposure)', 'data_exposure', 6.0, True),
            (r'(?i)(broken\s*access\s*control)', 'access_control', 7.0, True),
            (r'(?i)(security\s*misconfiguration)', 'misconfiguration', 5.0, False),
            
            # Low severity
            (r'(?i)(missing\s*security\s*header)', 'missing_header', 3.0, False),
            (r'(?i)(cookie\s*without\s*secure)', 'insecure_cookie', 3.0, False),
            (r'(?i)(version\s*disclosure)', 'version_disclosure', 2.0, False),
            
            # Infrastructure
            (r'(\d+)/(tcp|udp)\s+open\s+(\S+)', 'open_port', 4.0, False),
            (r'(?i)(default\s*credentials?)', 'default_creds', 8.0, True),
            (r'(?i)(weak\s*password)', 'weak_password', 7.0, True),
        ]
    
    def _pattern_based_parse(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Enhanced pattern-based parsing"""
        vulnerabilities = []
        seen_evidence = set()
        
        combined_output = stdout + '\n' + stderr
        
        for pattern, vuln_type, severity, exploitable in self.vuln_patterns:
            for match in re.finditer(pattern, combined_output, re.IGNORECASE | re.MULTILINE):
                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(combined_output), match.end() + 100)
                evidence = combined_output[start:end].strip()
                
                # Avoid duplicates
                evidence_hash = hash(evidence[:100])
                if evidence_hash in seen_evidence:
                    continue
                seen_evidence.add(evidence_hash)
                
                # Skip if it's negated
                pre_context = combined_output[max(0, match.start()-20):match.start()].lower()
                if any(neg in pre_context for neg in ['not ', 'no ', "n't ", 'without ']):
                    continue
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': vuln_type,
                    'name': f'{vuln_type.replace("_", " ").title()}: {match.group(0)[:50]}',
                    'severity': severity,
                    'confidence': 0.7,
                    'location': context.get('target', 'Unknown'),
                    'evidence': evidence[:300],
                    'exploitable': exploitable,
                    'tool': context.get('tool', 'unknown')
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    # =========================================================================
    # Strategy 5: Heuristic Analysis
    # =========================================================================
    
    def _build_severity_map(self) -> Dict[str, float]:
        """Build keyword to severity mapping"""
        return {
            'critical': 9.5,
            'severe': 9.0,
            'high': 7.5,
            'important': 7.0,
            'medium': 5.0,
            'moderate': 5.0,
            'low': 2.5,
            'minor': 2.0,
            'info': 1.0,
            'informational': 1.0,
            'warning': 4.0,
            'error': 5.0,
        }
    
    def _heuristic_parse(self, stdout: str, stderr: str, context: Dict) -> Dict:
        """Last resort heuristic analysis"""
        vulnerabilities = []
        
        # Analyze output structure
        lines = stdout.split('\n')
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            # Look for severity indicators
            severity = None
            for keyword, sev in self.severity_keywords.items():
                if keyword in line.lower():
                    severity = sev
                    break
            
            if severity and severity >= 4.0:
                # This line likely contains a finding
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'heuristic_finding',
                    'name': line[:100],
                    'severity': severity,
                    'confidence': 0.5,  # Low confidence for heuristic
                    'location': context.get('target', 'Unknown'),
                    'evidence': line[:300],
                    'exploitable': severity >= 7.0,
                    'tool': context.get('tool', 'unknown')
                })
        
        # If still nothing, look for any "interesting" lines
        if not vulnerabilities:
            interesting_patterns = [
                r'^[\+\!\*\[\]]',  # Lines starting with special chars
                r'found|detected|discovered|vulnerable',
                r'success|failed|error',
            ]
            
            for line in lines[:50]:  # Check first 50 lines
                line = line.strip()
                if any(re.search(p, line, re.IGNORECASE) for p in interesting_patterns):
                    if len(line) > 20:  # Skip very short lines
                        vulnerabilities.append({
                            'id': str(uuid.uuid4()),
                            'type': 'tool_output',
                            'name': line[:100],
                            'severity': 3.0,
                            'confidence': 0.3,
                            'location': context.get('target', 'Unknown'),
                            'evidence': line[:300],
                            'exploitable': False,
                            'tool': context.get('tool', 'unknown')
                        })
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def get_statistics(self) -> Dict:
        """Get parsing statistics"""
        total = self.parse_stats['total'] or 1
        return {
            **self.parse_stats,
            'success_rate': (total - self.parse_stats['failed']) / total,
            'structured_rate': self.parse_stats['structured'] / total,
            'tool_specific_rate': self.parse_stats['tool_specific'] / total,
        }
    
    def get_supported_tools(self) -> List[str]:
        """Get list of tools with dedicated parsers"""
        return list(self.tool_parsers.keys())


# Backward compatibility wrapper
class OutputParser(EnhancedOutputParser):
    """Backward compatible wrapper"""
    
    def parse_tool_output(self, tool_name: str, stdout: str, stderr: str, command: str = "", target: str = "") -> Dict[str, Any]:
        """Original interface method with full signature"""
        return self.parse(tool_name, stdout, stderr, command, target)
