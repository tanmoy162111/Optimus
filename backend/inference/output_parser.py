"""Parse tool outputs into structured vulnerability data
Supports: Nmap, Nikto, SQLMap, Nuclei, and 20+ other tools
"""
import re
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

class OutputParser:
    def parse_tool_output(self, tool_name: str, stdout: str,
                      stderr: str) -> Dict[str, Any]:
        """
        Parse tool output based on tool type
        
        Returns:
            {
                'vulnerabilities': [...],
                'hosts': [...],
                'services': [...],
                'raw_output': stdout
            }
        """
        parsers = {
            'nmap': self._parse_nmap,
            'nikto': self._parse_nikto,
            'sqlmap': self._parse_sqlmap,
            'nuclei': self._parse_nuclei,
            'sublist3r': self._parse_sublist3r,
            'whatweb': self._parse_whatweb,
            'dalfox': self._parse_dalfox,
            'commix': self._parse_commix,
        }
        
        parser = parsers.get(tool_name, self._parse_generic)
        return parser(stdout, stderr)

    def _parse_nmap(self, stdout: str, stderr: str) -> Dict:
        """Parse Nmap XML output"""
        vulnerabilities = []
        hosts = []
        services = []
        
        try:
            # Try to parse XML output
            if '<nmaprun' in stdout:
                root = ET.fromstring(stdout)
                
                for host in root.findall('host'):
                    host_data = {
                        'ip': host.find('address').get('addr'),
                        'status': host.find('status').get('state'),
                        'ports': []
                    }
                    
                    ports_elem = host.find('ports')
                    if ports_elem:
                        for port in ports_elem.findall('port'):
                            port_data = {
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'state': port.find('state').get('state'),
                                'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
                            }
                            host_data['ports'].append(port_data)
                            services.append(port_data)
                    
                    hosts.append(host_data)
            
            # Parse for vulnerabilities (open ports, outdated services)
            open_port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
            for match in re.finditer(open_port_pattern, stdout):
                port, service = match.groups()
                vulnerabilities.append({
                    'type': 'open_port',
                    'severity': 3.0,
                    'confidence': 0.9,
                    'name': f'Open Port: {port}/{service}',
                    'location': f'Port {port}',
                    'evidence': match.group(0)
                })
            
        except Exception as e:
            print(f"Nmap parsing error: {e}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': hosts,
            'services': services,
            'raw_output': stdout
        }

    def _parse_sqlmap(self, stdout: str, stderr: str) -> Dict:
        """Parse SQLMap output"""
        vulnerabilities = []
        
        # SQL injection patterns
        patterns = [
            (r'Parameter: (\S+).*?Type: (\S+)', 'sql_injection', 8.0),
            (r'back-end DBMS: (\S+)', 'database_exposure', 7.0),
            (r'the back-end DBMS is', 'sql_injection', 8.0),
        ]
        
        for pattern, vuln_type, severity in patterns:
            for match in re.finditer(pattern, stdout, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append({
                    'type': vuln_type,
                    'severity': severity,
                    'confidence': 0.95,
                    'name': f'SQL Injection in parameter: {match.group(1) if match.lastindex >= 1 else "unknown"}',
                    'location': match.group(0),
                    'evidence': match.group(0),
                    'exploitable': True
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'raw_output': stdout
        }

    def _parse_nuclei(self, stdout: str, stderr: str) -> Dict:
        """Parse Nuclei JSON output"""
        vulnerabilities = []
        
        for line in stdout.split('\n'):
            if line.strip().startswith('{'):
                try:
                    finding = json.loads(line)
                    vulnerabilities.append({
                        'type': finding.get('template-id', 'unknown'),
                        'severity': self._nuclei_severity_to_cvss(finding.get('info', {}).get('severity', 'info')),
                        'confidence': 0.9,
                        'name': finding.get('info', {}).get('name', 'Unknown'),
                        'location': finding.get('matched-at', ''),
                        'evidence': finding.get('matcher-name', ''),
                        'exploitable': finding.get('info', {}).get('severity') in ['critical', 'high']
                    })
                except:
                    pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'raw_output': stdout
        }

    def _parse_nikto(self, stdout: str, stderr: str) -> Dict:
        """Parse Nikto output"""
        vulnerabilities = []
        
        # Parse Nikto findings
        finding_pattern = r'\+ ([^:]+): (.+)'
        for match in re.finditer(finding_pattern, stdout):
            location, description = match.groups()
            vulnerabilities.append({
                'type': 'web_vulnerability',
                'severity': 5.0,
                'confidence': 0.8,
                'name': description[:100],
                'location': location,
                'evidence': match.group(0)
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'raw_output': stdout
        }

    def _parse_sublist3r(self, stdout: str, stderr: str) -> Dict:
        """Parse Sublist3r subdomain enumeration"""
        subdomains = []
        
        # Extract subdomains
        domain_pattern = r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
        for match in re.finditer(domain_pattern, stdout):
            subdomain = match.group(0)
            if subdomain not in subdomains:
                subdomains.append(subdomain)
        
        return {
            'vulnerabilities': [],
            'subdomains': subdomains,
            'raw_output': stdout
        }

    def _parse_whatweb(self, stdout: str, stderr: str) -> Dict:
        """Parse WhatWeb technology detection"""
        technologies = []
        
        # Extract technologies
        tech_pattern = r'\[([^\]]+)\]'
        for match in re.finditer(tech_pattern, stdout):
            tech = match.group(1)
            if tech not in technologies:
                technologies.append(tech)
        
        return {
            'vulnerabilities': [],
            'technologies': technologies,
            'raw_output': stdout
        }

    def _parse_dalfox(self, stdout: str, stderr: str) -> Dict:
        """Parse Dalfox XSS scanner"""
        vulnerabilities = []
        
        xss_pattern = r'POC: (.+)'
        for match in re.finditer(xss_pattern, stdout):
            vulnerabilities.append({
                'type': 'xss',
                'severity': 7.0,
                'confidence': 0.9,
                'name': 'Cross-Site Scripting (XSS)',
                'location': match.group(1),
                'evidence': match.group(0),
                'exploitable': True
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'raw_output': stdout
        }

    def _parse_commix(self, stdout: str, stderr: str) -> Dict:
        """Parse Commix command injection scanner"""
        vulnerabilities = []
        
        if 'command injection' in stdout.lower() or 'vulnerable' in stdout.lower():
            vulnerabilities.append({
                'type': 'command_injection',
                'severity': 9.0,
                'confidence': 0.95,
                'name': 'Command Injection',
                'location': 'Detected by Commix',
                'evidence': stdout[:500],
                'exploitable': True
            })
        
        return {
            'vulnerabilities': vulnerabilities,
            'raw_output': stdout
        }

    def _parse_generic(self, stdout: str, stderr: str) -> Dict:
        """Generic parser for unknown tools"""
        return {
            'vulnerabilities': [],
            'raw_output': stdout,
            'stderr': stderr
        }

    def _nuclei_severity_to_cvss(self, severity: str) -> float:
        """Convert Nuclei severity to CVSS score"""
        mapping = {
            'critical': 9.5,
            'high': 8.0,
            'medium': 6.0,
            'low': 3.0,
            'info': 1.0
        }
        return mapping.get(severity.lower(), 5.0)
