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
        """Parse Nmap output (supports both text and XML formats)"""
        vulnerabilities = []
        hosts = []
        services = []
        
        try:
            # Parse text output for open ports
            print(f"[DEBUG] Parsing Nmap output ({len(stdout)} chars)")
            
            for line in stdout.split('\n'):
                # Match patterns like: 3000/tcp open  http    Node.js Express framework
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]  # e.g., "3000/tcp"
                        state = parts[1]       # e.g., "open"
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        version_info = ' '.join(parts[3:]) if len(parts) > 3 else ''
                        
                        port = port_proto.split('/')[0]
                        
                        # Create vulnerability entry for open port
                        vulnerabilities.append({
                            'type': 'open_port',
                            'severity': 4.0,  # Medium severity
                            'confidence': 0.95,
                            'name': f'Open Port: {port}/{service}',
                            'location': f'Port {port}',
                            'evidence': f"{line.strip()} {version_info}".strip(),
                            'exploitable': False
                        })
                        
                        services.append({
                            'port': port,
                            'service': service,
                            'state': state,
                            'version': version_info
                        })
                        
                        print(f"[DEBUG] Found open port: {port} ({service})")
                # Check for vulnerability script results
            vuln_indicators = ['VULNERABLE', 'CVE-', 'exploit', 'Potential', 'disclosure']
            vuln_lines = []
            
            for line in stdout.split('\n'):
                if any(indicator in line for indicator in vuln_indicators):
                    vuln_lines.append(line.strip())
            
            # Create vulnerability entries from script results
            for vuln_line in vuln_lines[:10]:  # Limit to 10 findings
                # Try to extract CVE if present
                cve_match = None
                if 'CVE-' in vuln_line:
                    import re
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', vuln_line)
            
                severity = 7.0 if 'VULNERABLE' in vuln_line else 6.0
                
                vulnerabilities.append({
                    'type': 'service_vulnerability',
                    'severity': severity,
                    'confidence': 0.8,
                    'name': cve_match.group(0) if cve_match else 'Nmap Script Vulnerability',
                    'location': 'Service scan',
                    'evidence': vuln_line[:300],
                    'exploitable': True
                })
                
                print(f"[DEBUG] Found vulnerability: {vuln_line[:100]}")
            
            # Try XML parsing if available (backup method)
            if '<nmaprun' in stdout:
                try:
                    root = ET.fromstring(stdout)
                    for host in root.findall('.//host'):
                        for port in host.findall('.//port'):
                            port_id = port.get('portid')
                            service_elem = port.find('service')
                            state_elem = port.find('state')
                            
                            if state_elem is not None and state_elem.get('state') == 'open':
                                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                                
                                # Check if we already have this port
                                if not any(v.get('location') == f'Port {port_id}' for v in vulnerabilities):
                                    vulnerabilities.append({
                                        'type': 'open_port',
                                        'severity': 4.0,
                                        'confidence': 0.95,
                                        'name': f'Open Port: {port_id}/{service_name}',
                                        'location': f'Port {port_id}',
                                        'evidence': f'XML: Port {port_id} open, service: {service_name}'
                                    })
                except Exception as e:
                    print(f"[DEBUG] XML parsing failed (non-critical): {e}")
        except Exception as e:
            print(f"[ERROR] Nmap parsing error: {e}")
            import traceback
            traceback.print_exc()
        print(f"[DEBUG] Nmap parse complete: {len(vulnerabilities)} vulnerabilities, {len(services)} services")
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': hosts,
            'services': services,
            'raw_output': stdout
        }

    def _parse_sqlmap(self, stdout: str, stderr: str) -> Dict:
        """Parse SQLMap output for SQL injection findings"""
        vulnerabilities = []
        
        print(f"[DEBUG] Parsing SQLMap output ({len(stdout)} chars)")
        
        # SQL injection detection patterns
        injection_indicators = [
            'Parameter:',
            'Type:',
            'Title:',
            'Payload:',
            'is vulnerable',
            'sqlmap identified',
            'back-end DBMS:',
            'injectable'
        ]
        
        # Check if SQLMap found any injections
        found_injection = any(indicator.lower() in stdout.lower() for indicator in injection_indicators)
        
        if found_injection:
            # Parse detailed injection information
            lines = stdout.split('\n')
            current_param = None
            current_type = None
            current_title = None
            current_payload = None
            
            for i, line in enumerate(lines):
                line_lower = line.lower()
                
                # Extract parameter name
                if 'parameter:' in line_lower:
                    current_param = line.split('Parameter:')[-1].strip()
                
                # Extract injection type
                elif 'type:' in line_lower and current_param:
                    current_type = line.split('Type:')[-1].strip()
                
                # Extract title/technique
                elif 'title:' in line_lower:
                    current_title = line.split('Title:')[-1].strip()
                
                # Extract payload
                elif 'payload:' in line_lower:
                    current_payload = line.split('Payload:')[-1].strip()
                
                # Create vulnerability when we have enough info
                if current_param and current_type and (current_title or current_payload):
                    vulnerabilities.append({
                        'type': 'sql_injection',
                        'severity': 9.0,  # Critical
                        'confidence': 0.95,
                        'name': f'SQL Injection in {current_param}',
                        'location': current_param,
                        'evidence': f"Type: {current_type}, Payload: {current_payload[:100] if current_payload else 'N/A'}",
                        'exploitable': True
                    })
                    
                    print(f"[DEBUG] Found SQL injection in parameter: {current_param}")
                    
                    # Reset for next finding
                    current_param = None
                    current_type = None
                    current_title = None
                    current_payload = None
            
            # If we found indicators but couldn't parse details, create generic entry
            if not vulnerabilities and found_injection:
                # Extract database info
                db_match = None
                for line in lines:
                    if 'back-end DBMS' in line.lower():
                        db_match = line
                        break
                
                vulnerabilities.append({
                    'type': 'sql_injection',
                    'severity': 9.0,
                    'confidence': 0.9,
                    'name': 'SQL Injection Detected',
                    'location': 'Target endpoint',
                    'evidence': db_match if db_match else 'SQLMap confirmed SQL injection vulnerability',
                    'exploitable': True
                })
                
                print(f"[DEBUG] Generic SQL injection entry created")
        
        # Check for database enumeration results
        if 'available databases' in stdout.lower() or 'database:' in stdout.lower():
            vulnerabilities.append({
                'type': 'info_disclosure',
                'severity': 7.5,
                'confidence': 0.95,
                'name': 'Database Information Disclosure',
                'location': 'Database enumeration',
                'evidence': 'SQLMap successfully enumerated database information',
                'exploitable': True
            })
            
            print(f"[DEBUG] Database disclosure detected")
        
        print(f"[DEBUG] SQLMap parse complete: {len(vulnerabilities)} vulnerabilities")
        
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