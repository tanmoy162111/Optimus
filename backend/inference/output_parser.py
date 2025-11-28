"""Parse tool outputs into structured vulnerability data
Supports: Nmap, Nikto, SQLMap, Nuclei, and 20+ other tools
"""
import re
import json
import xml.etree.ElementTree as ET
import uuid
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
                'raw_output': str,
                'parse_error': str (optional)
            }
        """
        try:
            # Route to appropriate parser
            if tool_name == 'nmap':
                return self._parse_nmap(stdout, stderr)
            elif tool_name == 'sqlmap':
                return self._parse_sqlmap(stdout, stderr)
            elif tool_name == 'nuclei':
                return self._parse_nuclei(stdout, stderr)
            elif tool_name == 'sublist3r':
                return self._parse_sublist3r(stdout, stderr)
            elif tool_name == 'whatweb':
                return self._parse_whatweb(stdout, stderr)
            elif tool_name == 'dalfox':
                return self._parse_dalfox(stdout, stderr)
            elif tool_name == 'commix':
                return self._parse_commix(stdout, stderr)
            else:
                # Generic parser for unhandled tools
                return self._parse_generic(stdout, stderr)
        except Exception as e:
            print(f"[Parser] Error parsing {tool_name}: {e}")
            return {
                'vulnerabilities': [],
                'hosts': [],
                'services': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_nmap(self, stdout: str, stderr: str) -> Dict:
        """Enhanced Nmap parsing with error handling"""
        try:
            vulnerabilities = []
            services = []
            
            # Parse open ports MORE AGGRESSIVELY
            for line in stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0].split('/')[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                        
                        # Create vulnerability for EVERY open port
                        vulnerabilities.append({
                            'id': str(uuid.uuid4()),
                            'type': 'open_port',
                            'severity': 4.0,
                            'confidence': 0.95,
                            'name': f'Open Port: {port}/{service}',
                            'location': f'Port {port}',
                            'evidence': f"{line.strip()} {version}".strip(),
                            'exploitable': service in ['http', 'https', 'ssh', 'ftp', 'telnet']
                        })
                        
                        services.append({
                            'port': port,
                            'service': service,
                            'version': version
                        })
            
            # Look for NSE script vulnerabilities
            vuln_patterns = ['VULNERABLE', 'CVE-', 'exploit', 'Potential']
            for line in stdout.split('\n'):
                if any(pattern in line for pattern in vuln_patterns):
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'service_vulnerability',
                        'severity': 7.0,
                        'confidence': 0.8,
                        'name': 'Nmap Script Vulnerability',
                        'location': 'Service scan',
                        'evidence': line[:300],
                        'exploitable': True
                    })
            
            return {
                'vulnerabilities': vulnerabilities,
                'services': services,
                'hosts': [],
                'raw_output': stdout
            }
        except Exception as e:
            print(f"[Parser] Nmap parsing error: {e}")
            # Return empty but valid result
            return {
                'vulnerabilities': [],
                'services': [],
                'hosts': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_sqlmap(self, stdout: str, stderr: str) -> Dict:
        """Parse SQLMap output for SQL injection findings with error handling"""
        try:
            vulnerabilities = []
            
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
                            'id': str(uuid.uuid4()),
                            'type': 'sql_injection',
                            'severity': 9.0,  # Critical
                            'confidence': 0.95,
                            'name': f'SQL Injection in {current_param}',
                            'location': current_param,
                            'evidence': f"Type: {current_type}, Payload: {current_payload[:100] if current_payload else 'N/A'}",
                            'exploitable': True
                        })
                        
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
                        'id': str(uuid.uuid4()),
                        'type': 'sql_injection',
                        'severity': 9.0,
                        'confidence': 0.9,
                        'name': 'SQL Injection Detected',
                        'location': 'Target endpoint',
                        'evidence': db_match if db_match else 'SQLMap confirmed SQL injection vulnerability',
                        'exploitable': True
                    })
            
            # Check for database enumeration results
            if 'available databases' in stdout.lower() or 'database:' in stdout.lower():
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'info_disclosure',
                    'severity': 7.5,
                    'confidence': 0.95,
                    'name': 'Database Information Disclosure',
                    'location': 'Database enumeration',
                    'evidence': 'SQLMap successfully enumerated database information',
                    'exploitable': True
                })
            
            return {
                'vulnerabilities': vulnerabilities,
                'raw_output': stdout
            }
        except Exception as e:
            print(f"[Parser] SQLMap parsing error: {e}")
            # Return empty but valid result
            return {
                'vulnerabilities': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_nuclei(self, stdout: str, stderr: str) -> Dict:
        """Parse Nuclei JSON output with error handling"""
        try:
            vulnerabilities = []
            
            for line in stdout.split('\n'):
                if line.strip().startswith('{'):
                    try:
                        data = json.loads(line)
                        severity = data.get('info', {}).get('severity', 'medium')
                        cvss_score = self._nuclei_severity_to_cvss(severity)
                        
                        vulnerabilities.append({
                            'id': str(uuid.uuid4()),
                            'type': data.get('info', {}).get('name', 'nuclei_finding'),
                            'severity': cvss_score,
                            'confidence': 0.9,
                            'name': data.get('info', {}).get('name', 'Nuclei Finding'),
                            'location': data.get('matched-at', 'Unknown'),
                            'evidence': json.dumps(data, indent=2),
                            'exploitable': severity in ['critical', 'high', 'medium']
                        })
                    except json.JSONDecodeError:
                        # Skip invalid JSON lines
                        continue
            
            return {
                'vulnerabilities': vulnerabilities,
                'raw_output': stdout
            }
        except Exception as e:
            print(f"[Parser] Nuclei parsing error: {e}")
            # Return empty but valid result
            return {
                'vulnerabilities': [],
                'raw_output': stdout,
                'parse_error': str(e)
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

    def _parse_sublist3r(self, stdout: str, stderr: str) -> Dict:
        """Parse Sublist3r subdomain enumeration with error handling"""
        try:
            vulnerabilities = []
            subdomains = []
            
            # Check for API errors in output
            if 'api key' in stdout.lower() or 'api key' in stderr.lower():
                print("[Parser] Sublist3r: API key warning detected")
                # Continue anyway, tool may still work with limited functionality

            # Extract subdomains from output
            # Sublist3r typically outputs one subdomain per line
            lines = stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or line.startswith('[') or line.startswith('Total'):
                    continue
                
                # Extract domain patterns
                # Look for valid domain format: subdomain.domain.tld
                domain_pattern = r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
                matches = re.findall(domain_pattern, line)
                
                for match in matches:
                    if match not in subdomains:
                        subdomains.append(match)
                        
                        # Create a vulnerability entry for each subdomain found
                        # This counts as reconnaissance findings
                        vulnerabilities.append({
                            'id': str(uuid.uuid4()),
                            'type': 'subdomain_discovered',
                            'severity': 2.0,  # Low severity - informational
                            'confidence': 0.95,
                            'name': f'Subdomain: {match}',
                            'location': match,
                            'evidence': f'Subdomain enumeration found: {match}',
                            'exploitable': False
                        })
            
            # Check for "No subdomains found" messages
            if 'no subdomains' in stdout.lower() or len(subdomains) == 0:
                # Tool ran but found nothing - still a valid result
                print(f"[Parser] sublist3r found 0 subdomains")
            else:
                print(f"[Parser] sublist3r found {len(subdomains)} subdomains")
            
            return {
                'vulnerabilities': vulnerabilities,
                'subdomains': subdomains,
                'subdomain_count': len(subdomains),
                'raw_output': stdout
            }
        except Exception as e:
            print(f"[Parser] Sublist3r parsing error: {e}")
            # Return empty but valid result
            return {
                'vulnerabilities': [],
                'subdomains': [],
                'subdomain_count': 0,
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_whatweb(self, stdout: str, stderr: str) -> Dict:
        """Parse WhatWeb technology detection with error handling"""
        try:
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
        except Exception as e:
            print(f"[Parser] WhatWeb parsing error: {e}")
            # Return empty but valid result
            return {
                'vulnerabilities': [],
                'technologies': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_dalfox(self, stdout: str, stderr: str) -> Dict:
        """Parse Dalfox XSS scanner with error handling"""
        try:
            vulnerabilities = []
            
            xss_pattern = r'POC: (.+)'
            for match in re.finditer(xss_pattern, stdout):
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
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
        except Exception as e:
            print(f"[Parser] Dalfox parsing error: {e}")
            # Return empty but valid result
            return {
                'vulnerabilities': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_commix(self, stdout: str, stderr: str) -> Dict:
        """Parse Commix command injection scanner with error handling"""
        try:
            vulnerabilities = []
            
            if 'command injection' in stdout.lower() or 'vulnerable' in stdout.lower():
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
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
        except Exception as e:
            print(f"[Parser] Commix parsing error: {e}")
            # Return empty but valid result
            return {
                'vulnerabilities': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_generic(self, stdout: str, stderr: str) -> Dict:
        """Generic parser for unhandled tools"""
        try:
            # Look for common vulnerability indicators
            vuln_indicators = [
                'vulnerab', 'exploit', 'cve-', 'risk', 'severity',
                'critical', 'high', 'medium', 'low'
            ]
            
            vulnerabilities = []
            evidence_lines = []
            
            # Scan output for vulnerability indicators
            for line in (stdout + '\n' + stderr).split('\n'):
                line_lower = line.lower()
                if any(indicator in line_lower for indicator in vuln_indicators):
                    evidence_lines.append(line.strip())
            
            # Create vulnerability entries if we found indicators
            if evidence_lines:
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'generic_finding',
                    'severity': 5.0,  # Medium
                    'confidence': 0.7,
                    'name': 'Tool Output Analysis',
                    'location': 'Generic parsing',
                    'evidence': '\n'.join(evidence_lines[:10]),  # First 10 lines
                    'exploitable': True
                })
            
            return {
                'vulnerabilities': vulnerabilities,
                'hosts': [],
                'services': [],
                'raw_output': stdout + '\n' + stderr
            }
        except Exception as e:
            print(f"[Parser] Generic parsing error: {e}")
            return {
                'vulnerabilities': [],
                'hosts': [],
                'services': [],
                'raw_output': stdout + '\n' + stderr,
                'parse_error': str(e)
            }