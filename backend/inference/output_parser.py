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
            elif tool_name == 'nikto':
                return self._parse_nikto(stdout, stderr)
            elif tool_name == 'sublist3r':
                return self._parse_sublist3r(stdout, stderr)
            elif tool_name == 'whatweb':
                return self._parse_whatweb(stdout, stderr)
            elif tool_name == 'dalfox':
                return self._parse_dalfox(stdout, stderr)
            elif tool_name == 'commix':
                return self._parse_commix(stdout, stderr)
            elif tool_name in ['gobuster', 'ffuf', 'dirb']:
                return self._parse_directory_scanner(stdout, stderr)
            # ADD THESE:
            elif tool_name == 'fierce':
                return self._parse_fierce(stdout, stderr)
            elif tool_name == 'dnsenum':
                return self._parse_dnsenum(stdout, stderr)
            elif tool_name == 'sslscan':
                return self._parse_sslscan(stdout, stderr)
            elif tool_name == 'hydra':
                return self._parse_hydra(stdout, stderr)
            elif tool_name == 'enum4linux':
                return self._parse_enum4linux(stdout, stderr)
            elif tool_name == 'wpscan':
                return self._parse_wpscan(stdout, stderr)
            elif tool_name == 'amass':
                return self._parse_amass(stdout, stderr)
            elif tool_name == 'xsser':
                return self._parse_xsser(stdout, stderr)
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
        """Enhanced Nmap parsing with robust pattern matching"""
        try:
            vulnerabilities = []
            services = []
            
            # Parse open ports - IMPROVED with regex for reliability
            # Matches patterns like: "80/tcp open http" or "22/tcp  open  ssh"
            port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?'
            
            for match in re.finditer(port_pattern, stdout, re.IGNORECASE):
                port = match.group(1)
                protocol = match.group(2)
                service = match.group(3)
                version = match.group(4) if match.group(4) else ''
                
                # Create vulnerability for open port
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'open_port',
                    'severity': 4.0 if service in ['http', 'https', 'ssh', 'ftp', 'telnet', 'smb', 'mysql', 'mssql', 'postgres'] else 2.0,
                    'confidence': 0.95,
                    'name': f'Open {protocol.upper()} Port: {port}/{service}',
                    'location': f'Port {port}',
                    'evidence': f"{port}/{protocol} open {service} {version}".strip(),
                    'exploitable': service in ['http', 'https', 'ssh', 'ftp', 'telnet', 'smb', 'mysql']
                })
                
                services.append({
                    'port': port,
                    'protocol': protocol,
                    'service': service,
                    'version': version
                })
            
            # Look for CVE references
            cve_pattern = r'(CVE-\d{4}-\d+)'
            for cve in re.findall(cve_pattern, stdout, re.IGNORECASE):
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'cve',
                    'severity': 8.0,  # High severity for known CVEs
                    'confidence': 0.9,
                    'name': f'Known Vulnerability: {cve.upper()}',
                    'location': 'Nmap NSE detection',
                    'evidence': cve,
                    'exploitable': True
                })
            
            # Look for NSE script vulnerabilities with broader patterns
            vuln_indicators = [
                ('VULNERABLE', 9.0),
                ('Potential', 6.0),
                ('exploit', 7.0),
                ('vulnerable', 8.0),
                ('CRITICAL', 9.0),
                ('HIGH', 7.0),
                ('MEDIUM', 5.0),
                ('risk', 5.0)
            ]
            
            for line in stdout.split('\n'):
                for indicator, severity in vuln_indicators:
                    if indicator.lower() in line.lower() and 'not vulnerable' not in line.lower():
                        # Avoid duplicates
                        if not any(v.get('evidence') == line.strip()[:300] for v in vulnerabilities):
                            vulnerabilities.append({
                                'id': str(uuid.uuid4()),
                                'type': 'service_vulnerability',
                                'severity': severity,
                                'confidence': 0.8,
                                'name': 'Nmap Script Finding',
                                'location': 'Service scan',
                                'evidence': line.strip()[:300],
                                'exploitable': severity >= 7.0
                            })
                        break  # Only one finding per line
            
            # Parse host information
            host_pattern = r'Nmap scan report for\s+(\S+)'
            hosts = re.findall(host_pattern, stdout)
            
            print(f"[Parser] Nmap found: {len(services)} services, {len(vulnerabilities)} findings")
            
            return {
                'vulnerabilities': vulnerabilities,
                'services': services,
                'hosts': hosts,
                'raw_output': stdout
            }
        except Exception as e:
            print(f"[Parser] Nmap parsing error: {e}")
            return {
                'vulnerabilities': [],
                'services': [],
                'hosts': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_nikto(self, stdout: str, stderr: str) -> Dict:
        """Enhanced Nikto parser with better pattern matching"""
        try:
            vulnerabilities = []
            
            # Nikto output patterns - multiple formats
            patterns = [
                # Standard format: + OSVDB-XXXX: /path: Description
                r'\+\s*(?:OSVDB-(\d+):\s*)?(/[^\s:]*)?:?\s*(.+)',
                # Alternative format: + Server may be vulnerable to...
                r'\+\s*(Server [^.]+\.)',
                # Another format: + /path: Description
                r'\+\s*(/[^\s]+):\s*(.+)',
                # Generic interesting finding
                r'\+\s*([A-Z][^:]+):\s*(.+)',
            ]
            
            # Severity keywords
            critical_keywords = ['remote code', 'rce', 'command execution', 'file upload', 'arbitrary file']
            high_keywords = ['sql injection', 'sqli', 'xss', 'cross-site', 'authentication bypass', 'directory traversal']
            medium_keywords = ['information disclosure', 'sensitive', 'backup', 'config', 'debug', 'error message']
            
            for line in stdout.split('\n'):
                line = line.strip()
                if not line.startswith('+'):
                    continue
                
                # Skip informational lines
                if any(skip in line.lower() for skip in ['target ip', 'target hostname', 'target port', 'start time', 'end time', 'host(s) tested']):
                    continue
                
                # Extract information from the line
                description = line[1:].strip()  # Remove leading +
                path = ''
                osvdb = None
                
                # Try to extract OSVDB
                osvdb_match = re.search(r'OSVDB-(\d+)', line)
                if osvdb_match:
                    osvdb = osvdb_match.group(1)
                
                # Try to extract path
                path_match = re.search(r'(/[^\s:]+)', line)
                if path_match:
                    path = path_match.group(1)
                
                # Determine severity
                desc_lower = description.lower()
                if any(kw in desc_lower for kw in critical_keywords):
                    severity = 9.0
                    vuln_type = 'critical_vulnerability'
                elif any(kw in desc_lower for kw in high_keywords):
                    severity = 7.5
                    vuln_type = 'high_vulnerability'
                elif any(kw in desc_lower for kw in medium_keywords):
                    severity = 5.0
                    vuln_type = 'medium_vulnerability'
                else:
                    severity = 3.0
                    vuln_type = 'informational'
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': vuln_type,
                    'severity': severity,
                    'confidence': 0.85 if osvdb else 0.7,
                    'name': description[:100],
                    'location': path or 'Web Application',
                    'evidence': line,
                    'osvdb': osvdb,
                    'exploitable': severity >= 6.0
                })
            
            print(f"[Parser] Nikto found {len(vulnerabilities)} findings")
            return {
                'vulnerabilities': vulnerabilities,
                'raw_output': stdout
            }
            
        except Exception as e:
            print(f"[Parser] Nikto parsing error: {e}")
            return {
                'vulnerabilities': [],
                'raw_output': stdout,
                'parse_error': str(e)
            }

    def _parse_directory_scanner(self, stdout: str, stderr: str) -> Dict:
        """Parse gobuster, ffuf, dirb output for discovered directories"""
        try:
            vulnerabilities = []
            
            # Common patterns for directory scanners
            # gobuster: /path (Status: 200)
            # ffuf: path [Status: 200, Size: 1234]
            # dirb: + http://target/path (CODE:200|SIZE:1234)
            
            patterns = [
                r'(/[\w\-./]+)\s*\(Status:\s*(\d+)',  # gobuster
                r'([\w\-./]+)\s*\[Status:\s*(\d+)',   # ffuf
                r'\+\s*https?://[^/]+(/[\w\-./]*)\s*\(CODE:(\d+)',  # dirb
            ]
            
            found_paths = set()
            
            for pattern in patterns:
                for match in re.finditer(pattern, stdout, re.IGNORECASE):
                    path = match.group(1)
                    status = match.group(2) if match.lastindex >= 2 else '200'
                    
                    if path not in found_paths:
                        found_paths.add(path)
                        
                        # Determine severity based on path
                        severity = 3.0
                        vuln_type = 'discovered_directory'
                        
                        path_lower = path.lower()
                        if any(ext in path_lower for ext in ['.bak', '.old', '.sql', '.conf', '.config']):
                            severity = 6.5
                            vuln_type = 'sensitive_file'
                        elif any(d in path_lower for d in ['/admin', '/backup', '/config', '/upload']):
                            severity = 5.0
                            vuln_type = 'sensitive_directory'
                        elif any(d in path_lower for d in ['/phpmyadmin', '/wp-admin', '/manager']):
                            severity = 5.5
                            vuln_type = 'admin_panel'
                        
                        vulnerabilities.append({
                            'id': str(uuid.uuid4()),
                            'type': vuln_type,
                            'severity': severity,
                            'confidence': 0.9,
                            'name': f'Discovered: {path}',
                            'location': path,
                            'evidence': f'Path {path} returned status {status}',
                            'exploitable': severity >= 5.0
                        })
            
            print(f"[Parser] Directory scanner found {len(vulnerabilities)} paths")
            
            return {
                'vulnerabilities': vulnerabilities,
                'directories': list(found_paths),
                'raw_output': stdout
            }
        except Exception as e:
            print(f"[Parser] Directory scanner parsing error: {e}")
            return {
                'vulnerabilities': [],
                'directories': [],
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
        """Enhanced generic parser for unhandled tools - MORE AGGRESSIVE detection"""
        try:
            vulnerabilities = []
            evidence_lines = []
            combined_output = stdout + '\n' + stderr
            
            # Comprehensive vulnerability indicators with severity
            vuln_patterns = [
                # Critical indicators
                (r'CVE-\d{4}-\d+', 'cve', 8.0),
                (r'CRITICAL', 'critical_finding', 9.0),
                (r'remote code execution', 'rce', 9.5),
                (r'command injection', 'command_injection', 9.0),
                (r'sql injection', 'sql_injection', 9.0),
                (r'authentication bypass', 'auth_bypass', 9.0),
                
                # High severity
                (r'VULNERABLE', 'vulnerability', 8.0),
                (r'HIGH', 'high_finding', 7.0),
                (r'exploit(?:able|ed)?', 'exploitable', 7.5),
                (r'cross-site scripting|xss', 'xss', 7.0),
                (r'path traversal', 'path_traversal', 7.0),
                (r'file inclusion', 'file_inclusion', 8.0),
                (r'insecure', 'insecure_config', 6.0),
                
                # Medium severity
                (r'MEDIUM', 'medium_finding', 5.0),
                (r'information disclosure', 'info_disclosure', 5.0),
                (r'sensitive data', 'sensitive_data', 5.5),
                (r'misconfigur', 'misconfiguration', 5.0),
                (r'outdated', 'outdated_software', 4.5),
                (r'deprecated', 'deprecated', 4.0),
                
                # Low/Info
                (r'LOW', 'low_finding', 3.0),
                (r'version.*\d+\.\d+', 'version_info', 2.0),
                (r'server:.*\S+', 'server_banner', 2.0),
            ]
            
            findings_added = set()
            
            for line in combined_output.split('\n'):
                line_lower = line.lower()
                
                for pattern, vuln_type, severity in vuln_patterns:
                    if re.search(pattern, line_lower):
                        # Create unique key to avoid duplicates
                        finding_key = f"{vuln_type}:{line.strip()[:50]}"
                        
                        if finding_key not in findings_added:
                            findings_added.add(finding_key)
                            evidence_lines.append(line.strip())
                            
                            vulnerabilities.append({
                                'id': str(uuid.uuid4()),
                                'type': vuln_type,
                                'severity': severity,
                                'confidence': 0.7,
                                'name': f'Detected: {vuln_type.replace("_", " ").title()}',
                                'location': 'Generic tool output',
                                'evidence': line.strip()[:300],
                                'exploitable': severity >= 6.0
                            })
                        break  # Only one match per line
            
            # Look for directory/file discoveries
            path_pattern = r'/([\w\-./]+(?:\.php|\.asp|\.aspx|\.jsp|\.html|\.txt|\.bak|\.sql|\.conf|\.xml))'
            for match in re.finditer(path_pattern, combined_output):
                path = match.group(0)
                finding_key = f"path:{path}"
                if finding_key not in findings_added:
                    findings_added.add(finding_key)
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'discovered_path',
                        'severity': 3.0,
                        'confidence': 0.8,
                        'name': f'Discovered Path: {path}',
                        'location': path,
                        'evidence': f'Path found: {path}',
                        'exploitable': any(ext in path for ext in ['.bak', '.sql', '.conf'])
                    })
            
            print(f"[Parser] Generic parser found {len(vulnerabilities)} findings")
            
            return {
                'vulnerabilities': vulnerabilities,
                'hosts': [],
                'services': [],
                'raw_output': combined_output
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
    
    def _parse_fierce(self, stdout: str, stderr: str) -> Dict:
        """Parse fierce DNS enumeration output"""
        vulnerabilities = []
        hosts = []
            
        # Fierce outputs discovered hosts
        for line in stdout.split('\n'):
            if 'Found:' in line or re.match(r'\d+\.\d+\.\d+\.\d+', line):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                host_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                    
                if ip_match:
                    hosts.append(ip_match.group(1))
                if host_match:
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'subdomain',
                        'severity': 3.0,
                        'confidence': 0.9,
                        'name': f'Subdomain discovered: {host_match.group(1)}',
                        'location': host_match.group(1),
                        'evidence': line.strip(),
                        'exploitable': False
                    })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': list(set(hosts)),
            'services': [],
            'raw_output': stdout
        }
        
    def _parse_dnsenum(self, stdout: str, stderr: str) -> Dict:
        """Parse dnsenum output"""
        vulnerabilities = []
        hosts = []
            
        for line in stdout.split('\n'):
            # Look for IP addresses and hostnames
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                hosts.append(ip_match.group(1))
                
            # Zone transfer vulnerability
            if 'zone transfer' in line.lower() and 'failed' not in line.lower():
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'zone_transfer',
                    'severity': 7.0,
                    'confidence': 0.95,
                    'name': 'DNS Zone Transfer Allowed',
                    'location': 'DNS Server',
                    'evidence': line.strip(),
                    'exploitable': True
                })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': list(set(hosts)),
            'services': [],
            'raw_output': stdout
        }
        
    def _parse_sslscan(self, stdout: str, stderr: str) -> Dict:
        """Parse sslscan output"""
        vulnerabilities = []
            
        weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5']
            
        for line in stdout.split('\n'):
            line_lower = line.lower()
                
            # Check for weak ciphers
            for cipher in weak_ciphers:
                if cipher.lower() in line_lower and 'accepted' in line_lower:
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'weak_cipher',
                        'severity': 5.0,
                        'confidence': 0.95,
                        'name': f'Weak Cipher Supported: {cipher}',
                        'location': 'SSL/TLS Configuration',
                        'evidence': line.strip(),
                        'exploitable': False
                    })
                
            # SSLv2/SSLv3
            if ('sslv2' in line_lower or 'sslv3' in line_lower) and 'enabled' in line_lower:
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'deprecated_ssl',
                    'severity': 7.0,
                    'confidence': 0.95,
                    'name': 'Deprecated SSL Version Enabled',
                    'location': 'SSL/TLS Configuration',
                    'evidence': line.strip(),
                    'exploitable': True
                })
                
            # Certificate issues
            if 'expired' in line_lower:
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'type': 'expired_certificate',
                    'severity': 5.0,
                    'confidence': 0.95,
                    'name': 'Expired SSL Certificate',
                    'location': 'SSL Certificate',
                    'evidence': line.strip(),
                    'exploitable': False
                })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
        
    def _parse_hydra(self, stdout: str, stderr: str) -> Dict:
        """Parse hydra password cracking output"""
        vulnerabilities = []
            
        # Look for successful logins
        # Pattern: [PORT][SERVICE] host: HOST   login: USER   password: PASS
        login_pattern = r'\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)'
            
        for match in re.finditer(login_pattern, stdout):
            port, service, host, username, password = match.groups()
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'weak_credentials',
                'severity': 9.0,
                'confidence': 0.99,
                'name': f'Weak Credentials Found: {service}',
                'location': f'{host}:{port}',
                'evidence': f'Username: {username}, Password: {password}',
                'exploitable': True,
                'credentials': {'username': username, 'password': password}
            })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
        
    def _parse_enum4linux(self, stdout: str, stderr: str) -> Dict:
        """Parse enum4linux SMB enumeration output"""
        vulnerabilities = []
        services = []
            
        # Look for shares
        share_pattern = r'//([^/]+)/(\S+)'
        for match in re.finditer(share_pattern, stdout):
            host, share = match.groups()
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'smb_share',
                'severity': 4.0,
                'confidence': 0.9,
                'name': f'SMB Share Found: {share}',
                'location': f'//{host}/{share}',
                'evidence': match.group(0),
                'exploitable': 'IPC$' not in share
            })
            
        # Look for users
        user_pattern = r'user:\[([^\]]+)\]'
        for match in re.finditer(user_pattern, stdout):
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'user_enumeration',
                'severity': 3.0,
                'confidence': 0.9,
                'name': f'User Found: {match.group(1)}',
                'location': 'SMB',
                'evidence': match.group(0),
                'exploitable': False
            })
            
        # Null session
        if 'null session' in stdout.lower() and 'allowed' in stdout.lower():
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'null_session',
                'severity': 6.0,
                'confidence': 0.95,
                'name': 'SMB Null Session Allowed',
                'location': 'SMB Service',
                'evidence': 'Null session enumeration successful',
                'exploitable': True
            })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': services,
            'raw_output': stdout
        }
        
    def _parse_wpscan(self, stdout: str, stderr: str) -> Dict:
        """Parse wpscan WordPress scanner output"""
        vulnerabilities = []
            
        # Look for vulnerabilities
        vuln_pattern = r'\[!\]\s*Title:\s*(.+)'
        for match in re.finditer(vuln_pattern, stdout):
            title = match.group(1)
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'wordpress_vulnerability',
                'severity': 7.0,
                'confidence': 0.85,
                'name': title,
                'location': 'WordPress',
                'evidence': match.group(0),
                'exploitable': True
            })
            
        # Look for outdated versions
        if 'outdated' in stdout.lower() or 'old version' in stdout.lower():
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'outdated_software',
                'severity': 5.0,
                'confidence': 0.9,
                'name': 'Outdated WordPress Version',
                'location': 'WordPress Core',
                'evidence': 'WordPress version is outdated',
                'exploitable': True
            })
            
        # Look for users
        user_pattern = r'User\(s\) Identified:[\s\S]*?\[i\]\s*(\w+)'
        for match in re.finditer(user_pattern, stdout):
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'user_enumeration',
                'severity': 3.0,
                'confidence': 0.9,
                'name': f'WordPress User Found: {match.group(1)}',
                'location': 'WordPress',
                'evidence': match.group(0),
                'exploitable': False
            })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }
        
    def _parse_amass(self, stdout: str, stderr: str) -> Dict:
        """Parse amass subdomain enumeration output"""
        vulnerabilities = []
        hosts = []
            
        for line in stdout.split('\n'):
            line = line.strip()
            if line and '.' in line:
                # Check if it looks like a hostname
                if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$', line):
                    hosts.append(line)
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'type': 'subdomain',
                        'severity': 3.0,
                        'confidence': 0.9,
                        'name': f'Subdomain: {line}',
                        'location': line,
                        'evidence': line,
                        'exploitable': False
                    })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': hosts,
            'services': [],
            'raw_output': stdout
        }
        
    def _parse_xsser(self, stdout: str, stderr: str) -> Dict:
        """Parse xsser XSS scanner output"""
        vulnerabilities = []
            
        # Look for XSS findings
        if 'XSS FOUND' in stdout.upper() or 'VULNERABLE' in stdout.upper():
            # Extract URL if possible
            url_match = re.search(r'(https?://[^\s]+)', stdout)
            location = url_match.group(1) if url_match else 'Unknown'
                
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'type': 'xss',
                'severity': 7.0,
                'confidence': 0.85,
                'name': 'Cross-Site Scripting (XSS) Vulnerability',
                'location': location,
                'evidence': stdout[:500],
                'exploitable': True
            })
            
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': [],
            'services': [],
            'raw_output': stdout
        }