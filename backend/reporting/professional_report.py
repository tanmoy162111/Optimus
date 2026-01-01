"""
Professional Penetration Test Report Generator

Generates structured, actionable reports with:
- Clear vulnerability descriptions
- Step-by-step reproduction instructions
- Exploitation proof/evidence
- Remediation guidance
- Risk assessment with business impact
- CWE/OWASP mapping
"""

import json
import hashlib
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


# CWE Mapping for common vulnerability types
CWE_MAPPING = {
    'sql_injection': {'id': 'CWE-89', 'name': 'SQL Injection'},
    'sqli': {'id': 'CWE-89', 'name': 'SQL Injection'},
    'sql': {'id': 'CWE-89', 'name': 'SQL Injection'},
    'xss': {'id': 'CWE-79', 'name': 'Cross-site Scripting (XSS)'},
    'cross_site_scripting': {'id': 'CWE-79', 'name': 'Cross-site Scripting (XSS)'},
    'reflected': {'id': 'CWE-79', 'name': 'Reflected XSS'},
    'command_injection': {'id': 'CWE-78', 'name': 'OS Command Injection'},
    'rce': {'id': 'CWE-94', 'name': 'Code Injection'},
    'lfi': {'id': 'CWE-98', 'name': 'Local File Inclusion'},
    'rfi': {'id': 'CWE-98', 'name': 'Remote File Inclusion'},
    'path_traversal': {'id': 'CWE-22', 'name': 'Path Traversal'},
    'directory_traversal': {'id': 'CWE-22', 'name': 'Path Traversal'},
    'ssrf': {'id': 'CWE-918', 'name': 'Server-Side Request Forgery'},
    'xxe': {'id': 'CWE-611', 'name': 'XML External Entity'},
    'idor': {'id': 'CWE-639', 'name': 'Insecure Direct Object Reference'},
    'broken_auth': {'id': 'CWE-287', 'name': 'Improper Authentication'},
    'session': {'id': 'CWE-384', 'name': 'Session Fixation'},
    'csrf': {'id': 'CWE-352', 'name': 'Cross-Site Request Forgery'},
    'open_redirect': {'id': 'CWE-601', 'name': 'Open Redirect'},
    'file_upload': {'id': 'CWE-434', 'name': 'Unrestricted File Upload'},
    'deserialization': {'id': 'CWE-502', 'name': 'Insecure Deserialization'},
    'information_disclosure': {'id': 'CWE-200', 'name': 'Information Exposure'},
    'sensitive_data': {'id': 'CWE-200', 'name': 'Information Exposure'},
    'default': {'id': 'CWE-693', 'name': 'Protection Mechanism Failure'},
}

# OWASP Top 10 2021 Mapping
OWASP_MAPPING = {
    'sql_injection': 'A03:2021 - Injection',
    'sqli': 'A03:2021 - Injection',
    'sql': 'A03:2021 - Injection',
    'command_injection': 'A03:2021 - Injection',
    'xss': 'A03:2021 - Injection',
    'xxe': 'A03:2021 - Injection',
    'ldap_injection': 'A03:2021 - Injection',
    'broken_auth': 'A07:2021 - Identification and Authentication Failures',
    'session': 'A07:2021 - Identification and Authentication Failures',
    'sensitive_data': 'A02:2021 - Cryptographic Failures',
    'information_disclosure': 'A01:2021 - Broken Access Control',
    'idor': 'A01:2021 - Broken Access Control',
    'path_traversal': 'A01:2021 - Broken Access Control',
    'ssrf': 'A10:2021 - Server-Side Request Forgery',
    'security_misconfiguration': 'A05:2021 - Security Misconfiguration',
    'outdated': 'A06:2021 - Vulnerable and Outdated Components',
    'default': 'A03:2021 - Injection',
}


class ProfessionalReportGenerator:
    """
    Generates professional penetration testing reports.
    """
    
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path('reports')
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, scan_state: Dict) -> Dict[str, Any]:
        """
        Generate comprehensive penetration test report.
        """
        report = {
            'report_info': self._generate_report_info(scan_state),
            'executive_summary': self._generate_executive_summary(scan_state),
            'scope': self._generate_scope(scan_state),
            'methodology': self._generate_methodology(scan_state),
            'findings_summary': self._generate_findings_summary(scan_state),
            'detailed_findings': self._generate_detailed_findings(scan_state),
            'exploitation_results': self._generate_exploitation_results(scan_state),
            'risk_assessment': self._generate_risk_assessment(scan_state),
            'recommendations': self._generate_recommendations(scan_state),
            'appendix': self._generate_appendix(scan_state),
        }
        
        return report
    
    def _generate_report_info(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate report metadata."""
        scan_id = scan_state.get('scan_id', 'unknown')
        
        return {
            'title': f"Penetration Test Report - {scan_state.get('target', 'Unknown Target')}",
            'report_id': hashlib.md5(f"{scan_id}{datetime.now().isoformat()}".encode()).hexdigest()[:12].upper(),
            'classification': 'CONFIDENTIAL',
            'version': '1.0',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'target': scan_state.get('target'),
            'scan_id': scan_id,
            'duration': f"{scan_state.get('time_elapsed', 0):.1f} seconds",
            'tools_used': len(scan_state.get('tools_executed', [])),
            'generated_by': 'Optimus Autonomous Penetration Testing Platform',
        }
    
    def _generate_executive_summary(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate executive summary for non-technical stakeholders."""
        findings = scan_state.get('findings', [])
        
        # Count by severity
        critical = len([f for f in findings if f.get('severity', 0) >= 9.0])
        high = len([f for f in findings if 7.0 <= f.get('severity', 0) < 9.0])
        medium = len([f for f in findings if 4.0 <= f.get('severity', 0) < 7.0])
        low = len([f for f in findings if 1.0 <= f.get('severity', 0) < 4.0])
        info = len([f for f in findings if f.get('severity', 0) < 1.0])
        
        # Calculate risk score
        risk_score = (critical * 40) + (high * 20) + (medium * 5) + (low * 1)
        
        if risk_score >= 100:
            overall_risk = 'CRITICAL'
            risk_color = '#dc3545'
        elif risk_score >= 50:
            overall_risk = 'HIGH'
            risk_color = '#fd7e14'
        elif risk_score >= 20:
            overall_risk = 'MEDIUM'
            risk_color = '#ffc107'
        else:
            overall_risk = 'LOW'
            risk_color = '#28a745'
        
        # Generate narrative
        target = scan_state.get('target', 'the target')
        
        if critical > 0:
            narrative = f"""
The security assessment of {target} revealed {critical} CRITICAL vulnerabilities that pose 
immediate risk to the organization. These vulnerabilities could allow attackers to gain 
unauthorized access, steal sensitive data, or compromise system integrity. Immediate 
remediation is strongly recommended.
"""
        elif high > 0:
            narrative = f"""
The security assessment of {target} identified {high} HIGH severity vulnerabilities that 
require prompt attention. While not immediately exploitable in all cases, these issues 
could be leveraged by attackers to gain unauthorized access or escalate privileges.
"""
        elif medium > 0:
            narrative = f"""
The security assessment of {target} found {medium} MEDIUM severity issues. While these 
do not pose immediate critical risk, they should be addressed in the regular security 
maintenance cycle to maintain a strong security posture.
"""
        else:
            narrative = f"""
The security assessment of {target} found {low + info} low severity or informational 
findings. The target demonstrates a reasonable security posture, though minor improvements 
are recommended.
"""
        
        return {
            'overall_risk': overall_risk,
            'risk_score': risk_score,
            'risk_color': risk_color,
            'total_findings': len(findings),
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low,
            'info_count': info,
            'narrative': narrative.strip(),
            'key_findings': self._get_key_findings(findings),
            'immediate_actions': self._get_immediate_actions(findings),
        }
    
    def _get_key_findings(self, findings: List[Dict]) -> List[str]:
        """Extract key findings for executive summary."""
        key = []
        
        # Get top 5 by severity
        sorted_findings = sorted(findings, key=lambda x: x.get('severity', 0), reverse=True)
        
        for finding in sorted_findings[:5]:
            severity = finding.get('severity', 0)
            sev_label = self._severity_to_label(severity)
            name = finding.get('name', finding.get('type', 'Unknown'))
            location = finding.get('location', finding.get('url', 'Unknown location'))
            
            # Truncate location if too long
            if len(location) > 60:
                location = location[:57] + '...'
            
            key.append(f"[{sev_label}] {name} at {location}")
        
        return key
    
    def _get_immediate_actions(self, findings: List[Dict]) -> List[str]:
        """Generate immediate action items."""
        actions = []
        
        critical_high = [f for f in findings if f.get('severity', 0) >= 7.0]
        
        if not critical_high:
            return ["Continue regular security monitoring", "Address medium/low findings in next maintenance window"]
        
        vuln_types = set()
        for f in critical_high:
            vuln_types.add(f.get('type', 'unknown').lower())
        
        action_map = {
            'sql': "Implement parameterized queries and input validation for all database operations",
            'xss': "Implement output encoding and Content Security Policy headers",
            'command': "Sanitize all user input used in system commands",
            'rce': "Isolate affected systems and patch immediately",
            'auth': "Review and strengthen authentication mechanisms",
            'session': "Implement secure session management practices",
            'file': "Restrict file system access and implement proper access controls",
            'ssrf': "Implement URL validation and restrict outbound connections",
        }
        
        for vtype in vuln_types:
            for key, action in action_map.items():
                if key in vtype:
                    actions.append(action)
                    break
        
        if not actions:
            actions.append("Review and patch all critical/high severity findings immediately")
        
        return list(set(actions))[:5]  # Dedupe and limit
    
    def _generate_scope(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate scope section."""
        return {
            'target': scan_state.get('target'),
            'scan_type': scan_state.get('config', {}).get('scan_type', 'Full Scan'),
            'phases_executed': [
                'Reconnaissance',
                'Scanning', 
                'Exploitation' if scan_state.get('exploits_attempted') else 'Exploitation (Limited)',
                'Post-Exploitation' if scan_state.get('sessions_obtained') else 'Post-Exploitation (Skipped)',
            ],
            'tools_count': len(scan_state.get('tools_executed', [])),
            'duration': f"{scan_state.get('time_elapsed', 0):.0f} seconds",
            'limitations': [
                "Automated testing may not identify all vulnerabilities",
                "Some tests limited by scope/authorization",
                "Rate limiting may affect completeness",
            ]
        }
    
    def _generate_methodology(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate methodology section."""
        return {
            'framework': 'OWASP Testing Guide v4.2 / PTES',
            'phases': [
                {
                    'name': 'Reconnaissance',
                    'description': 'Information gathering and target enumeration',
                    'tools': ['nmap', 'whatweb', 'amass', 'fierce'],
                },
                {
                    'name': 'Scanning',
                    'description': 'Vulnerability scanning and service detection',
                    'tools': ['nikto', 'nuclei', 'gobuster', 'sslscan'],
                },
                {
                    'name': 'Exploitation',
                    'description': 'Attempting to exploit identified vulnerabilities',
                    'tools': ['sqlmap', 'dalfox', 'commix', 'metasploit'],
                },
                {
                    'name': 'Post-Exploitation',
                    'description': 'Privilege escalation and lateral movement',
                    'tools': ['linpeas', 'winpeas', 'mimikatz'],
                },
            ]
        }
    
    def _generate_findings_summary(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate findings summary table."""
        findings = scan_state.get('findings', [])
        
        summary_table = []
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 0)
            summary_table.append({
                'id': f"VULN-{i:03d}",
                'title': finding.get('name', finding.get('type', 'Unknown')),
                'severity': self._severity_to_label(severity),
                'severity_score': severity,
                'location': self._truncate(finding.get('location', finding.get('url', 'N/A')), 50),
                'status': 'Confirmed' if finding.get('exploitable') else 'Potential',
            })
        
        # Sort by severity
        summary_table.sort(key=lambda x: x['severity_score'], reverse=True)
        
        return {
            'table': summary_table,
            'total': len(findings),
        }
    
    def _generate_detailed_findings(self, scan_state: Dict) -> List[Dict[str, Any]]:
        """Generate detailed findings with reproduction steps."""
        findings = scan_state.get('findings', [])
        detailed = []
        
        for i, finding in enumerate(findings, 1):
            detailed.append(self._create_detailed_finding(finding, i, scan_state))
        
        # Sort by severity
        detailed.sort(key=lambda x: x['severity_score'], reverse=True)
        
        return detailed
    
    def _create_detailed_finding(self, finding: Dict, index: int, scan_state: Dict) -> Dict[str, Any]:
        """Create detailed finding entry."""
        vuln_type = finding.get('type', 'unknown').lower()
        severity = finding.get('severity', 0)
        
        # Get CWE mapping
        cwe = CWE_MAPPING.get(vuln_type, CWE_MAPPING['default'])
        
        # Get OWASP mapping
        owasp = OWASP_MAPPING.get(vuln_type, OWASP_MAPPING['default'])
        
        # Generate reproduction steps
        repro_steps = self._generate_reproduction_steps(finding, scan_state)
        
        # Generate remediation
        remediation = self._generate_remediation(finding)
        
        return {
            'id': f"VULN-{index:03d}",
            'title': finding.get('name', finding.get('type', 'Unknown Vulnerability')),
            'severity': self._severity_to_label(severity),
            'severity_score': severity,
            'cvss_score': severity,
            'cwe_id': cwe['id'],
            'cwe_name': cwe['name'],
            'owasp_category': owasp,
            
            'description': self._generate_description(finding),
            'location': finding.get('location', finding.get('url', 'Unknown')),
            'parameter': finding.get('parameter', finding.get('param', 'N/A')),
            'method': finding.get('method', 'GET'),
            
            'evidence': finding.get('evidence', 'No evidence captured'),
            'proof_of_concept': repro_steps,
            
            'impact': self._generate_impact(finding),
            'remediation': remediation,
            
            'references': self._get_references(vuln_type),
            'source_tool': finding.get('tool', finding.get('source_tool', 'Unknown')),
            'discovered_at': finding.get('timestamp', datetime.now().isoformat()),
        }
    
    def _generate_description(self, finding: Dict) -> str:
        """Generate vulnerability description."""
        vuln_type = finding.get('type', 'unknown').lower()
        location = finding.get('location', finding.get('url', 'the target'))
        
        descriptions = {
            'sql': f"A SQL Injection vulnerability was identified at {location}. This vulnerability allows an attacker to inject malicious SQL queries, potentially leading to unauthorized data access, modification, or deletion.",
            'xss': f"A Cross-Site Scripting (XSS) vulnerability was found at {location}. This allows attackers to inject malicious scripts that execute in victims' browsers, potentially stealing session cookies or performing actions on behalf of users.",
            'command': f"A Command Injection vulnerability was discovered at {location}. This allows attackers to execute arbitrary system commands on the server, potentially leading to complete system compromise.",
            'rce': f"A Remote Code Execution vulnerability was identified at {location}. This critical vulnerability allows attackers to execute arbitrary code on the server.",
            'ssrf': f"A Server-Side Request Forgery (SSRF) vulnerability was found at {location}. This allows attackers to make requests from the server to internal resources.",
            'xxe': f"An XML External Entity (XXE) vulnerability was identified at {location}. This can be exploited to read local files or perform SSRF attacks.",
            'lfi': f"A Local File Inclusion vulnerability was found at {location}. This allows attackers to read arbitrary files from the server.",
            'idor': f"An Insecure Direct Object Reference was identified at {location}. This allows unauthorized access to resources belonging to other users.",
        }
        
        for key, desc in descriptions.items():
            if key in vuln_type:
                return desc
        
        return f"A security vulnerability ({finding.get('type', 'unknown')}) was identified at {location}. {finding.get('evidence', '')}"
    
    def _generate_reproduction_steps(self, finding: Dict, scan_state: Dict) -> List[str]:
        """Generate step-by-step reproduction instructions."""
        vuln_type = finding.get('type', '').lower()
        location = finding.get('location', finding.get('url', scan_state.get('target', 'TARGET')))
        param = finding.get('parameter', finding.get('param', ''))
        evidence = finding.get('evidence', '')
        
        steps = []
        
        # Step 1: Always start with navigation
        steps.append(f"1. Navigate to: {location}")
        
        # Step 2: Specific to vulnerability type
        if 'sql' in vuln_type:
            if param:
                steps.append(f"2. Locate the '{param}' parameter")
                steps.append(f"3. Inject SQL payload: ' OR '1'='1")
                steps.append(f"4. Observe the response for SQL error messages or unexpected data")
            else:
                steps.append("2. Identify input fields or parameters")
                steps.append("3. Inject SQL payload: ' OR '1'='1' --")
                steps.append("4. Check for SQL errors or authentication bypass")
            steps.append(f"5. Verify with SQLMap: sqlmap -u '{location}' --batch --dbs")
        
        elif 'xss' in vuln_type:
            payload = evidence if '<script>' in evidence else '<script>alert(1)</script>'
            steps.append(f"2. Input the following payload: {payload}")
            steps.append("3. Submit the form or request")
            steps.append("4. Observe if the script executes (alert box appears)")
            steps.append("5. Check if payload is reflected in response without encoding")
        
        elif 'command' in vuln_type or 'rce' in vuln_type:
            steps.append("2. Identify the vulnerable parameter")
            steps.append("3. Inject command: ; id")
            steps.append("4. Check response for command output (uid, gid)")
            steps.append("5. Verify with: ; cat /etc/passwd")
        
        elif 'lfi' in vuln_type or 'path' in vuln_type:
            steps.append("2. Modify file path parameter")
            steps.append("3. Inject: ../../../etc/passwd")
            steps.append("4. Check if file contents are displayed")
            steps.append("5. Try: ....//....//....//etc/passwd (filter bypass)")
        
        elif 'ssrf' in vuln_type:
            steps.append("2. Identify URL/endpoint parameter")
            steps.append("3. Replace with: http://127.0.0.1:80")
            steps.append("4. Check for internal service responses")
            steps.append("5. Try: http://169.254.169.254/latest/meta-data/ (AWS)")
        
        else:
            # Generic steps
            steps.append("2. Identify the vulnerable component")
            steps.append("3. Send the following request:")
            if evidence:
                steps.append(f"   {evidence[:200]}")
            steps.append("4. Observe the application response")
            steps.append("5. Verify the vulnerability is exploitable")
        
        # Add evidence if available
        if evidence and len(evidence) > 10:
            steps.append(f"\nEvidence from scan:\n{evidence[:500]}")
        
        return steps
    
    def _generate_impact(self, finding: Dict) -> Dict[str, Any]:
        """Generate impact assessment."""
        severity = finding.get('severity', 0)
        vuln_type = finding.get('type', '').lower()
        
        # CIA impact
        if severity >= 9.0:
            cia = {'confidentiality': 'HIGH', 'integrity': 'HIGH', 'availability': 'HIGH'}
        elif severity >= 7.0:
            cia = {'confidentiality': 'HIGH', 'integrity': 'MEDIUM', 'availability': 'LOW'}
        elif severity >= 4.0:
            cia = {'confidentiality': 'MEDIUM', 'integrity': 'LOW', 'availability': 'LOW'}
        else:
            cia = {'confidentiality': 'LOW', 'integrity': 'LOW', 'availability': 'NONE'}
        
        # Business impact
        business_impacts = {
            'sql': "Database breach, data theft, regulatory fines",
            'xss': "Session hijacking, phishing, reputation damage",
            'command': "Complete system compromise, data breach, service disruption",
            'rce': "Full server takeover, lateral movement, ransomware",
            'auth': "Unauthorized access, account takeover, data breach",
            'ssrf': "Internal network access, cloud metadata exposure",
        }
        
        business = "Potential security breach and data exposure"
        for key, impact in business_impacts.items():
            if key in vuln_type:
                business = impact
                break
        
        return {
            'cia_impact': cia,
            'business_impact': business,
            'exploitability': 'High' if finding.get('exploitable') else 'Medium',
        }
    
    def _generate_remediation(self, finding: Dict) -> Dict[str, Any]:
        """Generate remediation guidance."""
        vuln_type = finding.get('type', '').lower()
        
        remediations = {
            'sql': {
                'short_term': 'Implement input validation and use parameterized queries',
                'long_term': 'Use ORM frameworks, implement WAF rules, conduct code review',
                'code_example': '''
# Instead of:
query = f"SELECT * FROM users WHERE id = {user_input}"

# Use parameterized queries:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
''',
            },
            'xss': {
                'short_term': 'Encode all user output and implement CSP headers',
                'long_term': 'Use templating engines with auto-escaping, implement strict CSP',
                'code_example': '''
# Encode output:
from html import escape
safe_output = escape(user_input)

# Add CSP header:
Content-Security-Policy: default-src 'self'; script-src 'self'
''',
            },
            'command': {
                'short_term': 'Sanitize user input, avoid system() calls',
                'long_term': 'Use language-specific APIs instead of shell commands',
                'code_example': '''
# Instead of:
os.system(f"ping {user_input}")

# Use subprocess with shell=False:
subprocess.run(["ping", "-c", "1", validated_ip], shell=False)
''',
            },
            'lfi': {
                'short_term': 'Validate file paths, use whitelist of allowed files',
                'long_term': 'Implement proper access controls, avoid user-controlled paths',
                'code_example': '''
# Validate against whitelist:
allowed_files = ['page1.html', 'page2.html']
if requested_file not in allowed_files:
    return "Access denied"
''',
            },
        }
        
        for key, remediation in remediations.items():
            if key in vuln_type:
                return remediation
        
        return {
            'short_term': 'Apply input validation and output encoding',
            'long_term': 'Conduct security code review and implement defense in depth',
            'code_example': '# Consult OWASP guidelines for specific remediation',
        }
    
    def _get_references(self, vuln_type: str) -> List[str]:
        """Get reference URLs for vulnerability type."""
        refs = {
            'sql': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            ],
            'xss': [
                'https://owasp.org/www-community/attacks/xss/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
            ],
            'command': [
                'https://owasp.org/www-community/attacks/Command_Injection',
                'https://cwe.mitre.org/data/definitions/78.html',
            ],
            'default': [
                'https://owasp.org/www-project-web-security-testing-guide/',
                'https://cwe.mitre.org/',
            ],
        }
        
        for key, ref_list in refs.items():
            if key in vuln_type:
                return ref_list
        
        return refs['default']
    
    def _generate_exploitation_results(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate exploitation results section."""
        exploits = scan_state.get('exploits_attempted', [])
        sessions = scan_state.get('sessions_obtained', [])
        credentials = scan_state.get('credentials_found', [])
        
        return {
            'exploits_attempted': len(exploits),
            'sessions_obtained': len(sessions),
            'credentials_found': len(credentials),
            'details': {
                'exploits': [
                    {
                        'target': e.get('finding', {}).get('type', 'Unknown'),
                        'timestamp': e.get('timestamp', ''),
                        'success': bool(e.get('result', {}).get('shell_obtained')),
                    }
                    for e in exploits[:10]
                ],
                'sessions': sessions[:5],
                'credentials': ['[REDACTED]' for _ in credentials],  # Don't expose creds in report
            }
        }
    
    def _generate_risk_assessment(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate risk assessment matrix."""
        findings = scan_state.get('findings', [])
        
        # Calculate risk by category
        categories = {}
        for finding in findings:
            vuln_type = finding.get('type', 'other').lower()
            severity = finding.get('severity', 0)
            
            # Categorize
            if 'sql' in vuln_type:
                cat = 'Injection'
            elif 'xss' in vuln_type:
                cat = 'XSS'
            elif 'auth' in vuln_type or 'session' in vuln_type:
                cat = 'Authentication'
            elif 'file' in vuln_type or 'path' in vuln_type:
                cat = 'File Access'
            else:
                cat = 'Other'
            
            if cat not in categories:
                categories[cat] = {'count': 0, 'max_severity': 0}
            categories[cat]['count'] += 1
            categories[cat]['max_severity'] = max(categories[cat]['max_severity'], severity)
        
        return {
            'risk_by_category': categories,
            'attack_surface': 'High' if len(findings) > 10 else 'Medium' if len(findings) > 3 else 'Low',
            'data_exposure_risk': any(f.get('severity', 0) >= 7 for f in findings),
        }
    
    def _generate_recommendations(self, scan_state: Dict) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations."""
        findings = scan_state.get('findings', [])
        recommendations = []
        
        # Group by type and severity
        high_sev = [f for f in findings if f.get('severity', 0) >= 7.0]
        med_sev = [f for f in findings if 4.0 <= f.get('severity', 0) < 7.0]
        
        if high_sev:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'title': 'Address Critical/High Severity Vulnerabilities',
                'description': f"Remediate {len(high_sev)} critical/high severity issues immediately",
                'affected': [f.get('type', 'Unknown') for f in high_sev[:5]],
            })
        
        recommendations.append({
            'priority': 'SHORT-TERM',
            'title': 'Implement Security Headers',
            'description': 'Add security headers: CSP, X-Frame-Options, X-Content-Type-Options',
        })
        
        recommendations.append({
            'priority': 'LONG-TERM',
            'title': 'Security Development Lifecycle',
            'description': 'Implement secure coding practices and regular security testing',
        })
        
        return recommendations
    
    def _generate_appendix(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate appendix with technical details."""
        return {
            'tools_used': scan_state.get('tools_executed', []),
            'scan_duration': f"{scan_state.get('time_elapsed', 0):.0f} seconds",
            'raw_tool_outputs': '[Available in detailed scan logs]',
        }
    
    def _severity_to_label(self, score: float) -> str:
        """Convert severity score to label."""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score >= 1.0:
            return 'LOW'
        else:
            return 'INFO'
    
    def _truncate(self, text: str, length: int) -> str:
        """Truncate text to length."""
        if len(text) <= length:
            return text
        return text[:length-3] + '...'
    
    def save_report(self, report: Dict, format: str = 'json') -> str:
        """Save report to file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format == 'json':
            filepath = self.output_dir / f"pentest_report_{timestamp}.json"
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        return str(filepath)


# Factory function
def get_professional_report_generator(output_dir: str = None) -> ProfessionalReportGenerator:
    """Get report generator instance."""
    return ProfessionalReportGenerator(output_dir)
