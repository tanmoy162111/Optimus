"""
Comprehensive Vulnerability Report Generator
Generates detailed, actionable reports with reproduction steps
"""

import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class VulnerabilityReportGenerator:
    """
    Generates professional penetration testing reports
    """

    def generate_detailed_report(self, scan_state: Dict) -> Dict:
        """
        Generate comprehensive report with:
        - Executive summary
        - Detailed vulnerability analysis
        - Step-by-step reproduction
        - Remediation guidance
        - Risk assessment
        """
        report = {
            'metadata': self._generate_metadata(scan_state),
            'executive_summary': self._generate_executive_summary(scan_state),
            'vulnerabilities': [],
            'attack_chain': self._reconstruct_attack_chain(scan_state),
            'recommendations': self._generate_recommendations(scan_state),
        }
        
        # Generate detailed vulnerability entries
        for finding in scan_state['findings']:
            vuln_entry = self._generate_vulnerability_entry(finding)
            report['vulnerabilities'].append(vuln_entry)
            
        return report

    def _generate_metadata(self, scan_state: Dict) -> Dict[str, Any]:
        """
        Generate report metadata
        """
        return {
            'report_id': str(uuid.uuid4()),
            'scan_id': scan_state.get('scan_id'),
            'target': scan_state.get('target'),
            'generated_at': datetime.now().isoformat(),
            'tools_used': scan_state.get('tools_executed', []),
            'duration_seconds': scan_state.get('time_elapsed', 0),
            'coverage_percentage': scan_state.get('coverage', 0)
        }

    def _generate_executive_summary(self, scan_state: Dict) -> Dict[str, Any]:
        """
        Generate executive summary
        """
        findings = scan_state.get('findings', [])
        
        # Count vulnerabilities by severity
        critical_count = len([f for f in findings if f.get('severity', 0) >= 9.0])
        high_count = len([f for f in findings if 7.0 <= f.get('severity', 0) < 9.0])
        medium_count = len([f for f in findings if 4.0 <= f.get('severity', 0) < 7.0])
        low_count = len([f for f in findings if f.get('severity', 0) < 4.0])
        
        total_findings = len(findings)
        
        risk_level = "Low"
        if critical_count > 0 or high_count > 5:
            risk_level = "Critical"
        elif high_count > 0 or medium_count > 10:
            risk_level = "High"
        elif medium_count > 0:
            risk_level = "Medium"
            
        return {
            'risk_level': risk_level,
            'total_findings': total_findings,
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'medium_vulnerabilities': medium_count,
            'low_vulnerabilities': low_count,
            'summary_text': f"Security scan of {scan_state.get('target')} identified {total_findings} vulnerabilities, "
                           f"including {critical_count} critical and {high_count} high severity issues."
        }

    def _generate_vulnerability_entry(self, finding: Dict) -> Dict:
        """
        Create detailed vulnerability entry with reproduction steps
        """
        return {
            'id': finding.get('id', str(uuid.uuid4())),
            'title': finding.get('name', 'Unnamed Vulnerability'),
            'severity': self._calculate_severity_rating(finding),
            'cvss_score': finding.get('severity', 0),
            'cwe_id': self._map_to_cwe(finding),
            'owasp_category': self._map_to_owasp(finding),
            
            # Detailed description
            'description': self._generate_description(finding),
            
            # Step-by-step reproduction
            'reproduction_steps': self._generate_reproduction_steps(finding),
            
            # Technical details
            'technical_details': {
                'location': finding.get('location'),
                'parameter': finding.get('parameter'),
                'method': finding.get('method'),
                'payload': finding.get('evidence'),
                'response': finding.get('response'),
                'request': finding.get('request'),
            },
            
            # Proof of concept
            'poc': self._generate_poc(finding),
            
            # Impact analysis
            'impact': self._analyze_impact(finding),
            
            # Remediation
            'remediation': self._generate_remediation(finding),
            
            # References
            'references': self._get_references(finding),
            
            # Screenshots/evidence
            'evidence': finding.get('screenshots', []),
        }

    def _calculate_severity_rating(self, finding: Dict) -> str:
        """
        Calculate severity rating from CVSS score
        """
        cvss_score = finding.get('severity', 0)
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"

    def _map_to_cwe(self, finding: Dict) -> str:
        """
        Map finding to CWE ID
        """
        vuln_type = finding.get('type', '')
        cwe_mapping = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'command_injection': 'CWE-77',
            'path_traversal': 'CWE-22',
            'idor': 'CWE-639',
            'ssrf': 'CWE-918',
            'xxe': 'CWE-611',
            'deserialization': 'CWE-502',
            'csrf': 'CWE-352',
            'insecure_deserialization': 'CWE-502'
        }
        return cwe_mapping.get(vuln_type, 'CWE-NVD-CWE-Other')

    def _map_to_owasp(self, finding: Dict) -> str:
        """
        Map finding to OWASP category
        """
        vuln_type = finding.get('type', '')
        owasp_mapping = {
            'sql_injection': 'A03:2021-Injection',
            'xss': 'A03:2021-Injection',
            'command_injection': 'A03:2021-Injection',
            'path_traversal': 'A01:2021-Broken Access Control',
            'idor': 'A01:2021-Broken Access Control',
            'ssrf': 'A10:2021-Server-Side Request Forgery',
            'xxe': 'A04:2021-Insecure Design',
            'deserialization': 'A08:2021-Software and Data Integrity Failures',
            'csrf': 'A01:2021-Broken Access Control'
        }
        return owasp_mapping.get(vuln_type, 'A00:2021-Other')

    def _generate_description(self, finding: Dict) -> str:
        """
        Generate detailed description of the vulnerability
        """
        vuln_type = finding.get('type', 'Unknown')
        location = finding.get('location', 'Unknown location')
        
        descriptions = {
            'sql_injection': f"SQL Injection vulnerability detected at {location}. "
                            f"The application is vulnerable to SQL injection attacks, "
                            f"which could allow an attacker to execute arbitrary SQL commands.",
            'xss': f"Cross-Site Scripting (XSS) vulnerability detected at {location}. "
                   f"The application does not properly sanitize user input, "
                   f"allowing malicious scripts to be executed in the victim's browser.",
            'command_injection': f"Command Injection vulnerability detected at {location}. "
                                f"The application executes system commands without proper input validation, "
                                f"potentially allowing attackers to execute arbitrary commands.",
            'path_traversal': f"Path Traversal vulnerability detected at {location}. "
                             f"The application does not properly validate file paths, "
                             f"allowing attackers to access files outside the intended directory.",
        }
        
        return descriptions.get(vuln_type, f"{vuln_type.replace('_', ' ').title()} vulnerability detected.")

    def _generate_reproduction_steps(self, finding: Dict) -> List[str]:
        """
        Generate detailed step-by-step reproduction instructions
        """
        vuln_type = finding.get('type')
        location = finding.get('location', '')
        parameter = finding.get('parameter', '')
        evidence = finding.get('evidence', '')
        
        if vuln_type == 'sql_injection':
            return [
                f"1. Navigate to the vulnerable endpoint: {location}",
                f"2. Identify the vulnerable parameter: {parameter}",
                f"3. Submit the following payload: {evidence}",
                "4. Observe the SQL error in the response indicating successful injection",
                f"5. Use SQLMap to confirm: sqlmap -u '{location}' -p {parameter}",
                f"6. Extract database: sqlmap -u '{location}' --dbs",
            ]
            
        elif vuln_type == 'xss':
            return [
                f"1. Open the target URL: {location}",
                f"2. Locate the input field: {parameter}",
                f"3. Input the XSS payload: {evidence}",
                "4. Submit the form or trigger the injection point",
                "5. Observe JavaScript execution (alert box appears)",
                "6. Verify payload is reflected in page source without sanitization",
            ]
            
        elif vuln_type == 'command_injection':
            return [
                f"1. Navigate to the vulnerable endpoint: {location}",
                f"2. Identify the vulnerable parameter: {parameter}",
                f"3. Submit the following payload: {evidence}",
                "4. Observe command execution output in the response",
                "5. Try to execute system commands like 'whoami' or 'id'",
            ]
            
        # Add cases for other vulnerability types
        return self._generate_generic_steps(finding)

    def _generate_generic_steps(self, finding: Dict) -> List[str]:
        """
        Generate generic reproduction steps
        """
        return [
            "1. Identify the vulnerable component",
            "2. Prepare the exploit payload",
            "3. Execute the exploit",
            "4. Verify the vulnerability exists",
            "5. Document the findings"
        ]

    def _generate_poc(self, finding: Dict) -> Dict[str, Any]:
        """
        Generate proof of concept
        """
        return {
            'request': finding.get('request', ''),
            'response': finding.get('response', ''),
            'payload': finding.get('evidence', ''),
            'screenshot': finding.get('screenshot', '')
        }

    def _analyze_impact(self, finding: Dict) -> Dict[str, str]:
        """
        Analyze impact of the vulnerability
        """
        vuln_type = finding.get('type', 'unknown')
        
        impact_descriptions = {
            'sql_injection': {
                'confidentiality': 'High - Allows unauthorized access to database contents',
                'integrity': 'High - Enables modification or deletion of database records',
                'availability': 'Medium - May cause denial of service through database manipulation'
            },
            'xss': {
                'confidentiality': 'Medium - Can steal session cookies and sensitive user data',
                'integrity': 'Medium - Can manipulate page content and user interactions',
                'availability': 'Low - Generally does not directly impact system availability'
            },
            'command_injection': {
                'confidentiality': 'High - Full system access may be possible',
                'integrity': 'High - Complete system compromise',
                'availability': 'High - System may be rendered unusable'
            }
        }
        
        return impact_descriptions.get(vuln_type, {
            'confidentiality': 'Varies based on vulnerability type',
            'integrity': 'Varies based on vulnerability type',
            'availability': 'Varies based on vulnerability type'
        })

    def _generate_remediation(self, finding: Dict) -> Dict[str, Any]:
        """
        Generate remediation guidance
        """
        vuln_type = finding.get('type', 'unknown')
        
        remediation_guidance = {
            'sql_injection': {
                'immediate': 'Implement parameterized queries or prepared statements',
                'long_term': 'Use ORM frameworks and input validation',
                'code_example': '''
# Example of secure parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
            },
            'xss': {
                'immediate': 'Implement proper input sanitization and output encoding',
                'long_term': 'Use Content Security Policy (CSP) and modern frameworks',
                'code_example': '''
# Example of output encoding
from html import escape
safe_output = escape(user_input)
'''
            },
            'command_injection': {
                'immediate': 'Validate and sanitize all user inputs before command execution',
                'long_term': 'Avoid direct system command execution when possible',
                'code_example': '''
# Example of secure command execution
import subprocess
# Use a whitelist of allowed commands
if command in ALLOWED_COMMANDS:
    subprocess.run([command, arg1, arg2], check=True)
'''
            }
        }
        
        return remediation_guidance.get(vuln_type, {
            'immediate': 'Apply security patches and update dependencies',
            'long_term': 'Implement secure coding practices and regular security reviews',
            'code_example': '# Consult security documentation for specific remediation'
        })

    def _get_references(self, finding: Dict) -> List[Dict[str, str]]:
        """
        Get references for the vulnerability
        """
        vuln_type = finding.get('type', '')
        cwe_id = self._map_to_cwe(finding)
        
        references = [
            {
                'title': 'CWE Entry',
                'url': f'https://cwe.mitre.org/data/definitions/{cwe_id.split("-")[-1]}.html'
            }
        ]
        
        if vuln_type == 'sql_injection':
            references.append({
                'title': 'OWASP SQL Injection Prevention',
                'url': 'https://owasp.org/www-community/attacks/SQL_Injection'
            })
        elif vuln_type == 'xss':
            references.append({
                'title': 'OWASP XSS Prevention',
                'url': 'https://owasp.org/www-community/attacks/xss/'
            })
            
        return references

    def _reconstruct_attack_chain(self, scan_state: Dict) -> List[Dict[str, Any]]:
        """
        Reconstruct the attack chain from findings
        """
        findings = scan_state.get('findings', [])
        
        # Simple attack chain reconstruction
        attack_chain = []
        for i, finding in enumerate(findings):
            attack_chain.append({
                'step': i + 1,
                'finding_id': finding.get('id', ''),
                'vulnerability': finding.get('name', 'Unknown'),
                'type': finding.get('type', ''),
                'severity': self._calculate_severity_rating(finding)
            })
            
        return attack_chain

    def _generate_recommendations(self, scan_state: Dict) -> List[Dict[str, str]]:
        """
        Generate security recommendations
        """
        findings = scan_state.get('findings', [])
        
        # Count vulnerabilities by type
        vuln_types = {}
        for finding in findings:
            vuln_type = finding.get('type', 'unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        recommendations = []
        
        # Generic recommendations
        recommendations.append({
            'priority': 'High',
            'category': 'General Security',
            'description': 'Implement a comprehensive security testing program with regular scans',
            'implementation': 'Schedule automated security scans weekly and before deployments'
        })
        
        recommendations.append({
            'priority': 'High',
            'category': 'Input Validation',
            'description': 'Implement strict input validation for all user-supplied data',
            'implementation': 'Use allowlists for acceptable input and reject all other input'
        })
        
        # Specific recommendations based on findings
        if 'sql_injection' in vuln_types:
            recommendations.append({
                'priority': 'Critical',
                'category': 'SQL Injection',
                'description': f'Fix {vuln_types["sql_injection"]} SQL injection vulnerabilities',
                'implementation': 'Implement parameterized queries and stored procedures'
            })
            
        if 'xss' in vuln_types:
            recommendations.append({
                'priority': 'High',
                'category': 'Cross-Site Scripting',
                'description': f'Fix {vuln_types["xss"]} XSS vulnerabilities',
                'implementation': 'Implement proper output encoding and Content Security Policy'
            })
            
        return recommendations