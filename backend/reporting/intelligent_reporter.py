"""
Intelligent Report Generator
Uses LLM for executive summaries and prioritized remediation
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
import json

logger = logging.getLogger(__name__)


@dataclass
class RemediationItem:
    """Prioritized remediation item"""
    priority: str  # P1 (Critical), P2 (High), P3 (Medium), P4 (Low)
    title: str
    description: str
    affected_assets: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    effort: str = "Medium"  # Low/Medium/High
    impact: str = "High"    # Low/Medium/High
    recommended_action: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class IntelligentReport:
    """Comprehensive penetration test report"""
    # Metadata
    report_id: str
    target: str
    scan_id: str
    generated_at: str
    
    # Executive Summary (LLM-generated)
    executive_summary: str
    key_findings: List[str]
    risk_rating: str
    risk_score: float
    
    # Statistics
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    # Prioritized Remediation
    remediation_plan: List[RemediationItem] = field(default_factory=list)
    
    # Detailed Findings
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # Attack Chain Analysis
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    
    # Recommendations
    strategic_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['remediation_plan'] = [
            asdict(r) if isinstance(r, RemediationItem) else r 
            for r in self.remediation_plan
        ]
        return result


class IntelligentReportGenerator:
    """
    LLM-powered report generator.
    
    Features:
    - AI-generated executive summaries
    - Prioritized remediation (P1/P2/P3/P4)
    - Risk scoring with context
    - Attack chain analysis
    """
    
    def __init__(self, ollama_client=None):
        """
        Initialize report generator.
        
        Args:
            ollama_client: Optional OllamaClient for LLM summaries
        """
        self.ollama = ollama_client
        
        # Try to get Ollama client if not provided
        if self.ollama is None:
            try:
                from inference.ollama_client import get_ollama_client
                self.ollama = get_ollama_client()
            except ImportError:
                logger.warning("[IntelligentReporter] Ollama not available")
        
        logger.info("[IntelligentReporter] Initialized")
    
    def generate_report(self, scan_state: Dict[str, Any]) -> IntelligentReport:
        """
        Generate comprehensive report from scan state.
        
        Args:
            scan_state: Complete scan state with findings
            
        Returns:
            IntelligentReport object
        """
        import uuid
        
        findings = scan_state.get('findings', [])
        
        # Count by severity
        severity_counts = self._count_by_severity(findings)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)
        risk_rating = self._get_risk_rating(risk_score)
        
        # Generate prioritized remediation
        remediation_plan = self._generate_remediation_plan(findings)
        
        # Extract key findings
        key_findings = self._extract_key_findings(findings)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            scan_state, findings, severity_counts, risk_score
        )
        
        # Analyze attack chains
        attack_chains = self._analyze_attack_chains(findings, scan_state)
        
        # Generate strategic recommendations
        strategic_recs = self._generate_strategic_recommendations(
            findings, scan_state
        )
        
        return IntelligentReport(
            report_id=str(uuid.uuid4()),
            target=scan_state.get('target', 'Unknown'),
            scan_id=scan_state.get('scan_id', ''),
            generated_at=datetime.now().isoformat(),
            executive_summary=executive_summary,
            key_findings=key_findings,
            risk_rating=risk_rating,
            risk_score=risk_score,
            total_findings=len(findings),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            remediation_plan=remediation_plan,
            findings=findings,
            attack_chains=attack_chains,
            strategic_recommendations=strategic_recs
        )
    
    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for f in findings:
            sev = f.get('severity', 0)
            if isinstance(sev, str):
                sev_map = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2}
                sev = sev_map.get(sev.lower(), 5)
            
            try:
                sev = float(sev)
            except:
                sev = 5.0
            
            if sev >= 9:
                counts['critical'] += 1
            elif sev >= 7:
                counts['high'] += 1
            elif sev >= 4:
                counts['medium'] += 1
            else:
                counts['low'] += 1
        
        return counts
    
    def _calculate_risk_score(self, findings: List[Dict]) -> float:
        """Calculate overall risk score (0-10)"""
        if not findings:
            return 0.0
        
        score = 0.0
        
        for f in findings:
            sev = f.get('severity', 0)
            if isinstance(sev, str):
                sev_map = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2}
                sev = sev_map.get(sev.lower(), 5)
            
            try:
                sev = float(sev)
            except:
                sev = 5.0
            
            # Weight by exploitability
            weight = 1.5 if f.get('exploitable', False) else 1.0
            score += sev * weight
        
        # Normalize (assume max ~100 weighted severity points = 10)
        return min(10.0, score / 10.0)
    
    def _get_risk_rating(self, score: float) -> str:
        """Convert score to rating"""
        if score >= 8:
            return 'Critical'
        elif score >= 6:
            return 'High'
        elif score >= 3:
            return 'Medium'
        return 'Low'
    
    def _generate_remediation_plan(self, findings: List[Dict]) -> List[RemediationItem]:
        """Generate prioritized remediation plan"""
        plan = []
        
        # Group findings by type
        by_type: Dict[str, List[Dict]] = {}
        for f in findings:
            ftype = f.get('type', 'unknown')
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(f)
        
        # Create remediation items
        for ftype, type_findings in by_type.items():
            # Get highest severity in group
            max_sev = max(
                (self._get_numeric_severity(f.get('severity', 0)) for f in type_findings),
                default=0
            )
            
            # Determine priority
            if max_sev >= 9:
                priority = 'P1'
            elif max_sev >= 7:
                priority = 'P2'
            elif max_sev >= 4:
                priority = 'P3'
            else:
                priority = 'P4'
            
            # Create remediation item
            item = RemediationItem(
                priority=priority,
                title=self._get_remediation_title(ftype),
                description=self._get_remediation_description(ftype),
                affected_assets=[f.get('location', '') for f in type_findings][:5],
                cve_ids=[f.get('cve', '') for f in type_findings if f.get('cve')][:5],
                effort=self._estimate_effort(ftype),
                impact=self._estimate_impact(max_sev),
                recommended_action=self._get_recommended_action(ftype),
                references=self._get_remediation_references(ftype)
            )
            plan.append(item)
        
        # Sort by priority
        priority_order = {'P1': 0, 'P2': 1, 'P3': 2, 'P4': 3}
        plan.sort(key=lambda x: priority_order.get(x.priority, 99))
        
        return plan
    
    def _get_numeric_severity(self, sev) -> float:
        """Convert severity to numeric"""
        if isinstance(sev, (int, float)):
            return float(sev)
        if isinstance(sev, str):
            return {'critical': 10, 'high': 8, 'medium': 5, 'low': 2}.get(sev.lower(), 5)
        return 5.0
    
    def _get_remediation_title(self, vuln_type: str) -> str:
        """Get remediation title for vulnerability type"""
        titles = {
            'sql_injection': 'SQL Injection Remediation',
            'xss': 'Cross-Site Scripting (XSS) Remediation',
            'rce': 'Remote Code Execution Remediation',
            'lfi': 'Local File Inclusion Remediation',
            'rfi': 'Remote File Inclusion Remediation',
            'ssrf': 'Server-Side Request Forgery Remediation',
            'command_injection': 'Command Injection Remediation',
            'auth_bypass': 'Authentication Bypass Remediation',
            'misconfiguration': 'Security Misconfiguration Remediation',
            'info_disclosure': 'Information Disclosure Remediation'
        }
        return titles.get(vuln_type, f'{vuln_type.replace("_", " ").title()} Remediation')
    
    def _get_remediation_description(self, vuln_type: str) -> str:
        """Get remediation description"""
        descriptions = {
            'sql_injection': 'Implement parameterized queries and input validation to prevent SQL injection attacks.',
            'xss': 'Implement output encoding, Content Security Policy, and input sanitization.',
            'rce': 'Review and restrict code execution paths, implement sandboxing, update vulnerable components.',
            'lfi': 'Implement strict file path validation and avoid user-controlled file paths.',
            'ssrf': 'Implement URL validation, use allowlists, and restrict outbound connections.',
            'command_injection': 'Use parameterized commands, avoid shell execution, implement input validation.',
            'auth_bypass': 'Review authentication logic, implement proper session management.',
            'misconfiguration': 'Review and harden server configurations according to security best practices.'
        }
        return descriptions.get(vuln_type, 'Review and address the identified security issue.')
    
    def _estimate_effort(self, vuln_type: str) -> str:
        """Estimate remediation effort"""
        high_effort = ['rce', 'auth_bypass', 'command_injection']
        low_effort = ['info_disclosure', 'misconfiguration']
        
        if vuln_type in high_effort:
            return 'High'
        elif vuln_type in low_effort:
            return 'Low'
        return 'Medium'
    
    def _estimate_impact(self, severity: float) -> str:
        """Estimate business impact"""
        if severity >= 9:
            return 'Critical'
        elif severity >= 7:
            return 'High'
        elif severity >= 4:
            return 'Medium'
        return 'Low'
    
    def _get_recommended_action(self, vuln_type: str) -> str:
        """Get recommended action"""
        actions = {
            'sql_injection': 'Use prepared statements with parameterized queries',
            'xss': 'Implement context-aware output encoding',
            'rce': 'Patch vulnerable components and restrict execution privileges',
            'lfi': 'Use allowlist-based file access validation',
            'ssrf': 'Implement URL validation against allowlist',
            'command_injection': 'Replace shell commands with safer alternatives',
            'auth_bypass': 'Implement multi-factor authentication',
            'misconfiguration': 'Apply CIS benchmark configurations'
        }
        return actions.get(vuln_type, 'Review and remediate according to security best practices')
    
    def _get_remediation_references(self, vuln_type: str) -> List[str]:
        """Get OWASP/CWE references"""
        refs = {
            'sql_injection': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cwe.mitre.org/data/definitions/89.html'
            ],
            'xss': [
                'https://owasp.org/www-community/attacks/xss/',
                'https://cwe.mitre.org/data/definitions/79.html'
            ],
            'rce': [
                'https://cwe.mitre.org/data/definitions/94.html'
            ],
            'command_injection': [
                'https://owasp.org/www-community/attacks/Command_Injection',
                'https://cwe.mitre.org/data/definitions/78.html'
            ]
        }
        return refs.get(vuln_type, ['https://owasp.org/www-project-web-security-testing-guide/'])
    
    def _extract_key_findings(self, findings: List[Dict]) -> List[str]:
        """Extract key findings for executive summary"""
        key = []
        
        # Sort by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: self._get_numeric_severity(f.get('severity', 0)),
            reverse=True
        )
        
        # Take top 5 findings
        for f in sorted_findings[:5]:
            name = f.get('name', f.get('type', 'Unknown'))
            sev = f.get('severity', 'Unknown')
            location = f.get('location', 'Unknown')
            
            key.append(f"{name} (Severity: {sev}) at {location}")
        
        return key
    
    def _generate_executive_summary(
        self,
        scan_state: Dict,
        findings: List[Dict],
        counts: Dict[str, int],
        risk_score: float
    ) -> str:
        """Generate executive summary using LLM or template"""
        
        # Try LLM generation
        if self.ollama and self.ollama.is_available():
            try:
                return self._generate_llm_summary(scan_state, findings, counts, risk_score)
            except Exception as e:
                logger.warning(f"[IntelligentReporter] LLM summary failed: {e}")
        
        # Fallback to template
        return self._generate_template_summary(scan_state, findings, counts, risk_score)
    
    def _generate_llm_summary(
        self,
        scan_state: Dict,
        findings: List[Dict],
        counts: Dict[str, int],
        risk_score: float
    ) -> str:
        """Generate summary using Ollama LLM"""
        
        # Prepare context
        target = scan_state.get('target', 'Unknown')
        total = len(findings)
        
        # Get top findings
        top_findings = sorted(
            findings,
            key=lambda f: self._get_numeric_severity(f.get('severity', 0)),
            reverse=True
        )[:5]
        
        findings_text = "\n".join([
            f"- {f.get('name', f.get('type', 'Unknown'))}: Severity {f.get('severity', 'Unknown')}"
            for f in top_findings
        ])
        
        prompt = f"""Write a professional executive summary for a penetration test report.

Target: {target}
Risk Score: {risk_score:.1f}/10
Total Findings: {total}
Critical: {counts['critical']}, High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']}

Top Findings:
{findings_text}

Write a concise 2-3 paragraph executive summary suitable for C-level executives. Focus on:
1. Overall security posture assessment
2. Most critical risks identified
3. High-level recommended actions

Do not use bullet points. Write in professional prose."""

        system = "You are a senior penetration tester writing an executive summary for a security assessment report."
        
        response = self.ollama.generate(prompt, system)
        
        if response:
            return response.strip()
        
        return self._generate_template_summary(scan_state, findings, counts, risk_score)
    
    def _generate_template_summary(
        self,
        scan_state: Dict,
        findings: List[Dict],
        counts: Dict[str, int],
        risk_score: float
    ) -> str:
        """Generate template-based summary"""
        target = scan_state.get('target', 'Unknown')
        total = len(findings)
        risk_rating = self._get_risk_rating(risk_score)
        
        summary = f"""A comprehensive security assessment was conducted against {target}. The assessment identified a total of {total} security findings, including {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, and {counts['low']} low severity issues.

The overall security posture is rated as {risk_rating} with a risk score of {risk_score:.1f}/10. """

        if counts['critical'] > 0:
            summary += f"Immediate attention is required to address the {counts['critical']} critical vulnerabilities that pose significant risk to the organization. "
        
        if counts['high'] > 0:
            summary += f"Additionally, {counts['high']} high-severity issues should be prioritized for remediation within the next 30 days. "
        
        summary += "\n\nIt is recommended that the organization implement the remediation plan outlined in this report, focusing on the P1 (critical) and P2 (high priority) items first."
        
        return summary
    
    def _analyze_attack_chains(
        self,
        findings: List[Dict],
        scan_state: Dict
    ) -> List[Dict[str, Any]]:
        """Analyze potential attack chains"""
        chains = []
        
        # Look for chain patterns
        has_rce = any(f.get('type') in ['rce', 'command_injection'] for f in findings)
        has_sqli = any(f.get('type') == 'sql_injection' for f in findings)
        has_ssrf = any(f.get('type') == 'ssrf' for f in findings)
        has_lfi = any(f.get('type') == 'lfi' for f in findings)
        
        if has_sqli and has_rce:
            chains.append({
                'name': 'SQL Injection to RCE',
                'description': 'SQL injection could be chained with file write or command execution for full system compromise',
                'severity': 'Critical',
                'likelihood': 'High'
            })
        
        if has_ssrf and has_lfi:
            chains.append({
                'name': 'SSRF to Internal Access',
                'description': 'SSRF combined with LFI could provide access to internal systems and sensitive files',
                'severity': 'High',
                'likelihood': 'Medium'
            })
        
        return chains
    
    def _generate_strategic_recommendations(
        self,
        findings: List[Dict],
        scan_state: Dict
    ) -> List[str]:
        """Generate strategic security recommendations"""
        recs = []
        
        counts = self._count_by_severity(findings)
        
        if counts['critical'] > 0:
            recs.append("Establish an emergency patching process for critical vulnerabilities")
        
        if counts['high'] > 3:
            recs.append("Implement a vulnerability management program with regular scanning")
        
        # Check for patterns
        vuln_types = set(f.get('type', '') for f in findings)
        
        if 'sql_injection' in vuln_types or 'xss' in vuln_types:
            recs.append("Implement secure coding training for development teams")
            recs.append("Deploy Web Application Firewall (WAF) for defense in depth")
        
        if 'misconfiguration' in vuln_types:
            recs.append("Establish configuration baselines and automated compliance checking")
        
        if len(findings) > 20:
            recs.append("Consider engaging a dedicated security team for continuous monitoring")
        
        if not recs:
            recs.append("Maintain current security practices and conduct regular assessments")
        
        return recs


# Factory function
def get_intelligent_reporter() -> IntelligentReportGenerator:
    """Get configured report generator"""
    return IntelligentReportGenerator()
