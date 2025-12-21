"""
Unified Intelligence API
Combines surface web and dark web intelligence with threat assessment
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

from .surface_web_intel import (
    SurfaceWebIntelligence, get_surface_intel,
    VulnerabilityInfo, IntelResult
)
from .dark_web_intel import (
    DarkWebIntelligence, get_dark_web_intel,
    BreachInfo, DarkWebResult
)

logger = logging.getLogger(__name__)


@dataclass
class ThreatAssessment:
    """Comprehensive threat assessment"""
    target: str
    risk_score: float  # 0-10
    risk_level: str    # Critical/High/Medium/Low
    
    # Intelligence summary
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    exploits_available: int = 0
    breaches_found: int = 0
    
    # Detailed findings
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    breaches: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    assessment_time: str = ""
    sources_used: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class UnifiedIntelligence:
    """
    Unified intelligence API combining all sources.
    
    Provides:
    - Combined vulnerability search
    - Threat assessment
    - Remediation recommendations
    """
    
    def __init__(
        self,
        surface_intel: SurfaceWebIntelligence = None,
        dark_web_intel: DarkWebIntelligence = None
    ):
        self.surface = surface_intel or get_surface_intel()
        self.dark_web = dark_web_intel or get_dark_web_intel()
        
        logger.info("[UnifiedIntel] Initialized")
    
    async def search_all(
        self,
        query: str,
        include_dark_web: bool = False
    ) -> Dict[str, Any]:
        """
        Search all intelligence sources.
        
        Args:
            query: Search query (CVE, domain, keyword)
            include_dark_web: Whether to include dark web sources
            
        Returns:
            Combined results from all sources
        """
        results = {
            'query': query,
            'surface_web': None,
            'dark_web': None,
            'total_findings': 0,
            'query_time': 0.0
        }
        
        start_time = asyncio.get_event_loop().time()
        
        # Create tasks
        tasks = [self.surface.search_vulnerabilities(query)]
        
        if include_dark_web:
            # Extract domain for dark web search
            domain = self._extract_domain(query)
            if domain:
                tasks.append(self.dark_web.search_breaches(domain))
        
        # Execute
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process surface results
        if not isinstance(task_results[0], Exception):
            surface_result: IntelResult = task_results[0]
            results['surface_web'] = surface_result.to_dict()
            results['total_findings'] += surface_result.total_results
        
        # Process dark web results
        if include_dark_web and len(task_results) > 1:
            if not isinstance(task_results[1], Exception):
                dark_result: DarkWebResult = task_results[1]
                results['dark_web'] = dark_result.to_dict()
                results['total_findings'] += dark_result.total_results
        
        results['query_time'] = asyncio.get_event_loop().time() - start_time
        return results
    
    async def assess_target(
        self,
        target: str,
        technologies: List[str] = None,
        include_dark_web: bool = False
    ) -> ThreatAssessment:
        """
        Perform comprehensive threat assessment for a target.
        
        Args:
            target: Target domain/IP
            technologies: Known technologies (e.g., ['apache', 'wordpress'])
            include_dark_web: Whether to include dark web intelligence
            
        Returns:
            ThreatAssessment with risk score and recommendations
        """
        assessment = ThreatAssessment(
            target=target,
            risk_score=0.0,
            risk_level='Low',
            assessment_time=datetime.now().isoformat()
        )
        
        technologies = technologies or []
        
        # Gather intelligence
        all_vulns: List[VulnerabilityInfo] = []
        all_breaches: List[BreachInfo] = []
        
        # Search for target
        surface_result = await self.surface.search_vulnerabilities(target)
        all_vulns.extend(surface_result.vulnerabilities)
        assessment.sources_used.append('surface_web')
        
        # Search for each technology
        for tech in technologies[:5]:  # Limit to 5 techs
            tech_result = await self.surface.search_vulnerabilities(tech)
            all_vulns.extend(tech_result.vulnerabilities)
        
        # Dark web search
        if include_dark_web:
            domain = self._extract_domain(target)
            if domain:
                dark_result = await self.dark_web.search_breaches(domain)
                all_breaches.extend(dark_result.breaches)
                assessment.sources_used.append('dark_web')
        
        # Deduplicate vulnerabilities by CVE ID
        seen_cves = set()
        unique_vulns = []
        for vuln in all_vulns:
            if vuln.cve_id not in seen_cves:
                seen_cves.add(vuln.cve_id)
                unique_vulns.append(vuln)
        
        # Count by severity
        for vuln in unique_vulns:
            if vuln.severity >= 9.0:
                assessment.critical_cves += 1
            elif vuln.severity >= 7.0:
                assessment.high_cves += 1
            if vuln.exploits_available:
                assessment.exploits_available += 1
        
        assessment.total_cves = len(unique_vulns)
        assessment.breaches_found = len(all_breaches)
        
        # Calculate risk score
        assessment.risk_score = self._calculate_risk_score(assessment, unique_vulns, all_breaches)
        assessment.risk_level = self._get_risk_level(assessment.risk_score)
        
        # Store findings
        assessment.vulnerabilities = [v.to_dict() for v in unique_vulns[:20]]  # Top 20
        assessment.breaches = [b.to_dict() for b in all_breaches]
        
        # Generate recommendations
        assessment.recommendations = self._generate_recommendations(assessment, unique_vulns)
        
        # Calculate confidence
        assessment.confidence = min(0.9, 0.5 + (assessment.total_cves * 0.02))
        
        return assessment
    
    def _calculate_risk_score(
        self,
        assessment: ThreatAssessment,
        vulns: List[VulnerabilityInfo],
        breaches: List[BreachInfo]
    ) -> float:
        """Calculate risk score (0-10)"""
        score = 0.0
        
        # CVE-based score
        score += assessment.critical_cves * 2.0
        score += assessment.high_cves * 1.0
        score += assessment.exploits_available * 1.5
        
        # Breach-based score
        score += len(breaches) * 1.0
        
        # Cap at 10
        return min(10.0, score)
    
    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 8.0:
            return 'Critical'
        elif score >= 6.0:
            return 'High'
        elif score >= 3.0:
            return 'Medium'
        return 'Low'
    
    def _generate_recommendations(
        self,
        assessment: ThreatAssessment,
        vulns: List[VulnerabilityInfo]
    ) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if assessment.critical_cves > 0:
            recommendations.append(
                f"URGENT: {assessment.critical_cves} critical vulnerabilities require immediate patching"
            )
        
        if assessment.high_cves > 0:
            recommendations.append(
                f"HIGH PRIORITY: {assessment.high_cves} high-severity vulnerabilities should be addressed within 30 days"
            )
        
        if assessment.exploits_available > 0:
            recommendations.append(
                f"WARNING: {assessment.exploits_available} vulnerabilities have known public exploits"
            )
        
        if assessment.breaches_found > 0:
            recommendations.append(
                f"ALERT: {assessment.breaches_found} potential data breaches detected - recommend credential rotation"
            )
        
        if not recommendations:
            recommendations.append("No critical issues found. Continue regular security monitoring.")
        
        return recommendations
    
    def _extract_domain(self, query: str) -> str:
        """Extract domain from query"""
        import re
        
        # Remove protocol
        query = re.sub(r'^https?://', '', query)
        
        # Extract domain
        domain_match = re.match(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', query)
        if domain_match:
            return domain_match.group(1)
        
        return query
    
    async def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a vulnerability finding with additional intelligence.
        
        Args:
            finding: Vulnerability finding from scan
            
        Returns:
            Enriched finding with additional context
        """
        enriched = dict(finding)
        
        # Look up CVE if present
        cve_id = finding.get('cve')
        if cve_id:
            cve_info = await self.surface.search_cve(cve_id)
            if cve_info:
                enriched['cve_details'] = cve_info.to_dict()
                enriched['has_public_exploit'] = cve_info.exploits_available
        
        return enriched


# Singleton
_unified_intel = None

def get_unified_intel() -> UnifiedIntelligence:
    """Get singleton unified intelligence instance"""
    global _unified_intel
    if _unified_intel is None:
        _unified_intel = UnifiedIntelligence()
    return _unified_intel


# Async helper for sync code
def search_intelligence_sync(query: str, include_dark_web: bool = False) -> Dict[str, Any]:
    """Synchronous wrapper for intelligence search"""
    intel = get_unified_intel()
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(intel.search_all(query, include_dark_web))
    finally:
        loop.close()
