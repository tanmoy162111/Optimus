"""
Multi-Target Campaign Intelligence Module

This module enables cross-target learning and campaign-level intelligence:
1. Pattern recognition across multiple targets
2. Industry/sector-specific vulnerability trends
3. Campaign planning and optimization
4. Comparative analysis between targets
5. Aggregate intelligence reporting

Key Features:
- Cross-target pattern extraction
- Sector-specific attack playbooks
- Campaign success prediction
- Resource optimization across targets
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import numpy as np

logger = logging.getLogger(__name__)


class IndustrySector(Enum):
    """Industry sectors for categorization"""
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    TECHNOLOGY = "technology"
    RETAIL = "retail"
    GOVERNMENT = "government"
    EDUCATION = "education"
    MANUFACTURING = "manufacturing"
    ENERGY = "energy"
    TELECOMMUNICATIONS = "telecommunications"
    UNKNOWN = "unknown"


class TargetSize(Enum):
    """Target organization size"""
    SMALL = "small"  # < 50 employees
    MEDIUM = "medium"  # 50-500 employees
    LARGE = "large"  # 500-5000 employees
    ENTERPRISE = "enterprise"  # > 5000 employees
    UNKNOWN = "unknown"


@dataclass
class TargetProfile:
    """Profile of a scan target"""
    target_id: str
    target_url: str
    sector: IndustrySector
    size: TargetSize
    technologies: List[str]
    findings_count: int
    critical_count: int
    scan_duration: float
    successful_tools: List[str]
    failed_tools: List[str]
    defenses_detected: List[str]
    attack_chains_found: int
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignTarget:
    """A target within a campaign"""
    target_id: str
    target_url: str
    status: str  # 'pending', 'in_progress', 'completed', 'failed'
    priority: int  # 1-10
    estimated_duration: float  # hours
    actual_duration: Optional[float]
    findings_count: int
    assigned_resources: List[str]  # Tools/agents assigned


@dataclass
class Campaign:
    """A multi-target penetration testing campaign"""
    campaign_id: str
    name: str
    description: str
    targets: List[CampaignTarget]
    start_time: str
    end_time: Optional[str]
    status: str  # 'planning', 'active', 'completed', 'paused'
    total_findings: int
    sector: IndustrySector
    created_at: str


class CrossTargetPatternAnalyzer:
    """Analyzes patterns across multiple targets"""
    
    def __init__(self):
        # Pattern storage
        self.vulnerability_patterns: Dict[str, Dict] = defaultdict(
            lambda: {'count': 0, 'targets': [], 'sectors': [], 'technologies': []}
        )
        
        self.technology_vulnerability_map: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        
        self.sector_vulnerability_map: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        
        self.tool_effectiveness: Dict[str, Dict] = defaultdict(
            lambda: {'success_count': 0, 'total_count': 0, 'vulns_found': 0}
        )
    
    def analyze_target_results(self, profile: TargetProfile, findings: List[Dict]):
        """Analyze results from a target scan"""
        # Extract vulnerability patterns
        for finding in findings:
            vuln_type = finding.get('type', 'unknown')
            
            # Update vulnerability pattern
            self.vulnerability_patterns[vuln_type]['count'] += 1
            self.vulnerability_patterns[vuln_type]['targets'].append(profile.target_id)
            self.vulnerability_patterns[vuln_type]['sectors'].append(profile.sector.value)
            self.vulnerability_patterns[vuln_type]['technologies'].extend(profile.technologies)
            
            # Update technology-vulnerability map
            for tech in profile.technologies:
                self.technology_vulnerability_map[tech][vuln_type] += 1
            
            # Update sector-vulnerability map
            self.sector_vulnerability_map[profile.sector.value][vuln_type] += 1
        
        # Update tool effectiveness
        for tool in profile.successful_tools:
            self.tool_effectiveness[tool]['success_count'] += 1
            self.tool_effectiveness[tool]['total_count'] += 1
        
        for tool in profile.failed_tools:
            self.tool_effectiveness[tool]['total_count'] += 1
        
        # Attribute vulnerabilities to tools (simplified)
        vulns_per_tool = len(findings) / max(1, len(profile.successful_tools))
        for tool in profile.successful_tools:
            self.tool_effectiveness[tool]['vulns_found'] += vulns_per_tool
    
    def get_common_vulnerabilities(self, min_occurrences: int = 3) -> List[Dict]:
        """Get commonly occurring vulnerabilities across targets"""
        common = []
        
        for vuln_type, data in self.vulnerability_patterns.items():
            if data['count'] >= min_occurrences:
                # Find most common technologies
                tech_counts = defaultdict(int)
                for tech in data['technologies']:
                    tech_counts[tech] += 1
                
                top_techs = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                
                common.append({
                    'vulnerability_type': vuln_type,
                    'occurrence_count': data['count'],
                    'affected_targets': len(set(data['targets'])),
                    'top_sectors': list(set(data['sectors']))[:3],
                    'associated_technologies': [t[0] for t in top_techs]
                })
        
        return sorted(common, key=lambda x: x['occurrence_count'], reverse=True)
    
    def get_sector_insights(self, sector: str) -> Dict[str, Any]:
        """Get vulnerability insights for a specific sector"""
        vuln_counts = self.sector_vulnerability_map.get(sector, {})
        
        if not vuln_counts:
            return {'sector': sector, 'no_data': True}
        
        total_vulns = sum(vuln_counts.values())
        
        return {
            'sector': sector,
            'total_vulnerabilities': total_vulns,
            'top_vulnerabilities': sorted(
                vuln_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
            'vulnerability_distribution': {
                k: v / total_vulns for k, v in vuln_counts.items()
            }
        }
    
    def get_technology_risk_profile(self, technology: str) -> Dict[str, Any]:
        """Get risk profile for a specific technology"""
        vuln_counts = self.technology_vulnerability_map.get(technology, {})
        
        if not vuln_counts:
            return {'technology': technology, 'no_data': True}
        
        total = sum(vuln_counts.values())
        
        return {
            'technology': technology,
            'total_associated_vulns': total,
            'vulnerability_breakdown': dict(vuln_counts),
            'risk_score': min(10, total / 5),  # Simple risk score
            'recommended_focus': list(vuln_counts.keys())[:5]
        }
    
    def predict_vulnerabilities(self, technologies: List[str], 
                               sector: str) -> List[Dict]:
        """Predict likely vulnerabilities based on tech stack and sector"""
        predictions = defaultdict(float)
        
        # Technology-based predictions
        for tech in technologies:
            vuln_counts = self.technology_vulnerability_map.get(tech, {})
            total = sum(vuln_counts.values()) or 1
            
            for vuln_type, count in vuln_counts.items():
                predictions[vuln_type] += count / total
        
        # Sector-based predictions
        sector_vulns = self.sector_vulnerability_map.get(sector, {})
        sector_total = sum(sector_vulns.values()) or 1
        
        for vuln_type, count in sector_vulns.items():
            predictions[vuln_type] += (count / sector_total) * 0.5  # Weight sector less
        
        # Normalize and sort
        max_score = max(predictions.values()) if predictions else 1
        
        return [
            {
                'vulnerability_type': vuln_type,
                'likelihood_score': score / max_score,
                'based_on': 'technology_and_sector_patterns'
            }
            for vuln_type, score in sorted(
                predictions.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
        ]


class CampaignManager:
    """Manages multi-target penetration testing campaigns"""
    
    def __init__(self, memory_system=None):
        self.memory_system = memory_system
        self.campaigns: Dict[str, Campaign] = {}
        self.target_profiles: Dict[str, TargetProfile] = {}
        self.pattern_analyzer = CrossTargetPatternAnalyzer()
        
        # Resource allocation
        self.available_resources = {
            'parallel_scans': 3,
            'tools': ['nmap', 'nuclei', 'nikto', 'sqlmap', 'wpscan', 'dirsearch']
        }
    
    def create_campaign(self, name: str, targets: List[Dict],
                       sector: IndustrySector = IndustrySector.UNKNOWN) -> Campaign:
        """Create a new multi-target campaign"""
        campaign_id = hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        # Create campaign targets
        campaign_targets = []
        for i, target in enumerate(targets):
            ct = CampaignTarget(
                target_id=hashlib.md5(target['url'].encode()).hexdigest()[:12],
                target_url=target['url'],
                status='pending',
                priority=target.get('priority', 5),
                estimated_duration=self._estimate_duration(target),
                actual_duration=None,
                findings_count=0,
                assigned_resources=[]
            )
            campaign_targets.append(ct)
        
        # Sort by priority
        campaign_targets.sort(key=lambda x: x.priority, reverse=True)
        
        campaign = Campaign(
            campaign_id=campaign_id,
            name=name,
            description=f"Campaign with {len(targets)} targets",
            targets=campaign_targets,
            start_time=datetime.now().isoformat(),
            end_time=None,
            status='planning',
            total_findings=0,
            sector=sector,
            created_at=datetime.now().isoformat()
        )
        
        self.campaigns[campaign_id] = campaign
        
        logger.info(f"Created campaign: {campaign_id} with {len(targets)} targets")
        
        return campaign
    
    def _estimate_duration(self, target: Dict) -> float:
        """Estimate scan duration for a target"""
        # Base duration in hours
        duration = 1.0
        
        # Adjust based on scope
        scope = target.get('scope', 'standard')
        if scope == 'comprehensive':
            duration *= 3
        elif scope == 'quick':
            duration *= 0.5
        
        # Adjust based on target type
        if 'api' in target.get('url', '').lower():
            duration *= 0.8
        
        return duration
    
    def optimize_campaign_order(self, campaign_id: str) -> List[Dict]:
        """Optimize the order of targets in a campaign"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return []
        
        # Simple optimization based on:
        # 1. Priority
        # 2. Estimated duration (shorter first for quick wins)
        # 3. Predicted vulnerability count (higher first)
        
        scored_targets = []
        
        for target in campaign.targets:
            if target.status != 'completed':
                score = (
                    target.priority * 3 +  # Priority weight
                    (1 / max(0.1, target.estimated_duration)) * 2 +  # Duration weight (shorter = higher)
                    5  # Base score
                )
                scored_targets.append({
                    'target_id': target.target_id,
                    'target_url': target.target_url,
                    'score': score,
                    'priority': target.priority,
                    'estimated_duration': target.estimated_duration
                })
        
        return sorted(scored_targets, key=lambda x: x['score'], reverse=True)
    
    def record_target_completion(self, campaign_id: str, target_id: str,
                                profile: TargetProfile, findings: List[Dict]):
        """Record completion of a target scan"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return
        
        # Update target status
        for target in campaign.targets:
            if target.target_id == target_id:
                target.status = 'completed'
                target.actual_duration = profile.scan_duration
                target.findings_count = profile.findings_count
                break
        
        # Update campaign totals
        campaign.total_findings += profile.findings_count
        
        # Store profile
        self.target_profiles[target_id] = profile
        
        # Analyze patterns
        self.pattern_analyzer.analyze_target_results(profile, findings)
        
        # Check if campaign complete
        if all(t.status == 'completed' for t in campaign.targets):
            campaign.status = 'completed'
            campaign.end_time = datetime.now().isoformat()
        
        # Store in memory
        if self.memory_system:
            self.memory_system.store_memory(
                memory_type='campaign_target_result',
                content={
                    'campaign_id': campaign_id,
                    'target_id': target_id,
                    'findings_count': profile.findings_count,
                    'technologies': profile.technologies,
                    'sector': campaign.sector.value
                },
                tags=[campaign.sector.value, 'campaign'],
                importance=min(1.0, profile.findings_count / 10)
            )
    
    def get_campaign_insights(self, campaign_id: str) -> Dict[str, Any]:
        """Get insights from a campaign"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return {}
        
        completed_targets = [t for t in campaign.targets if t.status == 'completed']
        
        insights = {
            'campaign_id': campaign_id,
            'name': campaign.name,
            'status': campaign.status,
            'progress': {
                'total_targets': len(campaign.targets),
                'completed': len(completed_targets),
                'in_progress': len([t for t in campaign.targets if t.status == 'in_progress']),
                'pending': len([t for t in campaign.targets if t.status == 'pending'])
            },
            'findings': {
                'total': campaign.total_findings,
                'average_per_target': campaign.total_findings / max(1, len(completed_targets))
            },
            'timing': {
                'start_time': campaign.start_time,
                'end_time': campaign.end_time,
                'total_scan_time': sum(
                    t.actual_duration or 0 for t in completed_targets
                )
            }
        }
        
        # Add pattern insights if we have enough data
        if len(completed_targets) >= 2:
            insights['patterns'] = {
                'common_vulnerabilities': self.pattern_analyzer.get_common_vulnerabilities(2),
                'sector_insights': self.pattern_analyzer.get_sector_insights(campaign.sector.value)
            }
        
        return insights
    
    def get_recommendations_for_target(self, campaign_id: str, 
                                       target_url: str) -> Dict[str, Any]:
        """Get recommendations for a specific target based on campaign learnings"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return {}
        
        # Find completed similar targets
        similar_profiles = []
        for target in campaign.targets:
            if target.status == 'completed' and target.target_url != target_url:
                profile = self.target_profiles.get(target.target_id)
                if profile:
                    similar_profiles.append(profile)
        
        if not similar_profiles:
            return {'message': 'Not enough campaign data for recommendations'}
        
        # Aggregate successful tools
        tool_success_rates = defaultdict(lambda: {'success': 0, 'total': 0})
        for profile in similar_profiles:
            for tool in profile.successful_tools:
                tool_success_rates[tool]['success'] += 1
                tool_success_rates[tool]['total'] += 1
            for tool in profile.failed_tools:
                tool_success_rates[tool]['total'] += 1
        
        # Calculate rates
        recommended_tools = []
        for tool, stats in tool_success_rates.items():
            rate = stats['success'] / max(1, stats['total'])
            if rate > 0.5:
                recommended_tools.append({
                    'tool': tool,
                    'success_rate': rate,
                    'based_on': stats['total']
                })
        
        # Predict vulnerabilities
        avg_technologies = []
        for profile in similar_profiles:
            avg_technologies.extend(profile.technologies)
        
        predicted_vulns = self.pattern_analyzer.predict_vulnerabilities(
            list(set(avg_technologies)),
            campaign.sector.value
        )
        
        return {
            'recommended_tools': sorted(
                recommended_tools, 
                key=lambda x: x['success_rate'], 
                reverse=True
            )[:5],
            'predicted_vulnerabilities': predicted_vulns[:5],
            'common_defenses': list(set(
                defense 
                for profile in similar_profiles 
                for defense in profile.defenses_detected
            )),
            'estimated_findings': int(np.mean([p.findings_count for p in similar_profiles]))
        }


class CampaignIntelligenceEngine:
    """
    Main engine for multi-target campaign intelligence
    """
    
    def __init__(self, memory_system=None):
        self.memory_system = memory_system
        self.campaign_manager = CampaignManager(memory_system)
        
        # Cross-campaign analytics
        self.all_campaigns: List[str] = []
        self.global_pattern_analyzer = CrossTargetPatternAnalyzer()
        
        logger.info("Campaign Intelligence Engine initialized")
    
    def create_campaign(self, name: str, targets: List[Dict],
                       sector: str = "unknown") -> Dict:
        """Create a new campaign"""
        try:
            sector_enum = IndustrySector(sector)
        except ValueError:
            sector_enum = IndustrySector.UNKNOWN
        
        campaign = self.campaign_manager.create_campaign(name, targets, sector_enum)
        self.all_campaigns.append(campaign.campaign_id)
        
        return {
            'campaign_id': campaign.campaign_id,
            'name': campaign.name,
            'targets': len(campaign.targets),
            'status': campaign.status
        }
    
    def get_optimized_scan_order(self, campaign_id: str) -> List[Dict]:
        """Get optimized order for scanning targets"""
        return self.campaign_manager.optimize_campaign_order(campaign_id)
    
    def record_scan_result(self, campaign_id: str, target_url: str,
                          scan_result: Dict, findings: List[Dict]):
        """Record results from a target scan"""
        # Create target profile
        profile = TargetProfile(
            target_id=hashlib.md5(target_url.encode()).hexdigest()[:12],
            target_url=target_url,
            sector=IndustrySector.UNKNOWN,  # Would be determined from context
            size=TargetSize.UNKNOWN,
            technologies=scan_result.get('technologies', []),
            findings_count=len(findings),
            critical_count=len([f for f in findings if f.get('severity', 0) >= 9]),
            scan_duration=scan_result.get('duration', 0),
            successful_tools=scan_result.get('successful_tools', []),
            failed_tools=scan_result.get('failed_tools', []),
            defenses_detected=scan_result.get('defenses', []),
            attack_chains_found=scan_result.get('chains_found', 0),
            timestamp=datetime.now().isoformat()
        )
        
        self.campaign_manager.record_target_completion(
            campaign_id, profile.target_id, profile, findings
        )
        
        # Update global patterns
        self.global_pattern_analyzer.analyze_target_results(profile, findings)
    
    def get_campaign_insights(self, campaign_id: str) -> Dict[str, Any]:
        """Get insights for a specific campaign"""
        return self.campaign_manager.get_campaign_insights(campaign_id)
    
    def get_target_recommendations(self, campaign_id: str, 
                                  target_url: str) -> Dict[str, Any]:
        """Get recommendations for a target based on campaign learnings"""
        return self.campaign_manager.get_recommendations_for_target(
            campaign_id, target_url
        )
    
    def get_global_vulnerability_trends(self) -> Dict[str, Any]:
        """Get vulnerability trends across all campaigns"""
        return {
            'common_vulnerabilities': self.global_pattern_analyzer.get_common_vulnerabilities(),
            'technology_risks': {
                tech: self.global_pattern_analyzer.get_technology_risk_profile(tech)
                for tech in list(self.global_pattern_analyzer.technology_vulnerability_map.keys())[:10]
            },
            'sector_breakdown': {
                sector: self.global_pattern_analyzer.get_sector_insights(sector)
                for sector in [s.value for s in IndustrySector if s != IndustrySector.UNKNOWN]
            }
        }
    
    def predict_campaign_success(self, targets: List[Dict], 
                                sector: str) -> Dict[str, Any]:
        """Predict campaign outcomes based on historical data"""
        predictions = {
            'targets': len(targets),
            'predicted_findings': [],
            'estimated_duration': 0,
            'risk_assessment': {}
        }
        
        for target in targets:
            # Get technology predictions
            techs = target.get('technologies', [])
            predicted = self.global_pattern_analyzer.predict_vulnerabilities(techs, sector)
            
            predictions['predicted_findings'].append({
                'target': target.get('url', 'unknown'),
                'likely_vulnerabilities': predicted[:3]
            })
            
            # Estimate duration
            predictions['estimated_duration'] += self.campaign_manager._estimate_duration(target)
        
        # Overall risk assessment
        predictions['risk_assessment'] = {
            'overall_confidence': min(1.0, len(self.all_campaigns) / 10),
            'data_quality': 'high' if len(self.all_campaigns) > 5 else 'medium' if len(self.all_campaigns) > 2 else 'low',
            'recommendation': 'Predictions based on historical data' if self.all_campaigns else 'Limited historical data available'
        }
        
        return predictions
    
    def generate_campaign_report(self, campaign_id: str) -> str:
        """Generate comprehensive campaign report"""
        insights = self.get_campaign_insights(campaign_id)
        
        if not insights:
            return "Campaign not found"
        
        lines = [
            f"# Campaign Report: {insights.get('name', 'Unknown')}",
            "",
            f"**Campaign ID:** {campaign_id}",
            f"**Status:** {insights.get('status', 'unknown')}",
            "",
            "## Progress",
            "",
            f"- Total Targets: {insights['progress']['total_targets']}",
            f"- Completed: {insights['progress']['completed']}",
            f"- In Progress: {insights['progress']['in_progress']}",
            f"- Pending: {insights['progress']['pending']}",
            "",
            "## Findings Summary",
            "",
            f"- Total Findings: {insights['findings']['total']}",
            f"- Average per Target: {insights['findings']['average_per_target']:.1f}",
            "",
            "## Timing",
            "",
            f"- Start Time: {insights['timing']['start_time']}",
            f"- End Time: {insights['timing']['end_time'] or 'In Progress'}",
            f"- Total Scan Time: {insights['timing']['total_scan_time']:.1f} hours",
            ""
        ]
        
        # Add pattern insights if available
        if 'patterns' in insights:
            lines.extend([
                "## Cross-Target Patterns",
                "",
                "### Common Vulnerabilities",
                ""
            ])
            
            for vuln in insights['patterns'].get('common_vulnerabilities', [])[:5]:
                lines.append(
                    f"- **{vuln['vulnerability_type']}**: Found in {vuln['affected_targets']} targets"
                )
            
            lines.append("")
        
        return "\n".join(lines)


# Singleton instance
_campaign_engine = None

def get_campaign_engine(memory_system=None) -> CampaignIntelligenceEngine:
    """Get the singleton campaign intelligence engine"""
    global _campaign_engine
    if _campaign_engine is None:
        _campaign_engine = CampaignIntelligenceEngine(memory_system)
    return _campaign_engine
