"""
Explainable AI Reporting Module

This module provides comprehensive explanations for AI decisions during penetration testing:
1. Why specific tools were chosen
2. Why certain vulnerabilities were prioritized
3. How attack chains were identified
4. What factors influenced exploitation strategies
5. Clear reasoning trails for compliance and audit

Key Features:
- Decision audit trail
- Human-readable explanations
- Confidence scoring
- Alternative option analysis
- Compliance-ready documentation
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class DecisionType(Enum):
    """Types of decisions made by the AI"""
    TOOL_SELECTION = "tool_selection"
    TARGET_PRIORITIZATION = "target_prioritization"
    VULNERABILITY_CLASSIFICATION = "vulnerability_classification"
    ATTACK_CHAIN = "attack_chain"
    EXPLOITATION_STRATEGY = "exploitation_strategy"
    EVASION_TECHNIQUE = "evasion_technique"
    PHASE_TRANSITION = "phase_transition"
    RETRY_DECISION = "retry_decision"
    RISK_ASSESSMENT = "risk_assessment"


class ConfidenceLevel(Enum):
    """Confidence levels for decisions"""
    VERY_HIGH = "very_high"  # 90%+
    HIGH = "high"            # 75-90%
    MEDIUM = "medium"        # 50-75%
    LOW = "low"              # 25-50%
    VERY_LOW = "very_low"    # <25%


@dataclass
class Factor:
    """A factor that influenced a decision"""
    name: str
    description: str
    weight: float  # 0.0 to 1.0
    value: Any
    impact: str  # 'positive', 'negative', 'neutral'
    source: str  # Where this factor came from (memory, analysis, rule, etc.)


@dataclass
class Alternative:
    """An alternative option that was considered"""
    name: str
    description: str
    score: float
    reason_not_chosen: str
    would_be_better_if: str


@dataclass
class DecisionRecord:
    """Record of a single decision made by the AI"""
    id: str
    timestamp: str
    decision_type: DecisionType
    context: Dict[str, Any]  # What the AI knew when making the decision
    decision: str  # What was decided
    factors: List[Factor]  # What influenced the decision
    alternatives: List[Alternative]  # What else was considered
    confidence: ConfidenceLevel
    confidence_score: float  # 0.0 to 1.0
    explanation: str  # Human-readable explanation
    outcome: Optional[str] = None  # What happened (filled in later)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'decision_type': self.decision_type.value,
            'context_summary': self._summarize_context(),
            'decision': self.decision,
            'factors': [
                {
                    'name': f.name,
                    'description': f.description,
                    'weight': f.weight,
                    'impact': f.impact
                }
                for f in self.factors
            ],
            'alternatives': [
                {
                    'name': a.name,
                    'reason_not_chosen': a.reason_not_chosen
                }
                for a in self.alternatives
            ],
            'confidence': self.confidence.value,
            'confidence_score': self.confidence_score,
            'explanation': self.explanation,
            'outcome': self.outcome
        }
    
    def _summarize_context(self) -> str:
        """Create a brief summary of the context"""
        target = self.context.get('target', 'unknown target')
        phase = self.context.get('phase', 'unknown phase')
        return f"Target: {target}, Phase: {phase}"


class DecisionExplainer:
    """Generates human-readable explanations for decisions"""
    
    def __init__(self):
        # Templates for different decision types
        self.explanation_templates = {
            DecisionType.TOOL_SELECTION: self._explain_tool_selection,
            DecisionType.TARGET_PRIORITIZATION: self._explain_target_prioritization,
            DecisionType.VULNERABILITY_CLASSIFICATION: self._explain_vuln_classification,
            DecisionType.ATTACK_CHAIN: self._explain_attack_chain,
            DecisionType.EXPLOITATION_STRATEGY: self._explain_exploitation_strategy,
            DecisionType.EVASION_TECHNIQUE: self._explain_evasion,
            DecisionType.PHASE_TRANSITION: self._explain_phase_transition,
            DecisionType.RETRY_DECISION: self._explain_retry,
            DecisionType.RISK_ASSESSMENT: self._explain_risk_assessment,
        }
    
    def generate_explanation(self, decision: DecisionRecord) -> str:
        """Generate a human-readable explanation for a decision"""
        template_func = self.explanation_templates.get(
            decision.decision_type,
            self._default_explanation
        )
        return template_func(decision)
    
    def _explain_tool_selection(self, decision: DecisionRecord) -> str:
        """Explain why a specific tool was selected"""
        tool = decision.decision
        factors = decision.factors
        alternatives = decision.alternatives
        
        # Build explanation
        lines = [f"**Tool Selected: {tool}**", ""]
        
        # Main reasoning
        lines.append("**Why this tool was chosen:**")
        
        positive_factors = [f for f in factors if f.impact == 'positive']
        for factor in positive_factors[:3]:  # Top 3 positive factors
            lines.append(f"- {factor.description} (weight: {factor.weight:.0%})")
        
        lines.append("")
        
        # Alternatives considered
        if alternatives:
            lines.append("**Alternatives considered:**")
            for alt in alternatives[:3]:
                lines.append(f"- {alt.name}: Not chosen because {alt.reason_not_chosen.lower()}")
        
        lines.append("")
        
        # Confidence
        lines.append(f"**Confidence:** {decision.confidence.value.replace('_', ' ').title()} ({decision.confidence_score:.0%})")
        
        return "\n".join(lines)
    
    def _explain_target_prioritization(self, decision: DecisionRecord) -> str:
        """Explain target prioritization"""
        lines = [f"**Target Priority Decision: {decision.decision}**", ""]
        
        lines.append("**Prioritization factors:**")
        for factor in sorted(decision.factors, key=lambda f: f.weight, reverse=True)[:5]:
            indicator = "↑" if factor.impact == 'positive' else "↓" if factor.impact == 'negative' else "→"
            lines.append(f"- {indicator} {factor.name}: {factor.description}")
        
        return "\n".join(lines)
    
    def _explain_vuln_classification(self, decision: DecisionRecord) -> str:
        """Explain vulnerability classification"""
        lines = [f"**Vulnerability Classification: {decision.decision}**", ""]
        
        lines.append("**Classification reasoning:**")
        
        # Get the key factors
        type_factors = [f for f in decision.factors if 'type' in f.name.lower()]
        severity_factors = [f for f in decision.factors if 'severity' in f.name.lower()]
        
        if type_factors:
            lines.append(f"- Type determination: {type_factors[0].description}")
        if severity_factors:
            lines.append(f"- Severity assessment: {severity_factors[0].description}")
        
        lines.append("")
        lines.append(f"**Confidence:** {decision.confidence_score:.0%}")
        
        return "\n".join(lines)
    
    def _explain_attack_chain(self, decision: DecisionRecord) -> str:
        """Explain attack chain reasoning"""
        lines = [f"**Attack Chain Identified**", ""]
        
        lines.append("**Chain logic:**")
        lines.append(decision.decision)
        lines.append("")
        
        lines.append("**Why this chain was selected:**")
        for factor in decision.factors:
            lines.append(f"- {factor.description}")
        
        if decision.alternatives:
            lines.append("")
            lines.append("**Other possible chains:**")
            for alt in decision.alternatives[:2]:
                lines.append(f"- {alt.name}: {alt.reason_not_chosen}")
        
        return "\n".join(lines)
    
    def _explain_exploitation_strategy(self, decision: DecisionRecord) -> str:
        """Explain exploitation strategy"""
        lines = [f"**Exploitation Strategy: {decision.decision}**", ""]
        
        lines.append("**Strategy reasoning:**")
        
        # Group factors by type
        technical_factors = [f for f in decision.factors if f.source == 'technical_analysis']
        historical_factors = [f for f in decision.factors if f.source == 'memory']
        
        if technical_factors:
            lines.append("*Technical considerations:*")
            for f in technical_factors[:2]:
                lines.append(f"  - {f.description}")
        
        if historical_factors:
            lines.append("*Based on past experience:*")
            for f in historical_factors[:2]:
                lines.append(f"  - {f.description}")
        
        return "\n".join(lines)
    
    def _explain_evasion(self, decision: DecisionRecord) -> str:
        """Explain evasion technique selection"""
        lines = [f"**Evasion Technique Applied: {decision.decision}**", ""]
        
        lines.append("**Why evasion was needed:**")
        defense_factors = [f for f in decision.factors if 'defense' in f.name.lower() or 'block' in f.name.lower()]
        for f in defense_factors:
            lines.append(f"- Detected: {f.description}")
        
        lines.append("")
        lines.append("**Evasion approach:**")
        lines.append(decision.explanation)
        
        return "\n".join(lines)
    
    def _explain_phase_transition(self, decision: DecisionRecord) -> str:
        """Explain phase transition"""
        lines = [f"**Phase Transition: {decision.decision}**", ""]
        
        context = decision.context
        from_phase = context.get('from_phase', 'unknown')
        to_phase = context.get('to_phase', 'unknown')
        
        lines.append(f"Transitioning from **{from_phase}** to **{to_phase}**")
        lines.append("")
        
        lines.append("**Transition criteria met:**")
        for factor in decision.factors:
            lines.append(f"- {factor.description}")
        
        return "\n".join(lines)
    
    def _explain_retry(self, decision: DecisionRecord) -> str:
        """Explain retry decision"""
        lines = [f"**Retry Decision: {decision.decision}**", ""]
        
        context = decision.context
        previous_outcome = context.get('previous_outcome', 'unknown')
        
        lines.append(f"Previous attempt result: {previous_outcome}")
        lines.append("")
        
        if 'retry' in decision.decision.lower():
            lines.append("**Why retrying:**")
            for factor in decision.factors:
                if factor.impact == 'positive':
                    lines.append(f"- {factor.description}")
            
            lines.append("")
            lines.append("**Adaptations made:**")
            adaptations = context.get('adaptations', [])
            for adaptation in adaptations:
                lines.append(f"- {adaptation}")
        else:
            lines.append("**Why not retrying:**")
            for factor in decision.factors:
                if factor.impact == 'negative':
                    lines.append(f"- {factor.description}")
        
        return "\n".join(lines)
    
    def _explain_risk_assessment(self, decision: DecisionRecord) -> str:
        """Explain risk assessment"""
        lines = [f"**Risk Assessment: {decision.decision}**", ""]
        
        lines.append("**Risk factors considered:**")
        
        for factor in sorted(decision.factors, key=lambda f: f.weight, reverse=True):
            risk_level = "HIGH" if factor.weight > 0.7 else "MEDIUM" if factor.weight > 0.4 else "LOW"
            lines.append(f"- [{risk_level}] {factor.name}: {factor.description}")
        
        return "\n".join(lines)
    
    def _default_explanation(self, decision: DecisionRecord) -> str:
        """Default explanation template"""
        lines = [f"**Decision: {decision.decision}**", ""]
        
        lines.append("**Factors considered:**")
        for factor in decision.factors[:5]:
            lines.append(f"- {factor.name}: {factor.description}")
        
        lines.append("")
        lines.append(f"**Confidence:** {decision.confidence_score:.0%}")
        
        return "\n".join(lines)


class DecisionAuditor:
    """Maintains audit trail of all AI decisions"""
    
    def __init__(self):
        self.decisions: List[DecisionRecord] = []
        self.decision_index: Dict[str, DecisionRecord] = {}
        self.explainer = DecisionExplainer()
        
        # Statistics
        self.stats = defaultdict(lambda: {'count': 0, 'avg_confidence': 0.0})
    
    def record_decision(self, decision_type: DecisionType, context: Dict,
                       decision: str, factors: List[Factor],
                       alternatives: List[Alternative],
                       confidence_score: float) -> DecisionRecord:
        """Record a new decision"""
        # Generate ID
        decision_id = f"{decision_type.value}_{len(self.decisions)}_{datetime.now().strftime('%H%M%S')}"
        
        # Determine confidence level
        confidence = self._score_to_level(confidence_score)
        
        # Create record
        record = DecisionRecord(
            id=decision_id,
            timestamp=datetime.now().isoformat(),
            decision_type=decision_type,
            context=context,
            decision=decision,
            factors=factors,
            alternatives=alternatives,
            confidence=confidence,
            confidence_score=confidence_score,
            explanation=""  # Will be generated
        )
        
        # Generate explanation
        record.explanation = self.explainer.generate_explanation(record)
        
        # Store
        self.decisions.append(record)
        self.decision_index[decision_id] = record
        
        # Update stats
        self._update_stats(decision_type, confidence_score)
        
        logger.debug(f"Recorded decision: {decision_id} ({decision_type.value})")
        
        return record
    
    def update_outcome(self, decision_id: str, outcome: str):
        """Update a decision with its outcome"""
        if decision_id in self.decision_index:
            self.decision_index[decision_id].outcome = outcome
            logger.debug(f"Updated outcome for decision {decision_id}: {outcome}")
    
    def get_decision_trail(self, scan_id: str = None) -> List[Dict]:
        """Get the complete decision trail"""
        decisions = self.decisions
        
        # Filter by scan if needed
        if scan_id:
            decisions = [d for d in decisions if d.context.get('scan_id') == scan_id]
        
        return [d.to_dict() for d in decisions]
    
    def get_decisions_by_type(self, decision_type: DecisionType) -> List[DecisionRecord]:
        """Get all decisions of a specific type"""
        return [d for d in self.decisions if d.decision_type == decision_type]
    
    def get_low_confidence_decisions(self, threshold: float = 0.5) -> List[DecisionRecord]:
        """Get decisions with confidence below threshold"""
        return [d for d in self.decisions if d.confidence_score < threshold]
    
    def generate_audit_report(self) -> Dict[str, Any]:
        """Generate a complete audit report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_decisions': len(self.decisions),
            'by_type': {},
            'confidence_distribution': {
                'very_high': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'very_low': 0
            },
            'low_confidence_decisions': [],
            'decision_timeline': []
        }
        
        # Count by type
        for dtype in DecisionType:
            count = len([d for d in self.decisions if d.decision_type == dtype])
            if count > 0:
                report['by_type'][dtype.value] = count
        
        # Confidence distribution
        for decision in self.decisions:
            report['confidence_distribution'][decision.confidence.value] += 1
        
        # Low confidence decisions
        low_conf = self.get_low_confidence_decisions()
        report['low_confidence_decisions'] = [
            {
                'id': d.id,
                'type': d.decision_type.value,
                'decision': d.decision,
                'confidence': d.confidence_score,
                'explanation': d.explanation[:200]
            }
            for d in low_conf
        ]
        
        # Timeline (last 20 decisions)
        for decision in self.decisions[-20:]:
            report['decision_timeline'].append({
                'timestamp': decision.timestamp,
                'type': decision.decision_type.value,
                'decision': decision.decision[:100],
                'confidence': decision.confidence.value
            })
        
        return report
    
    def _score_to_level(self, score: float) -> ConfidenceLevel:
        """Convert confidence score to level"""
        if score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.75:
            return ConfidenceLevel.HIGH
        elif score >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.25:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _update_stats(self, decision_type: DecisionType, confidence: float):
        """Update statistics"""
        key = decision_type.value
        current = self.stats[key]
        
        # Update running average
        n = current['count']
        current['avg_confidence'] = (current['avg_confidence'] * n + confidence) / (n + 1)
        current['count'] = n + 1


class ExplainableReportGenerator:
    """Generates comprehensive explainable reports"""
    
    def __init__(self, auditor: DecisionAuditor):
        self.auditor = auditor
    
    def generate_executive_summary(self, scan_results: Dict) -> str:
        """Generate executive summary with AI decision explanations"""
        lines = ["# Executive Summary", ""]
        
        # Overview
        target = scan_results.get('target', 'Unknown')
        findings_count = len(scan_results.get('findings', []))
        
        lines.append(f"## Scan Overview")
        lines.append(f"- **Target:** {target}")
        lines.append(f"- **Total Findings:** {findings_count}")
        lines.append(f"- **AI Decisions Made:** {len(self.auditor.decisions)}")
        lines.append("")
        
        # Key decisions explanation
        lines.append("## Key AI Decisions Explained")
        lines.append("")
        
        # Get most impactful decisions
        important_decisions = [
            d for d in self.auditor.decisions
            if d.decision_type in [
                DecisionType.ATTACK_CHAIN,
                DecisionType.EXPLOITATION_STRATEGY,
                DecisionType.RISK_ASSESSMENT
            ]
        ]
        
        for decision in important_decisions[:5]:
            lines.append(decision.explanation)
            lines.append("")
        
        # Confidence summary
        lines.append("## AI Confidence Summary")
        audit_report = self.auditor.generate_audit_report()
        conf_dist = audit_report['confidence_distribution']
        
        lines.append(f"- Very High Confidence Decisions: {conf_dist['very_high']}")
        lines.append(f"- High Confidence Decisions: {conf_dist['high']}")
        lines.append(f"- Medium Confidence Decisions: {conf_dist['medium']}")
        lines.append(f"- Low Confidence Decisions: {conf_dist['low'] + conf_dist['very_low']}")
        
        if audit_report['low_confidence_decisions']:
            lines.append("")
            lines.append("### Decisions Requiring Review")
            for d in audit_report['low_confidence_decisions'][:3]:
                lines.append(f"- {d['type']}: {d['decision']} (confidence: {d['confidence']:.0%})")
        
        return "\n".join(lines)
    
    def generate_technical_report(self, scan_results: Dict) -> str:
        """Generate detailed technical report with decision trail"""
        lines = ["# Technical Penetration Test Report", ""]
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")
        
        # Methodology with AI explanations
        lines.append("## Methodology")
        lines.append("")
        lines.append("This assessment was conducted using an AI-assisted penetration testing agent. ")
        lines.append("Below is a detailed explanation of the AI's decision-making process.")
        lines.append("")
        
        # Tool selection decisions
        tool_decisions = self.auditor.get_decisions_by_type(DecisionType.TOOL_SELECTION)
        if tool_decisions:
            lines.append("### Tool Selection Rationale")
            lines.append("")
            for decision in tool_decisions[:10]:
                lines.append(f"#### {decision.decision}")
                lines.append(decision.explanation)
                lines.append("")
        
        # Vulnerability analysis
        vuln_decisions = self.auditor.get_decisions_by_type(DecisionType.VULNERABILITY_CLASSIFICATION)
        if vuln_decisions:
            lines.append("### Vulnerability Classification Reasoning")
            lines.append("")
            for decision in vuln_decisions[:10]:
                lines.append(decision.explanation)
                lines.append("")
        
        # Attack chains
        chain_decisions = self.auditor.get_decisions_by_type(DecisionType.ATTACK_CHAIN)
        if chain_decisions:
            lines.append("### Attack Chain Analysis")
            lines.append("")
            for decision in chain_decisions:
                lines.append(decision.explanation)
                lines.append("")
        
        # Full decision audit trail
        lines.append("## Complete AI Decision Audit Trail")
        lines.append("")
        lines.append("| Time | Decision Type | Decision | Confidence |")
        lines.append("|------|---------------|----------|------------|")
        
        for decision in self.auditor.decisions:
            time = decision.timestamp.split('T')[1][:8]
            dtype = decision.decision_type.value.replace('_', ' ').title()
            dec = decision.decision[:50] + "..." if len(decision.decision) > 50 else decision.decision
            conf = f"{decision.confidence_score:.0%}"
            lines.append(f"| {time} | {dtype} | {dec} | {conf} |")
        
        return "\n".join(lines)
    
    def generate_compliance_report(self, scan_results: Dict, 
                                  framework: str = "generic") -> str:
        """Generate compliance-focused report"""
        lines = [f"# Compliance Report - {framework.upper()}", ""]
        
        lines.append("## AI Decision Transparency")
        lines.append("")
        lines.append("This section provides transparency into the AI-assisted testing process ")
        lines.append("to meet compliance and audit requirements.")
        lines.append("")
        
        # Decision accountability
        lines.append("### Decision Accountability")
        lines.append("")
        lines.append("| Decision ID | Type | Factors Considered | Confidence | Outcome |")
        lines.append("|-------------|------|-------------------|------------|---------|")
        
        for decision in self.auditor.decisions:
            factors = ", ".join([f.name for f in decision.factors[:3]])
            outcome = decision.outcome or "Pending"
            lines.append(
                f"| {decision.id} | {decision.decision_type.value} | "
                f"{factors} | {decision.confidence_score:.0%} | {outcome} |"
            )
        
        lines.append("")
        
        # Low confidence review
        low_conf = self.auditor.get_low_confidence_decisions()
        if low_conf:
            lines.append("### Low Confidence Decisions Requiring Manual Review")
            lines.append("")
            for decision in low_conf:
                lines.append(f"**{decision.id}**")
                lines.append(f"- Decision: {decision.decision}")
                lines.append(f"- Confidence: {decision.confidence_score:.0%}")
                lines.append(f"- Reasoning: {decision.explanation[:200]}...")
                lines.append("")
        
        return "\n".join(lines)
    
    def generate_finding_explanation(self, finding: Dict, 
                                    related_decisions: List[str]) -> str:
        """Generate detailed explanation for a specific finding"""
        lines = [f"# Finding Explanation: {finding.get('title', 'Unknown')}", ""]
        
        lines.append("## Finding Details")
        lines.append(f"- **Type:** {finding.get('type', 'Unknown')}")
        lines.append(f"- **Severity:** {finding.get('severity', 'Unknown')}")
        lines.append(f"- **Location:** {finding.get('url', finding.get('endpoint', 'Unknown'))}")
        lines.append("")
        
        lines.append("## How This Was Discovered")
        lines.append("")
        
        # Get related decisions
        for decision_id in related_decisions:
            if decision_id in self.auditor.decision_index:
                decision = self.auditor.decision_index[decision_id]
                lines.append(f"### {decision.decision_type.value.replace('_', ' ').title()}")
                lines.append(decision.explanation)
                lines.append("")
        
        lines.append("## AI Confidence in This Finding")
        lines.append("")
        
        # Aggregate confidence from related decisions
        confidences = [
            self.auditor.decision_index[d].confidence_score
            for d in related_decisions
            if d in self.auditor.decision_index
        ]
        
        if confidences:
            avg_conf = sum(confidences) / len(confidences)
            lines.append(f"Average decision confidence: **{avg_conf:.0%}**")
        
        return "\n".join(lines)


class ExplainableAIEngine:
    """
    Main engine for explainable AI reporting
    
    Integrates with the scanning process to track and explain all decisions
    """
    
    def __init__(self):
        self.auditor = DecisionAuditor()
        self.report_generator = ExplainableReportGenerator(self.auditor)
        
        # Decision-finding mapping
        self.finding_decisions: Dict[str, List[str]] = defaultdict(list)
        
        logger.info("Explainable AI Engine initialized")
    
    def record_tool_selection(self, tool: str, context: Dict,
                             scores: Dict[str, float],
                             factors: List[Dict]) -> str:
        """Record a tool selection decision"""
        # Convert factors
        factor_objects = [
            Factor(
                name=f.get('name', ''),
                description=f.get('description', ''),
                weight=f.get('weight', 0.5),
                value=f.get('value'),
                impact=f.get('impact', 'neutral'),
                source=f.get('source', 'analysis')
            )
            for f in factors
        ]
        
        # Create alternatives from scores
        alternatives = [
            Alternative(
                name=tool_name,
                description=f"Alternative tool option",
                score=score,
                reason_not_chosen=f"Lower score ({score:.2f}) than selected tool",
                would_be_better_if="Target characteristics matched better"
            )
            for tool_name, score in scores.items()
            if tool_name != tool
        ][:5]
        
        # Calculate confidence from score margin
        sorted_scores = sorted(scores.values(), reverse=True)
        if len(sorted_scores) >= 2:
            margin = sorted_scores[0] - sorted_scores[1]
            confidence = min(1.0, 0.5 + margin)
        else:
            confidence = 0.7
        
        record = self.auditor.record_decision(
            decision_type=DecisionType.TOOL_SELECTION,
            context=context,
            decision=f"Selected {tool}",
            factors=factor_objects,
            alternatives=alternatives,
            confidence_score=confidence
        )
        
        return record.id
    
    def record_vulnerability_classification(self, finding: Dict,
                                           classification: Dict,
                                           factors: List[Dict]) -> str:
        """Record a vulnerability classification decision"""
        factor_objects = [
            Factor(
                name=f.get('name', ''),
                description=f.get('description', ''),
                weight=f.get('weight', 0.5),
                value=f.get('value'),
                impact='positive',
                source=f.get('source', 'analysis')
            )
            for f in factors
        ]
        
        context = {
            'finding_type': finding.get('type', ''),
            'endpoint': finding.get('url', finding.get('endpoint', '')),
        }
        
        decision_text = f"Classified as {classification.get('type', 'unknown')} " \
                       f"with severity {classification.get('severity', 'unknown')}"
        
        record = self.auditor.record_decision(
            decision_type=DecisionType.VULNERABILITY_CLASSIFICATION,
            context=context,
            decision=decision_text,
            factors=factor_objects,
            alternatives=[],
            confidence_score=classification.get('confidence', 0.7)
        )
        
        # Link to finding
        finding_id = finding.get('id', str(hash(str(finding))))
        self.finding_decisions[finding_id].append(record.id)
        
        return record.id
    
    def record_attack_chain_selection(self, chain: Dict, 
                                     alternatives: List[Dict],
                                     factors: List[Dict]) -> str:
        """Record attack chain selection decision"""
        factor_objects = [
            Factor(
                name=f.get('name', ''),
                description=f.get('description', ''),
                weight=f.get('weight', 0.5),
                value=f.get('value'),
                impact=f.get('impact', 'positive'),
                source=f.get('source', 'chain_analysis')
            )
            for f in factors
        ]
        
        alternative_objects = [
            Alternative(
                name=alt.get('name', f"Chain {i}"),
                description=alt.get('description', ''),
                score=alt.get('score', 0),
                reason_not_chosen=alt.get('reason_not_chosen', 'Lower effectiveness score'),
                would_be_better_if=alt.get('would_be_better_if', 'Different target configuration')
            )
            for i, alt in enumerate(alternatives)
        ]
        
        context = {
            'chain_length': len(chain.get('vulnerabilities', [])),
            'final_impact': chain.get('final_impact', ''),
        }
        
        record = self.auditor.record_decision(
            decision_type=DecisionType.ATTACK_CHAIN,
            context=context,
            decision=chain.get('description', 'Attack chain selected'),
            factors=factor_objects,
            alternatives=alternative_objects,
            confidence_score=chain.get('success_probability', 0.5)
        )
        
        return record.id
    
    def record_evasion_decision(self, technique: str, 
                               detected_defenses: List[str],
                               context: Dict) -> str:
        """Record evasion technique decision"""
        factors = [
            Factor(
                name=f"defense_{defense}",
                description=f"Detected {defense} defense mechanism",
                weight=0.8,
                value=defense,
                impact='negative',
                source='defense_detection'
            )
            for defense in detected_defenses
        ]
        
        record = self.auditor.record_decision(
            decision_type=DecisionType.EVASION_TECHNIQUE,
            context=context,
            decision=f"Applied {technique} evasion",
            factors=factors,
            alternatives=[],
            confidence_score=0.6
        )
        
        return record.id
    
    def record_retry_decision(self, should_retry: bool,
                             previous_outcome: str,
                             adaptations: List[str],
                             context: Dict) -> str:
        """Record retry decision"""
        factors = [
            Factor(
                name="previous_outcome",
                description=f"Previous attempt resulted in: {previous_outcome}",
                weight=0.7,
                value=previous_outcome,
                impact='negative' if 'fail' in previous_outcome.lower() else 'neutral',
                source='execution_result'
            )
        ]
        
        if adaptations:
            factors.append(Factor(
                name="adaptations_available",
                description=f"Can apply {len(adaptations)} adaptations",
                weight=0.6,
                value=adaptations,
                impact='positive',
                source='adaptive_engine'
            ))
        
        context['previous_outcome'] = previous_outcome
        context['adaptations'] = adaptations
        
        record = self.auditor.record_decision(
            decision_type=DecisionType.RETRY_DECISION,
            context=context,
            decision="Retry with adaptations" if should_retry else "Do not retry",
            factors=factors,
            alternatives=[],
            confidence_score=0.7 if should_retry else 0.8
        )
        
        return record.id
    
    def get_finding_explanation(self, finding_id: str) -> str:
        """Get complete explanation for a finding"""
        related_decisions = self.finding_decisions.get(finding_id, [])
        
        # Mock finding for now - in production would retrieve actual finding
        finding = {'id': finding_id, 'title': 'Finding', 'type': 'unknown', 'severity': 'unknown'}
        
        return self.report_generator.generate_finding_explanation(finding, related_decisions)
    
    def generate_report(self, scan_results: Dict, report_type: str = "technical") -> str:
        """Generate a report of specified type"""
        if report_type == "executive":
            return self.report_generator.generate_executive_summary(scan_results)
        elif report_type == "compliance":
            return self.report_generator.generate_compliance_report(scan_results)
        else:
            return self.report_generator.generate_technical_report(scan_results)
    
    def get_audit_trail(self) -> List[Dict]:
        """Get complete decision audit trail"""
        return self.auditor.get_decision_trail()
    
    def get_audit_report(self) -> Dict:
        """Get audit statistics report"""
        return self.auditor.generate_audit_report()


# Singleton instance
_explainable_engine = None

def get_explainable_engine() -> ExplainableAIEngine:
    """Get the singleton explainable AI engine"""
    global _explainable_engine
    if _explainable_engine is None:
        _explainable_engine = ExplainableAIEngine()
    return _explainable_engine
