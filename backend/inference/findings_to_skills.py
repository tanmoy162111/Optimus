"""
Findings to Skills Connection Module
Connects tool findings to skill improvements and lessons learned
"""
import logging
from typing import Dict, List, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from utils.observability import log_skill, log_lesson_decision

logger = logging.getLogger(__name__)


class FindingType(Enum):
    """Types of findings that can improve specific skills"""
    OPEN_PORT = "open_port"
    SERVICE_DETECTION = "service_detection"
    VULNERABILITY = "vulnerability"
    WEB_TECHNOLOGY = "web_technology"
    SUBDOMAIN = "subdomain"
    DIRECTORY = "directory"
    PARAMETER = "parameter"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    WEAK_CREDENTIAL = "weak_credential"
    DEFAULT_CREDENTIAL = "default_credential"
    MISCONFIGURATION = "misconfiguration"


@dataclass
class Finding:
    """Structured finding from tool execution"""
    id: str
    type: str
    name: str
    severity: float
    confidence: float
    location: str
    evidence: str
    exploitable: bool
    tool: str
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class FindingsToSkillsConnector:
    """Connects tool findings to skill improvements and lessons learned"""
    
    def __init__(self):
        self.finding_to_skill_mapping = {
            FindingType.OPEN_PORT.value: ["nmap", "port_scanning", "reconnaissance"],
            FindingType.SERVICE_DETECTION.value: ["nmap", "service_detection", "enumeration"],
            FindingType.VULNERABILITY.value: ["vulnerability_assessment", "security_analysis"],
            FindingType.WEB_TECHNOLOGY.value: ["whatweb", "technology_detection", "web_recon"],
            FindingType.SUBDOMAIN.value: ["subdomain_enumeration", "dns_recon"],
            FindingType.DIRECTORY.value: ["directory_enumeration", "web_scanning"],
            FindingType.PARAMETER.value: ["parameter_discovery", "web_scanning"],
            FindingType.SQL_INJECTION.value: ["sqlmap", "sql_injection", "exploitation"],
            FindingType.XSS.value: ["xss_detection", "exploitation"],
            FindingType.WEAK_CREDENTIAL.value: ["hydra", "bruteforce", "credential_testing"],
            FindingType.DEFAULT_CREDENTIAL.value: ["credential_testing", "authentication"],
            FindingType.MISCONFIGURATION.value: ["nuclei", "misconfiguration", "security_analysis"]
        }
        
        # Skill improvement weights based on finding severity
        self.severity_weights = {
            9.0: 5.0,  # Critical
            7.0: 4.0,  # High
            4.0: 3.0,  # Medium
            2.0: 2.0,  # Low
            0.0: 1.0   # Informational
        }
        
        self.logger = logging.getLogger(__name__)
    
    def process_findings(self, findings: List[Dict], tool_name: str, phase: str, scan_id: str):
        """
        Process findings and update relevant skills
        """
        if not findings:
            return {"skills_updated": 0, "lessons_learned": 0, "findings_processed": 0}
        
        processed_findings = 0
        skills_updated = 0
        lessons_learned = 0
        
        for finding_data in findings:
            try:
                # Create finding object
                finding = Finding(
                    id=finding_data.get('id', ''),
                    type=finding_data.get('type', 'unknown'),
                    name=finding_data.get('name', ''),
                    severity=finding_data.get('severity', 0.0),
                    confidence=finding_data.get('confidence', 0.0),
                    location=finding_data.get('location', ''),
                    evidence=finding_data.get('evidence', ''),
                    exploitable=finding_data.get('exploitable', False),
                    tool=finding_data.get('tool', tool_name)
                )
                
                # Update skills based on finding
                updated_skills = self._update_skills_for_finding(finding, tool_name, phase, scan_id)
                skills_updated += len(updated_skills)
                
                # Generate lessons from finding
                lessons = self._generate_lessons_from_finding(finding, phase, scan_id)
                lessons_learned += len(lessons)
                
                processed_findings += 1
                
            except Exception as e:
                self.logger.error(f"Error processing finding: {e}")
                continue
        
        result = {
            "skills_updated": skills_updated,
            "lessons_learned": lessons_learned,
            "findings_processed": processed_findings,
            "scan_id": scan_id,
            "phase": phase,
            "tool": tool_name
        }
        
        self.logger.info(f"Processed {processed_findings} findings, updated {skills_updated} skills, learned {lessons_learned} lessons")
        
        # Log the processing result
        log_lesson_decision(
            decision=f"Findings processed: {processed_findings}, Skills updated: {skills_updated}, Lessons learned: {lessons_learned}",
            scan_id=scan_id,
            phase=phase,
            tool=tool_name
        )
        
        return result
    
    def _update_skills_for_finding(self, finding: Finding, tool_name: str, phase: str, scan_id: str) -> List[str]:
        """Update relevant skills based on a finding"""
        skills_to_update = []
        
        # Get relevant skills for this finding type
        finding_type = finding.type.lower()
        if finding_type in self.finding_to_skill_mapping:
            skills_to_update.extend(self.finding_to_skill_mapping[finding_type])
        else:
            # Add the tool name as a skill if no specific mapping exists
            skills_to_update.append(tool_name)
        
        # Add phase-specific skills
        phase_skills = {
            'reconnaissance': ['reconnaissance', 'information_gathering'],
            'scanning': ['scanning', 'enumeration'],
            'enumeration': ['enumeration', 'service_detection'],
            'exploitation': ['exploitation', 'vulnerability_exploitation'],
            'post_exploitation': ['post_exploitation', 'privilege_escalation']
        }
        
        if phase in phase_skills:
            skills_to_update.extend(phase_skills[phase])
        
        # Remove duplicates
        skills_to_update = list(set(skills_to_update))
        
        # Update each skill with appropriate weight based on severity
        updated_skills = []
        for skill_name in skills_to_update:
            try:
                # Calculate skill improvement based on finding severity
                severity = finding.severity
                improvement_weight = 1.0
                
                # Find closest severity weight
                for threshold in sorted(self.severity_weights.keys(), reverse=True):
                    if severity >= threshold:
                        improvement_weight = self.severity_weights[threshold]
                        break
                
                # Log skill update
                log_skill(
                    skill=skill_name,
                    finding_type=finding.type,
                    severity=finding.severity,
                    tool=tool_name,
                    phase=phase,
                    scan_id=scan_id,
                    improvement_weight=improvement_weight
                )
                
                updated_skills.append(skill_name)
                
            except Exception as e:
                self.logger.error(f"Error updating skill {skill_name}: {e}")
                continue
        
        return updated_skills
    
    def _generate_lessons_from_finding(self, finding: Finding, phase: str, scan_id: str) -> List[Dict[str, Any]]:
        """Generate lessons from a finding"""
        lessons = []
        
        try:
            # Create lesson based on finding
            lesson = {
                "id": f"lesson_{finding.id}",
                "type": "finding_lesson",
                "category": finding.type,
                "content": f"Found {finding.type} during {phase} phase: {finding.name}",
                "evidence": finding.evidence,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "timestamp": finding.timestamp,
                "context": {
                    "phase": phase,
                    "finding_type": finding.type,
                    "tool_used": finding.tool
                }
            }
            
            # Add lesson to results
            lessons.append(lesson)
            
            # Log lesson decision
            log_lesson_decision(
                decision=f"Lesson generated: {finding.type} in {phase}",
                finding_type=finding.type,
                severity=finding.severity,
                scan_id=scan_id,
                phase=phase
            )
            
        except Exception as e:
            self.logger.error(f"Error generating lesson from finding: {e}")
        
        return lessons


# Global instance for use throughout the application
findings_to_skills_connector = FindingsToSkillsConnector()


def process_findings_to_skills(findings: List[Dict], tool_name: str, phase: str, scan_id: str):
    """
    Process findings and connect them to skills and lessons
    """
    return findings_to_skills_connector.process_findings(findings, tool_name, phase, scan_id)