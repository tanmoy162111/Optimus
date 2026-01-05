#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗                 ║
║    ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝                 ║
║    ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗                 ║
║    ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║                 ║
║    ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║                 ║
║     ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝                 ║
║                                                                               ║
║                    NEWBIE TO PRO TRAINING SYSTEM                             ║
║                         10-12 Hour Curriculum                                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

A comprehensive training program that takes the agent from beginner to expert level.

TRAINING CURRICULUM:
═══════════════════

LEVEL 1: FUNDAMENTALS (Hours 1-2)
  - Basic reconnaissance techniques
  - Understanding tool outputs
  - Simple vulnerability detection
  - Parser foundation training

LEVEL 2: INTERMEDIATE (Hours 3-4)
  - Advanced enumeration
  - Multi-tool correlation
  - Basic exploitation
  - Command optimization

LEVEL 3: ADVANCED (Hours 5-7)
  - Chain attack execution
  - Adaptive tool selection
  - Complex vulnerability chains
  - Evasion techniques

LEVEL 4: EXPERT (Hours 8-10)
  - Zero-day pattern recognition
  - Custom exploit generation
  - Multi-stage attacks
  - Post-exploitation mastery

LEVEL 5: MASTERY (Hours 11-12)
  - Full autonomous operation
  - Strategy optimization
  - Edge case handling
  - Final evaluation

FEATURES:
═════════
- Progressive difficulty scaling
- Curriculum-based learning with prerequisites
- Skill assessment and adaptation
- Spaced repetition for retention
- Challenge scenarios and CTF-style problems
- Performance benchmarking
- Weakness identification and targeted practice
- Real-world scenario simulation
"""

import os
import sys
import json
import time
import random
import logging
import hashlib
import threading
import traceback
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import statistics

# Import standardized state schema
try:
    from inference.state_schema import ensure_scan_state
except ImportError:
    # Fallback when running from backend directory directly
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from inference.state_schema import ensure_scan_state

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup logging
log_dir = Path('training_output/newbie_to_pro')
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_dir / f'training_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger('NewbieToPro')


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS AND DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class SkillLevel(Enum):
    """Agent skill levels"""
    NEWBIE = 1
    BEGINNER = 2
    INTERMEDIATE = 3
    ADVANCED = 4
    EXPERT = 5
    MASTER = 6


class TrainingPhase(Enum):
    """Training curriculum phases"""
    FUNDAMENTALS = "fundamentals"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    MASTERY = "mastery"


class SkillCategory(Enum):
    """Skill categories to train"""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CHAIN_ATTACKS = "chain_attacks"
    EVASION = "evasion"
    REPORTING = "reporting"


@dataclass
class Skill:
    """Individual skill tracking"""
    name: str
    category: SkillCategory
    level: float = 0.0  # 0-100
    experience: int = 0
    successes: int = 0
    failures: int = 0
    last_practiced: Optional[str] = None
    
    def practice(self, success: bool, difficulty: float = 1.0):
        """Record practice session"""
        self.experience += int(10 * difficulty)
        if success:
            self.successes += 1
            self.level = min(100, self.level + (5 * difficulty * (1 - self.level/100)))
        else:
            self.failures += 1
            self.level = max(0, self.level - 1)
        self.last_practiced = datetime.now().isoformat()
    
    @property
    def success_rate(self) -> float:
        total = self.successes + self.failures
        return self.successes / total if total > 0 else 0.0


@dataclass
class AgentProfile:
    """Agent's learning profile"""
    agent_id: str
    created_at: str
    current_level: SkillLevel = SkillLevel.NEWBIE
    total_training_hours: float = 0.0
    skills: Dict[str, Skill] = field(default_factory=dict)
    achievements: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    
    # Learning metrics
    total_episodes: int = 0
    total_findings: int = 0
    total_shells: int = 0
    total_chains_completed: int = 0
    
    # Performance history
    performance_history: List[Dict] = field(default_factory=list)
    
    def get_skill(self, skill_name: str) -> Skill:
        if skill_name not in self.skills:
            # Determine category from skill name
            category = SkillCategory.RECONNAISSANCE
            for cat in SkillCategory:
                if cat.value in skill_name.lower():
                    category = cat
                    break
            self.skills[skill_name] = Skill(name=skill_name, category=category)
        return self.skills[skill_name]
    
    def update_level(self):
        """Update overall skill level based on skills"""
        if not self.skills:
            return
        
        avg_level = statistics.mean(s.level for s in self.skills.values())
        
        if avg_level >= 90:
            self.current_level = SkillLevel.MASTER
        elif avg_level >= 75:
            self.current_level = SkillLevel.EXPERT
        elif avg_level >= 55:
            self.current_level = SkillLevel.ADVANCED
        elif avg_level >= 35:
            self.current_level = SkillLevel.INTERMEDIATE
        elif avg_level >= 15:
            self.current_level = SkillLevel.BEGINNER
        else:
            self.current_level = SkillLevel.NEWBIE
    
    def identify_weaknesses(self):
        """Identify skills that need more practice"""
        self.weaknesses = [
            s.name for s in self.skills.values()
            if s.level < 40 or s.success_rate < 0.4
        ]
        self.strengths = [
            s.name for s in self.skills.values()
            if s.level >= 70 and s.success_rate >= 0.7
        ]


@dataclass
class Challenge:
    """Training challenge/scenario"""
    challenge_id: str
    name: str
    description: str
    difficulty: float  # 1-10
    required_skills: List[str]
    target_config: Dict[str, Any]
    success_criteria: Dict[str, Any]
    hints: List[str]
    max_time_minutes: int
    reward_multiplier: float = 1.0
    
    # Results
    attempts: int = 0
    completions: int = 0
    best_time: Optional[float] = None
    best_score: Optional[float] = None


@dataclass
class LessonPlan:
    """Structured lesson plan"""
    lesson_id: str
    title: str
    phase: TrainingPhase
    objectives: List[str]
    skills_trained: List[str]
    duration_minutes: int
    exercises: List[Dict[str, Any]]
    assessment: Dict[str, Any]
    prerequisites: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# CURRICULUM DEFINITION
# ═══════════════════════════════════════════════════════════════════════════════

class Curriculum:
    """Complete training curriculum"""
    
    @staticmethod
    def get_fundamentals_lessons() -> List[LessonPlan]:
        """Level 1: Fundamentals (Hours 1-2)"""
        return [
            LessonPlan(
                lesson_id="F1",
                title="Network Reconnaissance Basics",
                phase=TrainingPhase.FUNDAMENTALS,
                objectives=[
                    "Understand network scanning fundamentals",
                    "Learn to use nmap effectively",
                    "Identify open ports and services",
                ],
                skills_trained=["nmap_basic", "port_scanning", "service_detection"],
                duration_minutes=30,
                exercises=[
                    {"type": "tool_mastery", "tool": "nmap", "variations": 5},
                    {"type": "output_parsing", "tool": "nmap", "samples": 10},
                    {"type": "target_practice", "focus": "port_discovery"},
                ],
                assessment={"min_ports_found": 5, "accuracy": 0.8}
            ),
            LessonPlan(
                lesson_id="F2",
                title="Web Application Fingerprinting",
                phase=TrainingPhase.FUNDAMENTALS,
                objectives=[
                    "Identify web technologies",
                    "Detect CMS platforms",
                    "Recognize WAF presence",
                ],
                skills_trained=["whatweb", "wafw00f", "tech_detection"],
                duration_minutes=30,
                exercises=[
                    {"type": "tool_mastery", "tool": "whatweb", "variations": 5},
                    {"type": "tool_mastery", "tool": "wafw00f", "variations": 3},
                    {"type": "correlation", "tools": ["whatweb", "nmap"]},
                ],
                assessment={"technologies_identified": 3, "accuracy": 0.7}
            ),
            LessonPlan(
                lesson_id="F3",
                title="Directory and File Discovery",
                phase=TrainingPhase.FUNDAMENTALS,
                objectives=[
                    "Discover hidden directories",
                    "Find sensitive files",
                    "Understand wordlist selection",
                ],
                skills_trained=["gobuster", "ffuf", "dirbusting"],
                duration_minutes=30,
                exercises=[
                    {"type": "tool_mastery", "tool": "gobuster", "variations": 5},
                    {"type": "tool_mastery", "tool": "ffuf", "variations": 5},
                    {"type": "wordlist_optimization", "target_types": ["web", "api"]},
                ],
                assessment={"directories_found": 10, "sensitive_files": 2}
            ),
            LessonPlan(
                lesson_id="F4",
                title="Basic Vulnerability Scanning",
                phase=TrainingPhase.FUNDAMENTALS,
                objectives=[
                    "Run automated vulnerability scans",
                    "Interpret scan results",
                    "Prioritize findings",
                ],
                skills_trained=["nikto", "nuclei_basic", "vuln_prioritization"],
                duration_minutes=30,
                exercises=[
                    {"type": "tool_mastery", "tool": "nikto", "variations": 3},
                    {"type": "tool_mastery", "tool": "nuclei", "variations": 5},
                    {"type": "finding_analysis", "count": 10},
                ],
                assessment={"vulns_found": 3, "false_positive_rate": 0.3}
            ),
        ]
    
    @staticmethod
    def get_intermediate_lessons() -> List[LessonPlan]:
        """Level 2: Intermediate (Hours 3-4)"""
        return [
            LessonPlan(
                lesson_id="I1",
                title="Advanced Enumeration Techniques",
                phase=TrainingPhase.INTERMEDIATE,
                objectives=[
                    "Deep dive enumeration",
                    "API endpoint discovery",
                    "Parameter fuzzing",
                ],
                skills_trained=["api_enum", "param_fuzzing", "deep_enum"],
                duration_minutes=40,
                prerequisites=["F1", "F2", "F3"],
                exercises=[
                    {"type": "api_discovery", "techniques": ["swagger", "graphql", "rest"]},
                    {"type": "param_fuzzing", "tool": "arjun", "variations": 5},
                    {"type": "combined_enum", "tools": ["ffuf", "gobuster", "feroxbuster"]},
                ],
                assessment={"endpoints_found": 15, "params_found": 5}
            ),
            LessonPlan(
                lesson_id="I2",
                title="SQL Injection Detection & Exploitation",
                phase=TrainingPhase.INTERMEDIATE,
                objectives=[
                    "Detect SQL injection vulnerabilities",
                    "Use sqlmap effectively",
                    "Extract database information",
                ],
                skills_trained=["sqli_detection", "sqlmap", "db_extraction"],
                duration_minutes=45,
                prerequisites=["F4"],
                exercises=[
                    {"type": "vuln_detection", "vuln_type": "sqli", "samples": 10},
                    {"type": "tool_mastery", "tool": "sqlmap", "variations": 10},
                    {"type": "exploitation", "vuln_type": "sqli", "depth": "full"},
                ],
                assessment={"sqli_found": 2, "db_extracted": True}
            ),
            LessonPlan(
                lesson_id="I3",
                title="XSS Detection & Exploitation",
                phase=TrainingPhase.INTERMEDIATE,
                objectives=[
                    "Identify XSS vulnerabilities",
                    "Craft effective payloads",
                    "Understand context-based exploitation",
                ],
                skills_trained=["xss_detection", "dalfox", "payload_crafting"],
                duration_minutes=40,
                prerequisites=["F4"],
                exercises=[
                    {"type": "vuln_detection", "vuln_type": "xss", "samples": 10},
                    {"type": "tool_mastery", "tool": "dalfox", "variations": 8},
                    {"type": "payload_crafting", "contexts": ["html", "js", "attr"]},
                ],
                assessment={"xss_found": 3, "contexts_exploited": 2}
            ),
            LessonPlan(
                lesson_id="I4",
                title="Authentication Testing",
                phase=TrainingPhase.INTERMEDIATE,
                objectives=[
                    "Test authentication mechanisms",
                    "Perform credential attacks",
                    "Identify auth bypasses",
                ],
                skills_trained=["auth_testing", "hydra", "brute_force"],
                duration_minutes=35,
                prerequisites=["F1"],
                exercises=[
                    {"type": "auth_analysis", "mechanisms": ["basic", "form", "jwt"]},
                    {"type": "tool_mastery", "tool": "hydra", "variations": 5},
                    {"type": "bypass_techniques", "count": 5},
                ],
                assessment={"creds_found": 1, "bypasses_found": 1}
            ),
        ]
    
    @staticmethod
    def get_advanced_lessons() -> List[LessonPlan]:
        """Level 3: Advanced (Hours 5-7)"""
        return [
            LessonPlan(
                lesson_id="A1",
                title="Chain Attack: SQLi to Shell",
                phase=TrainingPhase.ADVANCED,
                objectives=[
                    "Chain SQL injection to file write",
                    "Upload webshell via SQLi",
                    "Obtain reverse shell",
                ],
                skills_trained=["sqli_chain", "webshell_upload", "reverse_shell"],
                duration_minutes=60,
                prerequisites=["I2"],
                exercises=[
                    {"type": "chain_attack", "chain": "sqli_to_shell", "attempts": 5},
                    {"type": "webshell_techniques", "types": ["php", "asp", "jsp"]},
                    {"type": "shell_stabilization", "techniques": 3},
                ],
                assessment={"chain_completed": True, "shell_obtained": True}
            ),
            LessonPlan(
                lesson_id="A2",
                title="Chain Attack: LFI/RFI to RCE",
                phase=TrainingPhase.ADVANCED,
                objectives=[
                    "Exploit file inclusion vulnerabilities",
                    "Log poisoning techniques",
                    "Achieve code execution",
                ],
                skills_trained=["lfi_exploitation", "log_poisoning", "rfi_rce"],
                duration_minutes=55,
                prerequisites=["I1", "F4"],
                exercises=[
                    {"type": "chain_attack", "chain": "lfi_to_rce", "attempts": 5},
                    {"type": "filter_bypass", "techniques": 8},
                    {"type": "log_poisoning", "services": ["apache", "ssh", "mail"]},
                ],
                assessment={"chain_completed": True, "rce_achieved": True}
            ),
            LessonPlan(
                lesson_id="A3",
                title="Command Injection Mastery",
                phase=TrainingPhase.ADVANCED,
                objectives=[
                    "Detect command injection points",
                    "Bypass filters and WAFs",
                    "Establish persistent access",
                ],
                skills_trained=["cmdi_detection", "commix", "filter_bypass"],
                duration_minutes=50,
                prerequisites=["I1"],
                exercises=[
                    {"type": "vuln_detection", "vuln_type": "cmdi", "samples": 10},
                    {"type": "tool_mastery", "tool": "commix", "variations": 10},
                    {"type": "evasion", "waf_types": ["modsec", "cloudflare"]},
                ],
                assessment={"cmdi_found": 2, "bypass_success": 0.6}
            ),
            LessonPlan(
                lesson_id="A4",
                title="SSRF and XXE Exploitation",
                phase=TrainingPhase.ADVANCED,
                objectives=[
                    "Exploit SSRF vulnerabilities",
                    "Access internal services",
                    "XXE for data exfiltration",
                ],
                skills_trained=["ssrf_exploitation", "xxe_exploitation", "internal_recon"],
                duration_minutes=50,
                prerequisites=["I1"],
                exercises=[
                    {"type": "vuln_detection", "vuln_type": "ssrf", "samples": 8},
                    {"type": "vuln_detection", "vuln_type": "xxe", "samples": 8},
                    {"type": "cloud_metadata", "providers": ["aws", "gcp", "azure"]},
                ],
                assessment={"ssrf_exploited": True, "internal_access": True}
            ),
            LessonPlan(
                lesson_id="A5",
                title="Privilege Escalation Fundamentals",
                phase=TrainingPhase.ADVANCED,
                objectives=[
                    "Linux privilege escalation",
                    "SUID/capability abuse",
                    "Kernel exploit identification",
                ],
                skills_trained=["linux_privesc", "linpeas", "kernel_exploits"],
                duration_minutes=60,
                prerequisites=["A1", "A2"],
                exercises=[
                    {"type": "privesc_enum", "os": "linux", "depth": "full"},
                    {"type": "tool_mastery", "tool": "linpeas", "variations": 5},
                    {"type": "exploit_selection", "vectors": ["suid", "sudo", "cron", "kernel"]},
                ],
                assessment={"privesc_vectors": 3, "root_obtained": True}
            ),
        ]
    
    @staticmethod
    def get_expert_lessons() -> List[LessonPlan]:
        """Level 4: Expert (Hours 8-10)"""
        return [
            LessonPlan(
                lesson_id="E1",
                title="Multi-Stage Attack Orchestration",
                phase=TrainingPhase.EXPERT,
                objectives=[
                    "Plan complex multi-stage attacks",
                    "Maintain persistence across stages",
                    "Pivot through networks",
                ],
                skills_trained=["attack_planning", "pivoting", "persistence"],
                duration_minutes=75,
                prerequisites=["A1", "A2", "A5"],
                exercises=[
                    {"type": "multi_stage", "stages": 5, "complexity": "high"},
                    {"type": "pivoting", "hops": 2},
                    {"type": "persistence", "techniques": ["cron", "ssh_key", "backdoor"]},
                ],
                assessment={"stages_completed": 5, "pivot_success": True}
            ),
            LessonPlan(
                lesson_id="E2",
                title="Custom Exploit Development",
                phase=TrainingPhase.EXPERT,
                objectives=[
                    "Analyze vulnerabilities for exploitation",
                    "Craft custom payloads",
                    "Adapt exploits to environment",
                ],
                skills_trained=["exploit_dev", "payload_generation", "exploit_adaptation"],
                duration_minutes=70,
                prerequisites=["A3", "A4"],
                exercises=[
                    {"type": "exploit_analysis", "cves": 5},
                    {"type": "payload_generation", "types": ["reverse", "bind", "staged"]},
                    {"type": "exploit_modification", "scenarios": 5},
                ],
                assessment={"custom_exploits": 2, "success_rate": 0.6}
            ),
            LessonPlan(
                lesson_id="E3",
                title="Evasion and Anti-Detection",
                phase=TrainingPhase.EXPERT,
                objectives=[
                    "Evade security controls",
                    "Obfuscate attack traffic",
                    "Clean forensic artifacts",
                ],
                skills_trained=["waf_bypass", "ids_evasion", "anti_forensics"],
                duration_minutes=60,
                prerequisites=["A3"],
                exercises=[
                    {"type": "evasion", "controls": ["waf", "ids", "av"]},
                    {"type": "obfuscation", "techniques": ["encoding", "fragmentation", "timing"]},
                    {"type": "cleanup", "artifacts": ["logs", "history", "timestamps"]},
                ],
                assessment={"evasion_rate": 0.7, "detection_avoided": True}
            ),
            LessonPlan(
                lesson_id="E4",
                title="Credential Harvesting & Lateral Movement",
                phase=TrainingPhase.EXPERT,
                objectives=[
                    "Extract credentials from systems",
                    "Perform lateral movement",
                    "Escalate across domain",
                ],
                skills_trained=["cred_harvest", "lateral_movement", "domain_escalation"],
                duration_minutes=65,
                prerequisites=["A5", "E1"],
                exercises=[
                    {"type": "credential_extraction", "sources": ["memory", "files", "registry"]},
                    {"type": "lateral_movement", "techniques": ["psexec", "wmi", "ssh"]},
                    {"type": "domain_attack", "attacks": ["kerberoast", "asreproast"]},
                ],
                assessment={"creds_harvested": 5, "systems_compromised": 3}
            ),
        ]
    
    @staticmethod
    def get_mastery_lessons() -> List[LessonPlan]:
        """Level 5: Mastery (Hours 11-12)"""
        return [
            LessonPlan(
                lesson_id="M1",
                title="Full Autonomous Operation",
                phase=TrainingPhase.MASTERY,
                objectives=[
                    "Execute complete pentest autonomously",
                    "Make strategic decisions",
                    "Adapt to unexpected situations",
                ],
                skills_trained=["autonomous_operation", "strategic_thinking", "adaptation"],
                duration_minutes=90,
                prerequisites=["E1", "E2", "E3", "E4"],
                exercises=[
                    {"type": "full_pentest", "autonomy": "complete", "targets": 2},
                    {"type": "scenario_adaptation", "scenarios": 5},
                    {"type": "time_pressure", "time_limit": 30},
                ],
                assessment={"autonomous_success": 0.8, "findings_quality": 0.9}
            ),
            LessonPlan(
                lesson_id="M2",
                title="Final Evaluation & Certification",
                phase=TrainingPhase.MASTERY,
                objectives=[
                    "Demonstrate mastery of all skills",
                    "Complete CTF-style challenges",
                    "Generate professional report",
                ],
                skills_trained=["all_skills", "ctf_solving", "professional_reporting"],
                duration_minutes=60,
                prerequisites=["M1"],
                exercises=[
                    {"type": "comprehensive_eval", "categories": "all"},
                    {"type": "ctf_challenge", "difficulty": "hard", "count": 3},
                    {"type": "report_generation", "quality": "professional"},
                ],
                assessment={"overall_score": 0.85, "certification": True}
            ),
        ]
    
    @classmethod
    def get_all_lessons(cls) -> List[LessonPlan]:
        """Get complete curriculum"""
        return (
            cls.get_fundamentals_lessons() +
            cls.get_intermediate_lessons() +
            cls.get_advanced_lessons() +
            cls.get_expert_lessons() +
            cls.get_mastery_lessons()
        )


# ═══════════════════════════════════════════════════════════════════════════════
# CHALLENGE SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

class ChallengeLibrary:
    """Library of training challenges"""
    
    @staticmethod
    def get_challenges() -> List[Challenge]:
        return [
            # Beginner Challenges
            Challenge(
                challenge_id="C001",
                name="Port Scanner Challenge",
                description="Find all open ports on the target within 5 minutes",
                difficulty=2.0,
                required_skills=["nmap_basic"],
                target_config={"type": "network"},
                success_criteria={"ports_found": 10, "accuracy": 0.9},
                hints=["Try different scan types", "Consider UDP"],
                max_time_minutes=5,
                reward_multiplier=1.0
            ),
            Challenge(
                challenge_id="C002",
                name="Hidden Directory Hunt",
                description="Find 5 hidden directories including admin panel",
                difficulty=3.0,
                required_skills=["gobuster", "ffuf"],
                target_config={"type": "web"},
                success_criteria={"directories": 5, "admin_found": True},
                hints=["Try multiple wordlists", "Check for backup files"],
                max_time_minutes=10,
                reward_multiplier=1.2
            ),
            
            # Intermediate Challenges
            Challenge(
                challenge_id="C003",
                name="SQL Injection Gauntlet",
                description="Find and exploit SQL injection to dump users table",
                difficulty=5.0,
                required_skills=["sqli_detection", "sqlmap"],
                target_config={"type": "web", "vuln": "sqli"},
                success_criteria={"sqli_found": True, "data_extracted": True},
                hints=["Check all parameters", "Try different injection types"],
                max_time_minutes=20,
                reward_multiplier=1.5
            ),
            Challenge(
                challenge_id="C004",
                name="XSS Cookie Stealer",
                description="Find XSS and craft payload to steal admin cookie",
                difficulty=5.5,
                required_skills=["xss_detection", "payload_crafting"],
                target_config={"type": "web", "vuln": "xss"},
                success_criteria={"xss_found": True, "cookie_stolen": True},
                hints=["Check reflected and stored", "Bypass filters"],
                max_time_minutes=15,
                reward_multiplier=1.5
            ),
            
            # Advanced Challenges
            Challenge(
                challenge_id="C005",
                name="SQLi to Shell",
                description="Chain SQL injection to obtain shell access",
                difficulty=7.0,
                required_skills=["sqli_chain", "webshell_upload"],
                target_config={"type": "web", "vuln": "sqli"},
                success_criteria={"shell_obtained": True},
                hints=["Use INTO OUTFILE", "Check file permissions"],
                max_time_minutes=30,
                reward_multiplier=2.0
            ),
            Challenge(
                challenge_id="C006",
                name="LFI to RCE",
                description="Exploit LFI with log poisoning to achieve RCE",
                difficulty=7.5,
                required_skills=["lfi_exploitation", "log_poisoning"],
                target_config={"type": "web", "vuln": "lfi"},
                success_criteria={"rce_achieved": True},
                hints=["Check /var/log/", "Poison User-Agent"],
                max_time_minutes=25,
                reward_multiplier=2.0
            ),
            
            # Expert Challenges
            Challenge(
                challenge_id="C007",
                name="Privilege Escalation Race",
                description="Escalate from www-data to root in minimum steps",
                difficulty=8.0,
                required_skills=["linux_privesc", "kernel_exploits"],
                target_config={"type": "linux", "access": "user"},
                success_criteria={"root_obtained": True, "steps": 3},
                hints=["Check SUID binaries", "Look for cron jobs"],
                max_time_minutes=20,
                reward_multiplier=2.5
            ),
            Challenge(
                challenge_id="C008",
                name="WAF Bypass Master",
                description="Exploit vulnerability while bypassing ModSecurity WAF",
                difficulty=8.5,
                required_skills=["waf_bypass", "payload_obfuscation"],
                target_config={"type": "web", "waf": "modsec"},
                success_criteria={"bypass_success": True, "exploit_success": True},
                hints=["Try encoding", "Use HPP"],
                max_time_minutes=30,
                reward_multiplier=2.5
            ),
            
            # Master Challenges
            Challenge(
                challenge_id="C009",
                name="Full Compromise",
                description="Complete autonomous pentest: recon to root in 45 minutes",
                difficulty=9.5,
                required_skills=["autonomous_operation"],
                target_config={"type": "full", "difficulty": "hard"},
                success_criteria={"root_obtained": True, "time_limit": True},
                hints=["Plan before attacking", "Document everything"],
                max_time_minutes=45,
                reward_multiplier=3.0
            ),
            Challenge(
                challenge_id="C010",
                name="Multi-Target Campaign",
                description="Compromise 3 interconnected targets",
                difficulty=10.0,
                required_skills=["pivoting", "lateral_movement"],
                target_config={"type": "network", "targets": 3},
                success_criteria={"targets_compromised": 3, "pivoting_used": True},
                hints=["Map the network first", "Use compromised hosts"],
                max_time_minutes=60,
                reward_multiplier=4.0
            ),
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# COMPONENT MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class ComponentManager:
    """Manages all training components"""
    
    def __init__(self):
        self.components = {}
        self.initialized = False
    
    def initialize(self) -> Dict[str, bool]:
        """Initialize all components"""
        status = {}
        
        # Core components
        components_to_init = [
            ('tool_manager', 'inference.tool_manager', 'ToolManager', {}),
            ('intelligent_selector', 'training_environment.selector_adapter', 'get_phase_aware_selector_adapter', {}),
            ('evolving_parser', 'inference.evolving_parser', 'get_evolving_parser', {}),
            ('evolving_commands', 'inference.evolving_commands', 'get_evolving_command_generator', {}),
            ('exploit_chainer', 'exploitation.exploit_chainer', 'ExploitChainer', {'needs_executor': True}),
            ('web_intel', 'intelligence.web_intelligence', 'get_web_intelligence', {}),
            ('rl_agent', 'training.deep_rl_agent', 'DeepRLAgent', {'args': {'state_dim': 128, 'num_actions': 50}}),
            ('state_encoder', 'training.enhanced_state_encoder', 'get_state_encoder', {}),
            ('reward_calculator', 'training.reward_calculator', 'RewardCalculator', {}),
            ('report_generator', 'reporting.professional_report', 'get_professional_report_generator', {}),
        ]
        
        for name, module_path, class_name, options in components_to_init:
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)
                
                if options.get('needs_executor'):
                    # Special handling for exploit chainer
                    from exploitation.exploit_executor import ExploitExecutor
                    executor = ExploitExecutor()
                    self.components[name] = cls(executor)
                elif name == 'tool_manager':
                    # Special handling for ToolManager - pass None for socketio
                    self.components[name] = cls(socketio=None)
                elif options.get('args'):
                    try:
                        self.components[name] = cls(**options['args'])
                    except TypeError as e:
                        if 'StateEncoder' in str(e):
                            # Fallback for StateEncoder import issue
                            try:
                                from training.enhanced_state_encoder import StateEncoder
                            except ImportError:
                                logger.warning("StateEncoder not found, using fallback")
                                import numpy as np
                                class StateEncoder:
                                    def encode(self, scan_state):
                                        return np.zeros(128)
                            self.components[name] = StateEncoder()
                        else:
                            raise
                elif callable(cls) and not isinstance(cls, type):
                    # It's a factory function
                    self.components[name] = cls()
                else:
                    self.components[name] = cls()
                
                # Try to load RL agent
                if name == 'rl_agent':
                    try:
                        self.components[name].load()
                    except:
                        pass
                
                status[name] = True
                logger.info(f"  OK {name}")
            except Exception as e:
                status[name] = False
                logger.warning(f"  FAILED {name}: {e}")
        
        self.initialized = True
        return status
    
    def get(self, name: str) -> Optional[Any]:
        return self.components.get(name)


# ═══════════════════════════════════════════════════════════════════════════════
# TRAINING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class NewbieToProTrainer:
    """Main training orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.targets = config.get('targets', [])
        self.total_hours = config.get('total_hours', 12)
        self.output_dir = Path(config.get('output_dir', 'training_output/newbie_to_pro'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.components = ComponentManager()
        
        # Initialize authorized targets
        self.authorized_targets = self._load_authorized_targets()
        
        # Validate that all configured targets are authorized
        self._validate_targets()
        
        # Initialize curriculum
        self.curriculum = Curriculum.get_all_lessons()
        self.challenges = ChallengeLibrary.get_challenges()
        
        # Agent profile
        self.agent = AgentProfile(
            agent_id=hashlib.md5(datetime.now().isoformat().encode()).hexdigest()[:8],
            created_at=datetime.now().isoformat()
        )
        
        # Training state
        self.current_lesson_idx = 0
        self.completed_lessons = []
        self.completed_challenges = []
        self.training_start = None
        self.total_reward = 0.0
        
        # Phase tracking
        self.current_phase_idx = 0
        self.pentest_phases = [
            'reconnaissance',
            'enumeration',
            'vulnerability_analysis',
            'exploitation',
            'post_exploitation'
        ]
        
        # Initialize target normalizer
        try:
            from inference.target_normalizer import get_target_normalizer
            self.target_normalizer = get_target_normalizer()
        except ImportError:
            self.target_normalizer = None
            logger.warning("TargetNormalizer not available")
        
        # Metrics
        self.metrics = {
            'lessons_completed': 0,
            'challenges_completed': 0,
            'skills_learned': 0,
            'total_findings': 0,
            'total_shells': 0,
            'total_chains': 0,
            'rl_updates': 0,
        }
    
    def initialize(self) -> bool:
        """Initialize the trainer"""
        self._print_banner()
        
        print("\n[Initializing Components]")
        status = self.components.initialize()
        
        available = sum(1 for s in status.values() if s)
        total = len(status)
        
        print(f"\nComponents: {available}/{total} available")
        
        if not status.get('tool_manager'):
            logger.error("Tool Manager is required!")
            return False
        
        return True
    
    def _print_banner(self):
        """Print training banner"""
        banner = """
+=================================================================================+
|                                                                               |
|     ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗                 |
|    ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝                 |
|    ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗                 |
|    ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║                 |
|    ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║                 |
|     ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝                 |
|                                                                               |
|                    NEWBIE TO PRO TRAINING SYSTEM                              |
|                                                                               |
|                     Duration: """ + f"{self.total_hours} hours".ljust(15) + """                          |
|                     Targets: """ + f"{len(self.targets)}".ljust(15) + """                           |
|                     Lessons: """ + f"{len(self.curriculum)}".ljust(15) + """                           |
|                     Challenges: """ + f"{len(self.challenges)}".ljust(15) + """                        |
|                                                                               |
+=================================================================================+
        """
        try:
            print(banner)
        except UnicodeEncodeError:
            # Fallback to ASCII-only banner if Unicode fails
            print(f"NEWBIE TO PRO TRAINING SYSTEM")
            print(f"Duration: {self.total_hours} hours")
            print(f"Targets: {len(self.targets)}")
            print(f"Lessons: {len(self.curriculum)}")
            print(f"Challenges: {len(self.challenges)}")
            print("=" * 50)
    
    def run_training(self) -> Dict[str, Any]:
        """Run the complete training program"""
        self.training_start = datetime.now()
        end_time = self.training_start + timedelta(hours=self.total_hours)
        
        print(f"\n{'='*70}")
        print(f"TRAINING STARTED: {self.training_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"EXPECTED END: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        try:
            # Phase 1: Fundamentals (Hours 1-2)
            self._run_training_phase(TrainingPhase.FUNDAMENTALS, hours=2)
            
            # Phase 2: Intermediate (Hours 3-4)
            self._run_training_phase(TrainingPhase.INTERMEDIATE, hours=2)
            
            # Phase 3: Advanced (Hours 5-7)
            self._run_training_phase(TrainingPhase.ADVANCED, hours=3)
            
            # Phase 4: Expert (Hours 8-10)
            self._run_training_phase(TrainingPhase.EXPERT, hours=3)
            
            # Phase 5: Mastery (Hours 11-12)
            self._run_training_phase(TrainingPhase.MASTERY, hours=2)
            
        except KeyboardInterrupt:
            print("\n[Training Interrupted]")
            self._save_checkpoint()
        except Exception as e:
            logger.error(f"Training error: {e}")
            traceback.print_exc()
        
        # Generate final report
        return self._generate_final_report()
    
    def _run_training_phase(self, phase: TrainingPhase, hours: float):
        """Run a training phase"""
        phase_start = datetime.now()
        phase_end = phase_start + timedelta(hours=hours)
        
        print(f"\n{'='*70}")
        print(f"PHASE: {phase.value.upper()}")
        print(f"Duration: {hours} hours")
        print(f"{'='*70}\n")
        
        # Get lessons for this phase
        phase_lessons = [l for l in self.curriculum if l.phase == phase]
        
        # Run lessons
        for lesson in phase_lessons:
            if datetime.now() >= phase_end:
                logger.info(f"Phase time limit reached")
                break
            
            self._run_lesson(lesson)
        
        # Run challenges appropriate for this level
        difficulty_range = {
            TrainingPhase.FUNDAMENTALS: (1, 3),
            TrainingPhase.INTERMEDIATE: (3, 6),
            TrainingPhase.ADVANCED: (6, 8),
            TrainingPhase.EXPERT: (8, 9.5),
            TrainingPhase.MASTERY: (9, 10),
        }
        
        min_diff, max_diff = difficulty_range.get(phase, (1, 10))
        phase_challenges = [
            c for c in self.challenges 
            if min_diff <= c.difficulty <= max_diff
        ]
        
        # Run some challenges
        for challenge in phase_challenges[:3]:  # Max 3 challenges per phase
            if datetime.now() >= phase_end:
                break
            
            self._run_challenge(challenge)
        
        # Practice weak skills
        self._practice_weak_skills(phase_end)
        
        # Update agent level
        self.agent.update_level()
        self.agent.identify_weaknesses()
        
        # Print phase summary
        self._print_phase_summary(phase)
        
        # Save checkpoint
        self._save_checkpoint()
    
    def _run_lesson(self, lesson: LessonPlan):
        """Run a single lesson"""
        print(f"\n[LESSON] {lesson.title}")
        print(f"   Objectives: {', '.join(lesson.objectives[:2])}...")
        print(f"   Skills: {', '.join(lesson.skills_trained)}")
        print(f"   Duration: {lesson.duration_minutes} minutes\n")
        
        lesson_start = datetime.now()
        lesson_end = lesson_start + timedelta(minutes=lesson.duration_minutes)
        
        # Determine appropriate phase based on lesson
        lesson_phase = 'reconnaissance'  # Default
        if lesson.phase == TrainingPhase.FUNDAMENTALS:
            lesson_phase = 'reconnaissance'
        elif lesson.phase == TrainingPhase.INTERMEDIATE:
            lesson_phase = 'enumeration'
        elif lesson.phase == TrainingPhase.ADVANCED:
            lesson_phase = 'vulnerability_analysis'
        elif lesson.phase == TrainingPhase.EXPERT:
            lesson_phase = 'exploitation'
        elif lesson.phase == TrainingPhase.MASTERY:
            lesson_phase = 'post_exploitation'
        
        # Initialize scan state for the lesson
        target = random.choice(self.targets) if self.targets else {'url': 'http://localhost'}
        target_url = target.get('url') or target.get('ip')
        
        initial_scan_state = {
            'scan_id': f"lesson_{lesson.lesson_id}_{datetime.now().strftime('%H%M%S')}",
            'target': target_url,
            'phase': lesson_phase,
            'findings': [],
            'tools_executed': [],
            'target_type': 'web',  # Default
            'discovered_technologies': [],
        }
        
        # Apply standardized schema
        scan_state = ensure_scan_state(initial_scan_state)
        
        # Run exercises
        for exercise in lesson.exercises:
            if datetime.now() >= lesson_end:
                break
            
            result = self._run_exercise_with_state(exercise, lesson, scan_state)
            
            # Update skills
            for skill_name in lesson.skills_trained:
                skill = self.agent.get_skill(skill_name)
                skill.practice(result.get('success', False), difficulty=1.0)
            
            # Check phase advancement after each exercise
            intelligent_selector = self.components.get('intelligent_selector')
            if intelligent_selector and self.should_advance_phase(scan_state):
                new_phase = self.advance_phase()
                if new_phase:
                    scan_state['phase'] = new_phase
                    logger.info(f"[Lesson Phase Advancement] Updated scan_state phase to: {new_phase}")
        
        # Run assessment
        assessment_result = self._run_assessment(lesson)
        
        if assessment_result.get('passed', False):
            print(f"   ✓ Lesson PASSED")
            self.completed_lessons.append(lesson.lesson_id)
            self.metrics['lessons_completed'] += 1
        else:
            print(f"   X Lesson needs more practice")
    
    def _run_exercise(self, exercise: Dict, lesson: LessonPlan) -> Dict:
        """Run a single exercise"""
        exercise_type = exercise.get('type')
        result = {'success': False, 'findings': 0, 'reward': 0}
        
        target = random.choice(self.targets) if self.targets else {'url': 'http://localhost'}
        target_url = target.get('url') or target.get('ip')
        
        tool_manager = self.components.get('tool_manager')
        intelligent_selector = self.components.get('intelligent_selector')
        evolving_parser = self.components.get('evolving_parser')
        
        if not tool_manager:
            return result
        
        # Track attempted command signatures to prevent retry spam
        attempted_signatures = set()
        
        # Determine appropriate phase based on lesson
        lesson_phase = 'reconnaissance'  # Default
        if lesson.phase == TrainingPhase.FUNDAMENTALS:
            lesson_phase = 'reconnaissance'
        elif lesson.phase == TrainingPhase.INTERMEDIATE:
            lesson_phase = 'enumeration'
        elif lesson.phase == TrainingPhase.ADVANCED:
            lesson_phase = 'vulnerability_analysis'
        elif lesson.phase == TrainingPhase.EXPERT:
            lesson_phase = 'exploitation'
        elif lesson.phase == TrainingPhase.MASTERY:
            lesson_phase = 'post_exploitation'
        
        initial_scan_state = {
            'scan_id': f"exercise_{datetime.now().strftime('%H%M%S')}",
            'target': target_url,
            'phase': lesson_phase,
            'findings': [],
            'tools_executed': [],
            'target_type': 'web',  # Default
            'discovered_technologies': [],
        }
        
        # Apply standardized schema
        scan_state = ensure_scan_state(initial_scan_state)
        
        try:
            if exercise_type == 'tool_mastery':
                # Practice using a specific tool
                tool = exercise.get('tool', 'nmap')
                variations = exercise.get('variations', 3)
                
                for i in range(variations):
                    # Get command from intelligent selector or evolving commands
                    if intelligent_selector:
                        recs = intelligent_selector.select_tools(
                            phase=scan_state['phase'], scan_state=scan_state, count=1
                        )
                        if recs and recs[0].tool == tool:
                            args = recs[0].args
                        else:
                            args = '{target}'
                    else:
                        args = '{target}'
                    
                    # Normalize target based on tool type
                    if self.target_normalizer and intelligent_selector:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, tool)
                    else:
                        normalized_target = target_url
                    
                    # Create signature for this attempt to prevent retry spam
                    command_signature = (tool, normalized_target, args.replace('{target}', normalized_target))
                    
                    # Skip if this exact command was already attempted
                    if command_signature in attempted_signatures:
                        print(f"[RetryProtection] Skipping duplicate command: {tool} {normalized_target} with args {args}")
                        continue
                    
                    # Track this attempt
                    attempted_signatures.add(command_signature)
                    
                    # Execute
                    exec_result = tool_manager.execute_tool(
                        tool_name=tool,
                        target=normalized_target,
                        parameters={'args': args.replace('{target}', normalized_target)},
                        scan_id=scan_state['scan_id'],
                        phase=scan_state['phase']
                    )
                    
                    if exec_result:
                        result['success'] = True
                        findings = exec_result.get('findings', [])
                        result['findings'] += len(findings)
                        
                        # Learn from output
                        if evolving_parser and exec_result.get('stdout'):
                            evolving_parser.learn_from_output(
                                tool, exec_result['stdout'], exec_result.get('stderr', '')
                            )
                        
                        # Record execution for intelligent selector learning
                        if intelligent_selector:
                            execution_time = exec_result.get('execution_time', 10.0)  # Default to 10 seconds if not provided
                            success = exec_result.get('success', False)
                            findings_count = len(exec_result.get('findings', []))
                            intelligent_selector.record_execution(tool, success, findings_count, execution_time)
                        
                        # Update skills learned metric when significant findings are made
                        if exec_result.get('findings') and len(exec_result.get('findings', [])) > 0:
                            self.metrics['skills_learned'] += 1
                    
                    time.sleep(1)
            
            elif exercise_type == 'output_parsing':
                # Practice parsing outputs
                tool = exercise.get('tool', 'nmap')
                samples = exercise.get('samples', 5)
                
                # Execute tool and practice parsing
                for _ in range(min(samples, 3)):
                    # Normalize target based on tool type
                    if self.target_normalizer and intelligent_selector:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, tool)
                    else:
                        normalized_target = target_url
                    
                    exec_result = tool_manager.execute_tool(
                        tool_name=tool,
                        target=normalized_target,
                        parameters={},
                        scan_id=scan_state['scan_id'],
                        phase=scan_state['phase']
                    )
                    
                    if exec_result and evolving_parser:
                        parsed = evolving_parser.parse(
                            tool, 
                            exec_result.get('stdout', ''),
                            exec_result.get('stderr', '')
                        )
                        if parsed:
                            result['success'] = True
                            result['findings'] += len(parsed.get('findings', []))
                    
                    time.sleep(0.5)
            
            elif exercise_type == 'chain_attack':
                # Practice chain attacks
                chain_name = exercise.get('chain', 'sqli_to_shell')
                attempts = exercise.get('attempts', 3)
                
                exploit_chainer = self.components.get('exploit_chainer')
                if exploit_chainer:
                    for _ in range(attempts):
                        # Execute chain
                        chain_result = self._execute_chain(chain_name, target_url, scan_state)
                        if chain_result.get('success'):
                            result['success'] = True
                            result['reward'] += 50
                            self.metrics['total_chains'] += 1
                            break
            
            elif exercise_type == 'vuln_detection':
                # Practice detecting specific vulnerability type
                vuln_type = exercise.get('vuln_type', 'xss')
                samples = exercise.get('samples', 5)
                
                # Map vuln type to tools
                vuln_tools = {
                    'sqli': ['sqlmap'],
                    'xss': ['dalfox', 'xsstrike'],
                    'cmdi': ['commix'],
                    'ssrf': ['nuclei'],
                    'xxe': ['nuclei'],
                    'lfi': ['ffuf'],
                }
                
                tools = vuln_tools.get(vuln_type, ['nuclei'])
                
                for tool in tools:
                    # Normalize target based on tool type
                    if self.target_normalizer and intelligent_selector:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, tool)
                    else:
                        normalized_target = target_url
                    
                    exec_result = tool_manager.execute_tool(
                        tool_name=tool,
                        target=normalized_target,
                        parameters={},
                        scan_id=scan_state['scan_id'],
                        phase=scan_state['phase']
                    )
                    
                    if exec_result:
                        findings = exec_result.get('findings', [])
                        relevant = [f for f in findings if vuln_type in f.get('type', '').lower()]
                        if relevant:
                            result['success'] = True
                            result['findings'] += len(relevant)
                    
                    time.sleep(1)
            
            # Calculate reward
            result['reward'] = result['findings'] * 10 + (50 if result['success'] else 0)
            self.total_reward += result['reward']
            self.metrics['total_findings'] += result['findings']
            
            # Update skills learned based on findings
            if result['findings'] > 0:
                self.metrics['skills_learned'] += result['findings']
            
            # Check if we should advance phase based on findings and progress
            if intelligent_selector and self.should_advance_phase(scan_state):
                new_phase = self.advance_phase()
                if new_phase:
                    scan_state['phase'] = new_phase
                    logger.info(f"[Phase Advancement] Updated scan_state phase to: {new_phase}")
        
        except Exception as e:
            logger.debug(f"Exercise error: {e}")
        
        return result
    
    def _run_exercise_with_state(self, exercise: Dict, lesson: LessonPlan, scan_state: Dict) -> Dict:
        """Run a single exercise with shared scan state"""
        exercise_type = exercise.get('type')
        result = {'success': False, 'findings': 0, 'reward': 0}
        
        target_url = scan_state.get('target')
        
        tool_manager = self.components.get('tool_manager')
        intelligent_selector = self.components.get('intelligent_selector')
        evolving_parser = self.components.get('evolving_parser')
        
        if not tool_manager:
            return result
        
        # Track attempted command signatures to prevent retry spam
        attempted_signatures = set()
        
        try:
            if exercise_type == 'tool_mastery':
                # Practice using a specific tool
                tool = exercise.get('tool', 'nmap')
                variations = exercise.get('variations', 3)
                
                for i in range(variations):
                    # Get command from intelligent selector or evolving commands
                    if intelligent_selector:
                        recs = intelligent_selector.select_tools(
                            phase=scan_state['phase'], scan_state=scan_state, count=1
                        )
                        if recs and recs[0].tool == tool:
                            args = recs[0].args
                        else:
                            args = '{target}'
                    else:
                        args = '{target}'
                    
                    # Normalize target based on tool type
                    if self.target_normalizer and intelligent_selector:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, tool)
                    else:
                        normalized_target = target_url
                    
                    # Create signature for this attempt to prevent retry spam
                    command_signature = (tool, normalized_target, args.replace('{target}', normalized_target))
                    
                    # Skip if this exact command was already attempted
                    if command_signature in attempted_signatures:
                        print(f"[RetryProtection] Skipping duplicate command: {tool} {normalized_target} with args {args}")
                        continue
                    
                    # Track this attempt
                    attempted_signatures.add(command_signature)
                    
                    # Execute
                    exec_result = tool_manager.execute_tool(
                        tool_name=tool,
                        target=normalized_target,
                        parameters={'args': args.replace('{target}', normalized_target)},
                        scan_id=scan_state['scan_id'],
                        phase=scan_state['phase']
                    )
                    
                    if exec_result:
                        result['success'] = True
                        findings = exec_result.get('findings', [])
                        result['findings'] += len(findings)
                        
                        # Add findings to scan state
                        scan_state['findings'].extend(findings)
                        scan_state['tools_executed'].append(tool)
                        
                        # Learn from output
                        if evolving_parser and exec_result.get('stdout'):
                            evolving_parser.learn_from_output(
                                tool, exec_result['stdout'], exec_result.get('stderr', '')
                            )
                        
                        # Record execution for intelligent selector learning
                        if intelligent_selector:
                            execution_time = exec_result.get('execution_time', 10.0)  # Default to 10 seconds if not provided
                            success = exec_result.get('success', False)
                            findings_count = len(exec_result.get('findings', []))
                            intelligent_selector.record_execution(tool, success, findings_count, execution_time)
                        
                        # Update skills learned metric when significant findings are made
                        if exec_result.get('findings') and len(exec_result.get('findings', [])) > 0:
                            self.metrics['skills_learned'] += 1
                    
                    time.sleep(1)
            
            elif exercise_type == 'output_parsing':
                # Practice parsing outputs
                tool = exercise.get('tool', 'nmap')
                samples = exercise.get('samples', 5)
                
                # Execute tool and practice parsing
                for _ in range(min(samples, 3)):
                    # Normalize target based on tool type
                    if self.target_normalizer and intelligent_selector:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, tool)
                    else:
                        normalized_target = target_url
                    
                    exec_result = tool_manager.execute_tool(
                        tool_name=tool,
                        target=normalized_target,
                        parameters={},
                        scan_id=scan_state['scan_id'],
                        phase=scan_state['phase']
                    )
                    
                    if exec_result and evolving_parser:
                        parsed = evolving_parser.parse(
                            tool, 
                            exec_result.get('stdout', ''),
                            exec_result.get('stderr', '')
                        )
                        if parsed:
                            result['success'] = True
                            parsed_findings = parsed.get('findings', [])
                            result['findings'] += len(parsed_findings)
                            
                            # Add findings to scan state
                            scan_state['findings'].extend(parsed_findings)
                            scan_state['tools_executed'].append(tool)
                    
                    time.sleep(0.5)
            
            elif exercise_type == 'chain_attack':
                # Practice chain attacks
                chain_name = exercise.get('chain', 'sqli_to_shell')
                attempts = exercise.get('attempts', 3)
                
                exploit_chainer = self.components.get('exploit_chainer')
                if exploit_chainer:
                    for _ in range(attempts):
                        # Execute chain
                        chain_result = self._execute_chain_with_state(chain_name, target_url, scan_state)
                        if chain_result.get('success'):
                            result['success'] = True
                            result['reward'] += 50
                            self.metrics['total_chains'] += 1
                            break
            
            elif exercise_type == 'vuln_detection':
                # Practice detecting specific vulnerability type
                vuln_type = exercise.get('vuln_type', 'xss')
                samples = exercise.get('samples', 5)
                
                # Map vuln type to tools
                vuln_tools = {
                    'sqli': ['sqlmap'],
                    'xss': ['dalfox', 'xsstrike'],
                    'cmdi': ['commix'],
                    'ssrf': ['nuclei'],
                    'xxe': ['nuclei'],
                    'lfi': ['ffuf'],
                }
                
                tools = vuln_tools.get(vuln_type, ['nuclei'])
                
                for tool in tools:
                    # Normalize target based on tool type
                    if self.target_normalizer and intelligent_selector:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, tool)
                    else:
                        normalized_target = target_url
                    
                    exec_result = tool_manager.execute_tool(
                        tool_name=tool,
                        target=normalized_target,
                        parameters={},
                        scan_id=scan_state['scan_id'],
                        phase=scan_state['phase']  # Use scan_state phase instead of hardcoded
                    )
                    
                    if exec_result:
                        findings = exec_result.get('findings', [])
                        relevant = [f for f in findings if vuln_type in f.get('type', '').lower()]
                        if relevant:
                            result['success'] = True
                            result['findings'] += len(relevant)
                            
                            # Add findings to scan state
                            scan_state['findings'].extend(findings)
                            scan_state['tools_executed'].append(tool)
                    
                    time.sleep(1)
            
            # Check if we should advance phase based on findings and progress
            if intelligent_selector and self.should_advance_phase(scan_state):
                new_phase = self.advance_phase()
                if new_phase:
                    scan_state['phase'] = new_phase
                    logger.info(f"[Phase Advancement] Updated scan_state phase to: {new_phase}")
            
            # Calculate reward
            result['reward'] = result['findings'] * 10 + (50 if result['success'] else 0)
            self.total_reward += result['reward']
            self.metrics['total_findings'] += result['findings']
            
            # Update skills learned based on findings
            if result['findings'] > 0:
                self.metrics['skills_learned'] += result['findings']
            
        except Exception as e:
            logger.debug(f"Exercise error: {e}")
        
        return result
    
    def should_advance_phase(self, scan_state: Dict) -> bool:
        """Check if we should advance to the next phase based on findings and progress"""
        findings_count = len(scan_state.get('findings', []))
        tools_executed = len(scan_state.get('tools_executed', []))
        
        # Advance phase if we have sufficient findings or have tried enough tools
        if findings_count >= 5 or tools_executed >= 10:
            return True
        
        # Check for specific phase completion indicators
        current_phase = scan_state.get('phase', 'reconnaissance')
        
        if current_phase == 'reconnaissance':
            # Move to enumeration if we have discovered technologies or services
            technologies = scan_state.get('discovered_technologies', [])
            return len(technologies) >= 2
        elif current_phase == 'enumeration':
            # Move to vulnerability analysis if we have found interesting endpoints
            endpoints_found = any('directory' in str(f).lower() or 'endpoint' in str(f).lower() 
                                for f in scan_state.get('findings', []))
            return endpoints_found
        elif current_phase == 'vulnerability_analysis':
            # Move to exploitation if we have found exploitable vulnerabilities
            vulns_found = any('vulnerability' in str(f).lower() or 'cve' in str(f).lower() 
                            for f in scan_state.get('findings', []))
            return vulns_found
        
        return False
    
    def advance_phase(self):
        """Advance to the next pentest phase"""
        if self.current_phase_idx < len(self.pentest_phases) - 1:
            self.current_phase_idx += 1
            current_phase = self.pentest_phases[self.current_phase_idx]
            logger.info(f"[Phase Advancement] Moving to phase: {current_phase}")
            return current_phase
        return None
    
    def get_current_phase(self) -> str:
        """Get the current pentest phase"""
        if 0 <= self.current_phase_idx < len(self.pentest_phases):
            return self.pentest_phases[self.current_phase_idx]
        return 'reconnaissance'  # fallback
    
    def _run_assessment(self, lesson: LessonPlan) -> Dict:
        """Run lesson assessment"""
        assessment = lesson.assessment
        result = {'passed': False, 'score': 0}
        
        # Simple assessment based on skill levels
        skill_levels = [
            self.agent.get_skill(s).level 
            for s in lesson.skills_trained
        ]
        
        avg_level = statistics.mean(skill_levels) if skill_levels else 0
        result['score'] = avg_level / 100
        result['passed'] = avg_level >= 30  # 30% proficiency to pass
        
        return result
    
    def _run_challenge(self, challenge: Challenge):
        """Run a training challenge"""
        print(f"\n🏆 CHALLENGE: {challenge.name}")
        print(f"   Difficulty: {'⭐' * int(challenge.difficulty)}")
        print(f"   Time Limit: {challenge.max_time_minutes} minutes")
        print(f"   Required Skills: {', '.join(challenge.required_skills)}\n")
        
        challenge.attempts += 1
        challenge_start = datetime.now()
        challenge_end = challenge_start + timedelta(minutes=challenge.max_time_minutes)
        
        target = random.choice(self.targets) if self.targets else {'url': 'http://localhost'}
        target_url = target.get('url') or target.get('ip')
        
        initial_scan_state = {
            'scan_id': f"challenge_{challenge.challenge_id}",
            'target': target_url,
            'phase': 'exploitation',  # Use appropriate phase for challenge
            'findings': [],
            'tools_executed': [],
        }
        
        # Apply standardized schema
        scan_state = ensure_scan_state(initial_scan_state)
        
        success = False
        score = 0
        
        try:
            # Run challenge based on type
            tool_manager = self.components.get('tool_manager')
            intelligent_selector = self.components.get('intelligent_selector')
            
            if not tool_manager:
                return
            
            # Autonomous challenge execution
            while datetime.now() < challenge_end:
                # Get tool recommendation
                if intelligent_selector:
                    recs = intelligent_selector.select_tools(
                        phase=scan_state['phase'],
                        scan_state=scan_state,
                        count=3
                    )
                    
                    if not recs:
                        break
                    
                    rec = recs[0]
                    
                    # Normalize target based on tool type
                    if self.target_normalizer:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, rec.tool)
                    else:
                        normalized_target = target_url
                    
                    # Execute
                    exec_result = tool_manager.execute_tool(
                        tool_name=rec.tool,
                        target=normalized_target,
                        parameters={'args': rec.args.replace('{target}', normalized_target)},
                        scan_id=scan_state['scan_id'],
                        phase=scan_state['phase']
                    )
                    
                    if exec_result:
                        scan_state['tools_executed'].append(rec.tool)
                        findings = exec_result.get('findings', [])
                        scan_state['findings'].extend(findings)
                        
                        # Record execution for intelligent selector learning
                        if intelligent_selector:
                            execution_time = exec_result.get('execution_time', 10.0)  # Default to 10 seconds if not provided
                            success = exec_result.get('success', False)
                            findings_count = len(exec_result.get('findings', []))
                            intelligent_selector.record_execution(rec.tool, success, findings_count, execution_time)
                        
                        # Update skills learned metric when significant findings are made
                        if exec_result.get('findings') and len(exec_result.get('findings', [])) > 0:
                            self.metrics['skills_learned'] += 1
                        
                        # Check success criteria
                        criteria = challenge.success_criteria
                        
                        if criteria.get('shell_obtained') and 'shell' in str(exec_result).lower():
                            success = True
                            break
                        
                        if criteria.get('rce_achieved') and any('rce' in f.get('type', '').lower() for f in findings):
                            success = True
                            break
                        
                        if len(scan_state['findings']) >= criteria.get('vulns_found', 999):
                            success = True
                            break
                
                time.sleep(1)
            
            # Calculate score
            duration = (datetime.now() - challenge_start).total_seconds() / 60
            time_bonus = max(0, 1 - (duration / challenge.max_time_minutes))
            
            score = (
                (1 if success else 0) * 50 +
                len(scan_state['findings']) * 5 +
                time_bonus * 20
            ) * challenge.reward_multiplier
            
        except Exception as e:
            logger.debug(f"Challenge error: {e}")
        
        # Update challenge stats
        if success:
            challenge.completions += 1
            self.completed_challenges.append(challenge.challenge_id)
            self.metrics['challenges_completed'] += 1
            print(f"   ✓ Challenge COMPLETED! Score: {score:.1f}")
        else:
            print(f"   ✗ Challenge failed. Score: {score:.1f}")
        
        # Update skills
        for skill_name in challenge.required_skills:
            skill = self.agent.get_skill(skill_name)
            skill.practice(success, difficulty=challenge.difficulty / 5)
        
        self.total_reward += score
    
    def _execute_chain(self, chain_name: str, target: str, scan_state: Dict) -> Dict:
        """Execute a chain attack"""
        result = {'success': False, 'steps_completed': 0}
        
        # Define chains
        chains = {
            'sqli_to_shell': ['sqlmap', 'curl', 'nc'],
            'lfi_to_rce': ['ffuf', 'curl', 'nc'],
            'xss_to_session': ['dalfox', 'curl'],
        }
        
        tools = chains.get(chain_name, ['nuclei'])
        tool_manager = self.components.get('tool_manager')
        
        if not tool_manager:
            return result
        
        for tool in tools:
            try:
                # Normalize target based on tool type
                if self.target_normalizer:
                    normalized_target = self.target_normalizer.get_tool_target(target, tool)
                else:
                    normalized_target = target
                            
                exec_result = tool_manager.execute_tool(
                    tool_name=tool,
                    target=normalized_target,
                    parameters={},
                    scan_id=scan_state['scan_id'],
                    phase=scan_state['phase']
                )
                
                if exec_result and exec_result.get('success'):
                    result['steps_completed'] += 1
                    
                    # Check for shell
                    stdout = exec_result.get('stdout', '')
                    if any(ind in stdout for ind in ['uid=', 'root:', 'shell']):
                        result['success'] = True
                        self.metrics['total_shells'] += 1
                        break
                        
            except Exception as e:
                logger.debug(f"Chain step error: {e}")
            
            time.sleep(1)
        
        return result
    
    def _practice_weak_skills(self, end_time: datetime):
        """Practice weak skills until phase end"""
        self.agent.identify_weaknesses()
        
        if not self.agent.weaknesses:
            return
        
        print(f"\n📖 Practicing weak skills: {', '.join(self.agent.weaknesses[:3])}")
        
        target = random.choice(self.targets) if self.targets else {'url': 'http://localhost'}
        target_url = target.get('url') or target.get('ip')
        
        tool_manager = self.components.get('tool_manager')
        if not tool_manager:
            return
        
        # Map skills to tools
        skill_tools = {
            'nmap': 'nmap',
            'gobuster': 'gobuster',
            'sqli': 'sqlmap',
            'xss': 'dalfox',
            'nuclei': 'nuclei',
        }
        
        for weakness in self.agent.weaknesses[:3]:
            if datetime.now() >= end_time:
                break
            
            # Find matching tool
            tool = None
            for skill_key, tool_name in skill_tools.items():
                if skill_key in weakness.lower():
                    tool = tool_name
                    break
            
            if tool:
                try:
                    # Normalize target based on tool type
                    if self.target_normalizer:
                        normalized_target = self.target_normalizer.get_tool_target(target_url, tool)
                    else:
                        normalized_target = target_url
                    
                    exec_result = tool_manager.execute_tool(
                        tool_name=tool,
                        target=normalized_target,
                        parameters={},
                        scan_id='practice',
                        phase='reconnaissance'  # Default phase for practice
                    )
                    
                    success = exec_result and exec_result.get('success', False)
                    skill = self.agent.get_skill(weakness)
                    skill.practice(success, difficulty=0.5)
                    
                except Exception as e:
                    logger.debug(f"Practice error: {e}")
            
            time.sleep(1)
    
    def _print_phase_summary(self, phase: TrainingPhase):
        """Print phase summary"""
        elapsed = (datetime.now() - self.training_start).total_seconds() / 3600
        
        print(f"\n{'─'*70}")
        print(f"PHASE SUMMARY: {phase.value.upper()}")
        print(f"{'─'*70}")
        print(f"  Agent Level: {self.agent.current_level.name}")
        print(f"  Training Time: {elapsed:.1f} hours")
        print(f"  Lessons Completed: {self.metrics['lessons_completed']}")
        print(f"  Challenges Completed: {self.metrics['challenges_completed']}")
        print(f"  Total Findings: {self.metrics['total_findings']}")
        print(f"  Total Shells: {self.metrics['total_shells']}")
        print(f"  Total Reward: {self.total_reward:.1f}")
        
        if self.agent.strengths:
            print(f"  Strengths: {', '.join(self.agent.strengths[:3])}")
        if self.agent.weaknesses:
            print(f"  Weaknesses: {', '.join(self.agent.weaknesses[:3])}")
        print(f"{'─'*70}\n")
    
    def _save_checkpoint(self):
        """Save training checkpoint"""
        checkpoint = {
            'timestamp': datetime.now().isoformat(),
            'agent': asdict(self.agent),
            'metrics': self.metrics,
            'total_reward': self.total_reward,
            'completed_lessons': self.completed_lessons,
            'completed_challenges': self.completed_challenges,
        }
        
        checkpoint_path = self.output_dir / f"checkpoint_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint, f, indent=2, default=str)
        
        logger.info(f"Checkpoint saved: {checkpoint_path}")
        
        # Save RL model
        rl_agent = self.components.get('rl_agent')
        if rl_agent:
            try:
                rl_agent.save()
            except:
                pass
    
    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate final training report"""
        training_end = datetime.now()
        total_duration = (training_end - self.training_start).total_seconds() / 3600
        
        report = {
            'training_summary': {
                'start_time': self.training_start.isoformat(),
                'end_time': training_end.isoformat(),
                'total_hours': total_duration,
                'target_hours': self.total_hours,
            },
            'agent_profile': {
                'agent_id': self.agent.agent_id,
                'final_level': self.agent.current_level.name,
                'skills': {k: asdict(v) for k, v in self.agent.skills.items()},
                'strengths': self.agent.strengths,
                'weaknesses': self.agent.weaknesses,
            },
            'metrics': self.metrics,
            'achievements': self.agent.achievements,
            'total_reward': self.total_reward,
            'curriculum_completion': {
                'lessons_completed': len(self.completed_lessons),
                'total_lessons': len(self.curriculum),
                'completion_rate': len(self.completed_lessons) / len(self.curriculum) if self.curriculum else 0,
            },
            'challenges_completion': {
                'challenges_completed': len(self.completed_challenges),
                'total_challenges': len(self.challenges),
                'completion_rate': len(self.completed_challenges) / len(self.challenges) if self.challenges else 0,
            },
        }
        
        # Save report
        report_path = self.output_dir / f"final_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print final summary
        self._print_final_summary(report)
        
        return report
    
    def _print_final_summary(self, report: Dict):
        """Print final training summary"""
        print(f"""
+=================================================================================+
|                         TRAINING COMPLETE                                     |
+=================================================================================+
|                                                                               |
|  Duration: {report['training_summary']['total_hours']:.1f} hours                                                     |
|  Final Level: {report['agent_profile']['final_level'].ljust(20)}                                   |
|                                                                               |
|  METRICS:                                                                     |
|    • Lessons Completed: {str(report['curriculum_completion']['lessons_completed']).ljust(5)} / {len(self.curriculum)}                                    |
|    • Challenges Completed: {str(report['challenges_completion']['challenges_completed']).ljust(5)} / {len(self.challenges)}                                 |
|    • Total Findings: {str(report['metrics']['total_findings']).ljust(10)}                                        |
|    • Skills Learned: {str(report['metrics']['skills_learned']).ljust(10)}                                         |
|    • Total Shells: {str(report['metrics']['total_shells']).ljust(10)}                                          |
|    • Chain Attacks: {str(report['metrics']['total_chains']).ljust(10)}                                         |
|    • Total Reward: {str(int(report['total_reward'])).ljust(10)}                                          |
|                                                                               |
|  SKILL ASSESSMENT:                                                            |
|    Strengths: {', '.join(report['agent_profile']['strengths'][:3]) if report['agent_profile']['strengths'] else 'None yet'.ljust(50)}|
|    Weaknesses: {', '.join(report['agent_profile']['weaknesses'][:3]) if report['agent_profile']['weaknesses'] else 'None'.ljust(49)}|
|                                                                               |
+=================================================================================+
        """)
    
    def _load_authorized_targets(self) -> List[str]:
        """Load authorized vulnerable targets for training"""
        # Default authorized targets (local/vulnerable lab environments)
        default_targets = [
            'localhost',
            '127.0.0.1',
            '192.168.56.',  # VirtualBox/Vagrant networks
            '192.168.1.',   # Common local networks
            '10.0.2.',      # VirtualBox default
            'juice-shop',   # OWASP Juice Shop container name
            'dvwa',         # DVWA container name
            'metasploitable', # Metasploitable container name
        ]
        
        # Load from config if available
        config_targets = self.config.get('authorized_targets', [])
        if config_targets:
            default_targets.extend(config_targets)
        
        return default_targets
    
    def _is_target_authorized(self, target: str) -> bool:
        """Check if target is in authorized list"""
        target_lower = target.lower().strip()
        
        # Check if target matches any authorized patterns
        for auth_target in self.authorized_targets:
            if auth_target in target_lower or target_lower.startswith(auth_target.replace('.', '')):
                return True
        
        # Check if it's a localhost or private IP
        if target_lower in ['localhost', '127.0.0.1']:
            return True
        
        # Check for private IP ranges
        if any(target_lower.startswith(private_prefix) for private_prefix in 
               ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', 
                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', 
                '172.30.', '172.31.']):
            return True
        
        return False
    
    def _validate_targets(self):
        """Validate that all configured targets are authorized"""
        invalid_targets = []
        valid_targets = []
        
        for target in self.targets:
            target_url = target.get('url') or target.get('ip') or str(target)
            if self._is_target_authorized(target_url):
                valid_targets.append(target)
            else:
                invalid_targets.append(target_url)
        
        if invalid_targets:
            logger.warning(f"Unauthorized targets filtered out: {invalid_targets}")
            
        self.targets = valid_targets
        logger.info(f"Validated targets: {len(self.targets)} authorized targets")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Optimus Newbie to Pro Training')
    parser.add_argument('--hours', type=int, default=12, help='Total training hours (default: 12)')
    parser.add_argument('--targets', type=str, help='Comma-separated target URLs/IPs')
    parser.add_argument('--config', type=str, help='Config JSON file')
    parser.add_argument('--output', type=str, default='training_output/newbie_to_pro', help='Output directory')
    parser.add_argument('--resume', type=str, help='Resume from checkpoint file')
    
    args = parser.parse_args()
    
    # Build config
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
    else:
        if args.targets:
            targets = [{'url': t.strip(), 'name': f'target_{i}'} 
                      for i, t in enumerate(args.targets.split(','))]
        else:
            targets = [
                {'url': 'http://192.168.56.101:3000', 'name': 'OWASP_Juice_Shop'},
                {'ip': '192.168.56.102', 'name': 'Vulnerable_VM_1'},
                {'ip': '192.168.56.103', 'name': 'Vulnerable_VM_2'},
            ]
        
        config = {
            'targets': targets,
            'total_hours': args.hours,
            'output_dir': args.output,
        }
    
    # Initialize and run
    trainer = NewbieToProTrainer(config)
    
    if not trainer.initialize():
        print("Failed to initialize trainer!")
        sys.exit(1)
    
    try:
        report = trainer.run_training()
        print(f"\nTraining complete! Report saved to {config['output_dir']}")
    except KeyboardInterrupt:
        print("\nTraining interrupted. Progress saved.")
    except Exception as e:
        print(f"\nTraining error: {e}")
        traceback.print_exc()


if __name__ == '__main__':
    main()
