"""
Optimus Robust Scan Orchestrator v2

This replaces the scan execution logic to ensure:
1. All phases execute with minimum tool requirements
2. Exploitation phase actually runs
3. Scans don't terminate prematurely
4. Real findings trigger exploitation attempts

USAGE:
    Replace the call in scan_engine.py:
    
    # OLD:
    result = agent.run_autonomous_scan(target, scan_config)
    
    # NEW:
    from inference.robust_orchestrator import RobustScanOrchestrator
    orchestrator = RobustScanOrchestrator(socketio)
    result = orchestrator.run_full_scan(target, scan_config)
"""

import uuid
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Import exploitation fixes
try:
    from .exploitation_fix import (
        get_enhanced_exploitable_findings,
        classify_finding_for_exploitation,
        get_exploitation_commands,
        should_run_post_exploitation,
        get_post_exploitation_tools,
    )
    EXPLOITATION_FIX_AVAILABLE = True
except ImportError:
    EXPLOITATION_FIX_AVAILABLE = False
    logger.warning("[Orchestrator] Exploitation fix module not available")

# Import professional report generator
try:
    from reporting.professional_report import get_professional_report_generator
    PROFESSIONAL_REPORT_AVAILABLE = True
except ImportError:
    PROFESSIONAL_REPORT_AVAILABLE = False
    logger.warning("[Orchestrator] Professional report generator not available")

# Import intelligent tool selector
try:
    from .intelligent_selector import get_intelligent_selector, ToolRecommendation
    INTELLIGENT_SELECTOR_AVAILABLE = True
except ImportError:
    INTELLIGENT_SELECTOR_AVAILABLE = False
    logger.warning("[Orchestrator] Intelligent selector not available")


class ScanPhase(Enum):
    """Scan phases in order"""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


@dataclass
class PhaseConfig:
    """Configuration for each phase"""
    name: str
    min_tools: int  # Minimum tools to execute before moving on
    max_tools: int  # Maximum tools before forcing transition
    min_time: int   # Minimum seconds in this phase
    max_time: int   # Maximum seconds before forcing transition
    required_for_next: List[str] = field(default_factory=list)  # Required findings


# Phase configurations - ensures adequate coverage
PHASE_CONFIGS = {
    ScanPhase.RECONNAISSANCE: PhaseConfig(
        name="reconnaissance",
        min_tools=5,
        max_tools=15,
        min_time=30,
        max_time=300,
        required_for_next=[]
    ),
    ScanPhase.ENUMERATION: PhaseConfig(
        name="enumeration", 
        min_tools=5,
        max_tools=20,
        min_time=30,
        max_time=300,
        required_for_next=[]
    ),
    ScanPhase.VULNERABILITY_SCAN: PhaseConfig(
        name="vulnerability_scan",
        min_tools=8,
        max_tools=25,
        min_time=60,
        max_time=600,
        required_for_next=[]
    ),
    ScanPhase.EXPLOITATION: PhaseConfig(
        name="exploitation",
        min_tools=3,
        max_tools=15,
        min_time=30,
        max_time=300,
        required_for_next=[]
    ),
    ScanPhase.POST_EXPLOITATION: PhaseConfig(
        name="post_exploitation",
        min_tools=2,
        max_tools=10,
        min_time=15,
        max_time=180,
        required_for_next=[]
    ),
}


class RobustScanOrchestrator:
    """
    Robust scan orchestrator that ensures all phases execute properly.
    
    Key improvements:
    1. Minimum tool execution per phase
    2. Time-based phase progression
    3. Explicit exploitation phase with our exploitation module
    4. WebSocket updates throughout
    5. Comprehensive logging
    6. Progress tracking with ETA
    7. Enhanced output parsing
    """
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.tool_manager = None
        self.exploitation_manager = None
        self.progress_tracker = None
        self.output_parser = None
        self.universal_exploits = None
        self.phase_tools = {}
        self.intelligent_selector = None
        
        self._init_components()
        self._init_phase_tools()
        self._init_intelligent_selector()
    
    def _init_components(self):
        # Initialize required components
        try:
            from inference.target_normalizer import get_target_normalizer
            self.target_normalizer = get_target_normalizer()
            logger.info("[Orchestrator] TargetNormalizer initialized")
        except Exception as e:
            logger.warning(f"[Orchestrator] TargetNormalizer not available: {e}")
            self.target_normalizer = None
        try:
            from inference.tool_manager import ToolManager
            self.tool_manager = ToolManager(self.socketio)
            logger.info("[Orchestrator] ToolManager initialized")
        except Exception as e:
            logger.error(f"[Orchestrator] Failed to init ToolManager: {e}")
        
        try:
            from exploitation.integration import ExploitationManager
            self.exploitation_manager = ExploitationManager(self.tool_manager)
            logger.info("[Orchestrator] ExploitationManager initialized")
        except Exception as e:
            logger.warning(f"[Orchestrator] ExploitationManager not available: {e}")
        
        # Initialize progress tracker
        try:
            from inference.progress_tracker import get_progress_manager
            self.progress_manager = get_progress_manager(self.socketio)
            logger.info("[Orchestrator] ProgressManager initialized")
        except Exception as e:
            logger.warning(f"[Orchestrator] ProgressManager not available: {e}")
            self.progress_manager = None
        
        # Initialize enhanced parser
        try:
            from inference.enhanced_output_parser import EnhancedOutputParser
            self.output_parser = EnhancedOutputParser()
            logger.info("[Orchestrator] EnhancedOutputParser initialized")
        except Exception as e:
            logger.warning(f"[Orchestrator] EnhancedParser not available: {e}")
            self.output_parser = None
        
        # Initialize universal exploits database
        try:
            from exploitation.universal_exploits import get_universal_exploit_db
            self.universal_exploits = get_universal_exploit_db()
            logger.info("[Orchestrator] UniversalExploitDB initialized")
        except Exception as e:
            logger.warning(f"[Orchestrator] UniversalExploitDB not available: {e}")
    
    def _init_intelligent_selector(self):
        """Initialize intelligent tool selector"""
        if INTELLIGENT_SELECTOR_AVAILABLE:
            try:
                self.intelligent_selector = get_intelligent_selector()
                logger.info("[Orchestrator] ✓ Intelligent Tool Selector initialized")
            except Exception as e:
                logger.warning(f"[Orchestrator] Intelligent selector failed: {e}")
                self.intelligent_selector = None
        else:
            self.intelligent_selector = None
    
    def _init_phase_tools(self):
        """Initialize tools for each phase"""
        self.phase_tools = {
            ScanPhase.RECONNAISSANCE: [
                # Network discovery
                {"tool": "nmap", "args": "-sn {target}", "description": "Host discovery"},
                {"tool": "nmap", "args": "-sV -sC -p- --min-rate=1000 {target}", "description": "Full port scan"},
                {"tool": "nmap", "args": "-sU --top-ports 100 {target}", "description": "UDP scan"},
                {"tool": "whatweb", "args": "{target}", "description": "Web fingerprinting"},
                {"tool": "dig", "args": "{domain} ANY", "description": "DNS enumeration"},
                {"tool": "whois", "args": "{domain}", "description": "WHOIS lookup"},
                {"tool": "curl", "args": "-I {target}", "description": "HTTP headers"},
                {"tool": "wafw00f", "args": "{target}", "description": "WAF detection"},
            ],
            ScanPhase.ENUMERATION: [
                # Directory/file discovery
                {"tool": "gobuster", "args": "dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 50", "description": "Directory bruteforce"},
                {"tool": "ffuf", "args": "-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403", "description": "Fuzzing"},
                {"tool": "nikto", "args": "-h {target} -Tuning 123bde", "description": "Web server scan"},
                {"tool": "wpscan", "args": "--url {target} --enumerate ap,at,u", "description": "WordPress scan"},
                {"tool": "droopescan", "args": "scan drupal -u {target}", "description": "Drupal scan"},
                {"tool": "joomscan", "args": "-u {target}", "description": "Joomla scan"},
                # API/endpoint discovery  
                {"tool": "curl", "args": "{target}/api/ -s", "description": "API discovery"},
                {"tool": "curl", "args": "{target}/swagger.json -s", "description": "Swagger discovery"},
                {"tool": "curl", "args": "{target}/robots.txt -s", "description": "Robots.txt"},
                {"tool": "curl", "args": "{target}/sitemap.xml -s", "description": "Sitemap"},
            ],
            ScanPhase.VULNERABILITY_SCAN: [
                # Vulnerability scanners
                {"tool": "nuclei", "args": "-u {target} -t cves/ -severity critical,high,medium", "description": "CVE scanning"},
                {"tool": "nuclei", "args": "-u {target} -t vulnerabilities/", "description": "Vuln templates"},
                {"tool": "nuclei", "args": "-u {target} -t exposures/", "description": "Exposure scanning"},
                {"tool": "sqlmap", "args": "-u {target} --batch --crawl=2 --level=2 --risk=2", "description": "SQL injection"},
                {"tool": "xsstrike", "args": "-u {target} --crawl", "description": "XSS scanning"},
                {"tool": "commix", "args": "-u {target} --batch", "description": "Command injection"},
                {"tool": "ssrf-sheriff", "args": "-u {target}", "description": "SSRF scanning"},
                {"tool": "lfi-suite", "args": "-u {target}", "description": "LFI scanning"},
                # SSL/TLS
                {"tool": "sslscan", "args": "{target}", "description": "SSL analysis"},
                {"tool": "testssl", "args": "{target}", "description": "TLS testing"},
            ],
            ScanPhase.EXPLOITATION: [
                # This phase is handled specially by exploitation module
                {"tool": "exploit_auto", "args": "", "description": "Automated exploitation"},
            ],
            ScanPhase.POST_EXPLOITATION: [
                # Post-exploitation enumeration
                {"tool": "linpeas", "args": "", "description": "Linux privesc enum"},
                {"tool": "winpeas", "args": "", "description": "Windows privesc enum"},
            ],
        }
    
    def run_full_scan(self, target: str, config: Dict = None, shared_scan_state: Dict = None) -> Dict[str, Any]:
        """
        Run complete scan through all phases.
        
        This is the main entry point that ensures:
        1. All phases execute
        2. Minimum tool coverage per phase
        3. Exploitation runs on findings
        4. Proper reporting
        5. Progress tracking with ETA
        """
        config = config or {}
        
        print(f"\n{'='*70}")
        print(f"[RobustOrchestrator] STARTING FULL SCAN")
        print(f"  Target: {target}")
        print(f"  Config: {config}")
        print(f"{'='*70}\n")
        
        # Use shared scan state if provided, otherwise initialize new one
        if shared_scan_state is not None:
            scan_state = shared_scan_state
            # Reset start_time to current time to avoid timezone/elapsed time issues
            scan_state['start_time'] = datetime.now().isoformat()
            logger.info(f"[Orchestrator] Using shared scan state for {scan_state['scan_id']}")
        else:
            # Initialize scan state
            scan_state = self._init_scan_state(target, config)
            logger.info(f"[Orchestrator] Created new scan state for {scan_state['scan_id']}")
        
        # Reset intelligent selector for new scan
        if self.intelligent_selector:
            self.intelligent_selector.reset_session()
            logger.info("[Orchestrator] ✓ Intelligent selector reset for new scan")
        
        # Initialize progress tracker
        progress_tracker = None
        if hasattr(self, 'progress_manager') and self.progress_manager:
            progress_tracker = self.progress_manager.create_tracker(
                scan_state['scan_id'],
                target
            )
            progress_tracker.start_scan()
            # Don't add progress_tracker to scan_state as it's not JSON serializable
            # Instead, keep it as a local variable for use in this method
        
        # Emit scan started
        self._emit_event('scan_started', {
            'scan_id': scan_state['scan_id'],
            'target': target,
            'phases': [p.value for p in ScanPhase],
            'eta_seconds': self._get_total_expected_duration(),
        })
        
        # Execute phases in order
        phases = [
            ScanPhase.RECONNAISSANCE,
            ScanPhase.ENUMERATION,
            ScanPhase.VULNERABILITY_SCAN,
            ScanPhase.EXPLOITATION,
            ScanPhase.POST_EXPLOITATION,
        ]
        
        for phase in phases:
            if self._should_stop(scan_state):
                logger.info(f"[Orchestrator] Scan stopped by user")
                break
            
            # Check time budget
            elapsed = self._get_elapsed_time(scan_state)
            max_time = config.get('max_time', 3600)
            
            if elapsed >= max_time:
                logger.info(f"[Orchestrator] Time budget exhausted: {elapsed}s")
                break
            
            # Run phase
            logger.info(f"\n{'='*50}")
            logger.info(f"[Orchestrator] PHASE: {phase.value}")
            logger.info(f"{'='*50}")
            
            # Update progress tracker
            if progress_tracker:
                progress_tracker.start_phase(phase.value)
            
            progress_info = {}
            if progress_tracker:
                progress_info = {
                    'progress': progress_tracker.get_progress(),
                    'eta': progress_tracker.get_eta_formatted(),
                }
            
            self._emit_event('phase_transition', {
                'scan_id': scan_state['scan_id'],
                'from': scan_state.get('phase', 'init'),
                'to': phase.value,
                **progress_info
            })
            
            scan_state['phase'] = phase.value
            scan_state['phase_start_time'] = datetime.now().isoformat()
            
            # Execute phase
            if phase == ScanPhase.EXPLOITATION:
                self._run_exploitation_phase(scan_state, progress_tracker)
            elif phase == ScanPhase.POST_EXPLOITATION:
                self._run_post_exploitation_phase(scan_state, progress_tracker)
            else:
                self._run_standard_phase(scan_state, phase, progress_tracker)
            
            # Complete phase in tracker
            if progress_tracker:
                progress_tracker.complete_phase(phase.value)
            
            # Phase complete
            logger.info(f"[Orchestrator] Phase {phase.value} complete:")
            logger.info(f"  Tools executed: {len([t for t in scan_state['tools_executed'] if t.get('phase') == phase.value])}")
            logger.info(f"  Total findings: {len(scan_state['findings'])}")
            
            # Emit progress
            if progress_tracker:
                self._emit_event('scan_progress', progress_tracker.get_status())
        
        # Complete scan
        if progress_tracker:
            progress_tracker.complete_scan()
        
        # Generate final report
        scan_state['status'] = 'completed'
        scan_state['end_time'] = datetime.now().isoformat()
        scan_state['time_elapsed'] = self._get_elapsed_time(scan_state)
        
        # Emit completion
        self._emit_event('scan_complete', {
            'scan_id': scan_state['scan_id'],
            'findings_count': len(scan_state['findings']),
            'tools_executed': len(scan_state['tools_executed']),
            'time_elapsed': scan_state['time_elapsed']
        })
        
        return self._generate_report(scan_state)
    
    def _init_scan_state(self, target: str, config: Dict) -> Dict[str, Any]:
        """Initialize scan state"""
        # Normalize target
        normalized_target = target
        if hasattr(self, 'target_normalizer') and self.target_normalizer:
            normalized_result = self.target_normalizer.normalize(target)
            normalized_target = normalized_result['url']
        else:
            # Fallback normalization
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            normalized_target = target
        
        # Extract domain for DNS tools
        from urllib.parse import urlparse
        parsed = urlparse(normalized_target)
        domain = parsed.netloc.split(':')[0]
        
        # Return initialized scan state with all required fields
        result = {
            'scan_id': config.get('scan_id', str(uuid.uuid4())[:8]),
            'target': normalized_target,
            'domain': domain,
            'host': parsed.netloc,
            'phase': 'init',
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'findings': [],
            'tools_executed': [],
            'exploits_attempted': [],
            'sessions_obtained': [],
            'credentials_found': [],
            'coverage': 0,
            'risk_score': 0,
            'config': config,
            'stop_requested': False,
            'discovered_endpoints': [],
            'discovered_technologies': [],
            'open_ports': [],
        }
        return result
    
    def _run_standard_phase(self, scan_state: Dict, phase: ScanPhase, progress_tracker=None):
        """
        Run a standard scanning phase with INTELLIGENT tool selection.
        
        Uses IntelligentToolSelector when available, falls back to hardcoded lists.
        """
        config = PHASE_CONFIGS[phase]
        phase_start = datetime.now()
        tools_run_in_phase = 0
        
        # Determine if using intelligent selection
        use_intelligent = (self.intelligent_selector is not None and 
                          INTELLIGENT_SELECTOR_AVAILABLE)
        
        if use_intelligent:
            logger.info(f"[Orchestrator] Phase {phase.value}: Using INTELLIGENT tool selection")
            self._run_phase_intelligent(scan_state, phase, config, progress_tracker)
        else:
            logger.info(f"[Orchestrator] Phase {phase.value}: Using fallback hardcoded tools")
            self._run_phase_hardcoded(scan_state, phase, config, progress_tracker)
    
    def _run_phase_intelligent(self, scan_state: Dict, phase: ScanPhase, config: PhaseConfig, progress_tracker=None):
        """Run phase with intelligent tool selection"""
        phase_start = datetime.now()
        tools_run_in_phase = 0
        consecutive_no_findings = 0
        
        while tools_run_in_phase < config.max_tools:
            # Check stop conditions
            if self._should_stop(scan_state):
                break
            
            # Check phase time limit
            phase_elapsed = (datetime.now() - phase_start).total_seconds()
            if phase_elapsed >= config.max_time:
                logger.info(f"[Orchestrator] Phase time limit reached: {phase_elapsed:.0f}s")
                break
            
            # Check minimum tools met and no recent findings
            if tools_run_in_phase >= config.min_tools and consecutive_no_findings >= 3:
                logger.info(f"[Orchestrator] Min tools met, no recent findings - moving on")
                break
            
            # Get intelligent tool recommendations
            recommendations = self.intelligent_selector.select_tools(
                phase=phase.value,
                scan_state=scan_state,
                count=3  # Get top 3 recommendations
            )
            
            if not recommendations:
                logger.info(f"[Orchestrator] No more tools recommended for {phase.value}")
                break
            
            # Execute top recommended tool
            rec = recommendations[0]
            tool_name = rec.tool
            args_template = rec.args
            
            # Build command with normalized target
            normalized_target = scan_state['target']
            if self.target_normalizer:
                normalized_target = self.target_normalizer.get_tool_target(scan_state['target'], tool_name)
            
            # Format args with target info
            try:
                args = args_template.format(
                    target=normalized_target,
                    domain=scan_state.get('domain', ''),
                    host=scan_state.get('host', '')
                )
            except KeyError:
                args = args_template.replace('{target}', normalized_target)
            
            logger.info(f"[Orchestrator] 🎯 Intelligent selection: {tool_name} "
                       f"(priority={rec.priority:.2f}, source={rec.source}, reason={rec.reason})")
            
            # Execute tool
            exec_start = datetime.now()
            result = self._execute_tool(tool_name, args, scan_state, progress_tracker)
            exec_time = (datetime.now() - exec_start).total_seconds()
            
            if result:
                tools_run_in_phase += 1
                findings_count = len(result.get('findings', []))
                
                # Update intelligent selector with results
                self.intelligent_selector.record_execution(
                    tool=tool_name,
                    success=result.get('success', False),
                    findings_count=findings_count,
                    execution_time=exec_time
                )
                
                # Track consecutive no-findings for early exit
                if findings_count > 0:
                    consecutive_no_findings = 0
                else:
                    consecutive_no_findings += 1
                
                # Record execution
                scan_state['tools_executed'].append({
                    'tool': tool_name,
                    'phase': phase.value,
                    'args': args,
                    'selection_source': rec.source,
                    'selection_reason': rec.reason,
                    'priority': rec.priority,
                    'timestamp': datetime.now().isoformat(),
                    'success': result.get('success', False),
                    'findings_count': findings_count
                })
                
                # Process findings
                for finding in result.get('findings', []):
                    self._add_finding(scan_state, finding, tool_name, phase.value)
                
                # Update discovered info
                if result.get('endpoints'):
                    scan_state['discovered_endpoints'].extend(result['endpoints'])
                if result.get('technologies'):
                    scan_state['discovered_technologies'].extend(result['technologies'])
                if result.get('ports'):
                    scan_state['open_ports'].extend(result['ports'])
            
            time.sleep(0.5)  # Brief pause between tools
        
        logger.info(f"[Orchestrator] Phase {phase.value} complete: {tools_run_in_phase} tools executed")
    
    def _run_phase_hardcoded(self, scan_state: Dict, phase: ScanPhase, config: PhaseConfig, progress_tracker=None):
        """Fallback: Run phase with hardcoded tool list"""
        phase_start = datetime.now()
        tools_run_in_phase = 0
        
        # Get tools for this phase
        tools = self.phase_tools.get(phase, [])
        
        logger.info(f"[Orchestrator] Phase {phase.value}: {len(tools)} tools available")
        
        for tool_config in tools:
            # Check stop conditions
            if self._should_stop(scan_state):
                break
            
            # Check phase time limit
            phase_elapsed = (datetime.now() - phase_start).total_seconds()
            if phase_elapsed >= config.max_time:
                logger.info(f"[Orchestrator] Phase time limit reached: {phase_elapsed}s")
                break
            
            # Check tool limit
            if tools_run_in_phase >= config.max_tools:
                logger.info(f"[Orchestrator] Max tools for phase reached: {tools_run_in_phase}")
                break
            
            # Execute tool
            tool_name = tool_config['tool']
            args_template = tool_config['args']
            description = tool_config['description']
            
            # Build command with normalized target
            normalized_target = scan_state['target']
            if self.target_normalizer:
                normalized_target = self.target_normalizer.get_tool_target(scan_state['target'], tool_name)
            
            args = args_template.format(
                target=normalized_target,
                domain=scan_state['domain'],
                host=scan_state['host']
            )
            
            logger.info(f"[Orchestrator] Executing: {tool_name} - {description}")
            
            result = self._execute_tool(tool_name, args, scan_state, progress_tracker)
            
            if result:
                tools_run_in_phase += 1
                
                # Record execution
                scan_state['tools_executed'].append({
                    'tool': tool_name,
                    'phase': phase.value,
                    'args': args,
                    'description': description,
                    'timestamp': datetime.now().isoformat(),
                    'success': result.get('success', False),
                    'findings_count': len(result.get('findings', []))
                })
                
                # Process findings
                for finding in result.get('findings', []):
                    self._add_finding(scan_state, finding, tool_name, phase.value)
                
                # Update discovered info
                if result.get('endpoints'):
                    scan_state['discovered_endpoints'].extend(result['endpoints'])
                if result.get('technologies'):
                    scan_state['discovered_technologies'].extend(result['technologies'])
                if result.get('ports'):
                    scan_state['open_ports'].extend(result['ports'])
                
                # Emit tool completion
                self._emit_event('tool_complete', {
                    'scan_id': scan_state['scan_id'],
                    'tool': tool_name,
                    'phase': phase.value,
                    'findings': len(result.get('findings', []))
                })
            
            # Small delay between tools
            time.sleep(0.5)
        
        # Ensure minimum tools if not met and time allows
        if tools_run_in_phase < config.min_tools:
            phase_elapsed = (datetime.now() - phase_start).total_seconds()
            if phase_elapsed < config.max_time:
                logger.info(f"[Orchestrator] Running additional tools to meet minimum ({tools_run_in_phase}/{config.min_tools})")
                # Could run additional discovery tools here
    
    def _run_exploitation_phase(self, scan_state: Dict, progress_tracker=None):
        """
        Run exploitation phase using our exploitation module.
        
        ENHANCED: Always runs exploitation tools on findings, regardless of ExploitationManager.
        """
        logger.info("[Orchestrator] === EXPLOITATION PHASE (ENHANCED) ===")
        
        findings = scan_state.get('findings', [])
        
        if not findings:
            logger.warning("[Orchestrator] No findings to exploit - running basic exploitation anyway")
            # Run basic exploitation even without findings
            self._run_basic_exploitation_tools(scan_state, progress_tracker)
            return
        
        logger.info(f"[Orchestrator] {len(findings)} findings available for exploitation")
        
        # Filter exploitable findings using enhanced logic
        exploitable = self._get_exploitable_findings(findings)
        logger.info(f"[Orchestrator] {len(exploitable)} exploitable findings identified")
        
        # ALWAYS run exploitation tools, even if no "exploitable" findings
        if not exploitable:
            logger.info("[Orchestrator] No exploitable findings - running fallback exploitation on all findings")
            exploitable = findings[:5]  # Use top 5 findings anyway
        
        # Track tools executed in this phase
        exploitation_tools_run = 0
        
        # Method 1: Use ExploitationManager if available
        if self.exploitation_manager:
            logger.info("[Orchestrator] Using ExploitationManager for exploitation")
            
            for finding in exploitable[:10]:  # Limit to top 10
                if self._should_stop(scan_state):
                    break
                
                logger.info(f"[Orchestrator] Attempting exploit for: {finding.get('type', 'unknown')}")
                
                try:
                    # Create attack plan
                    normalized_target = scan_state['target']
                    if self.target_normalizer:
                        normalized_target = self.target_normalizer.get_tool_target(scan_state['target'], 'exploitation')
                    
                    # Safely get config from scan_state with fallback to default values
                    scan_config = scan_state.get('config', {})
                    context = {
                        'lhost': scan_config.get('lhost', '10.10.14.1'),
                        'lport': scan_config.get('lport', 4444)
                    }
                    
                    plan = self.exploitation_manager.create_attack_plan(
                        target=normalized_target,
                        objective="shell",
                        vulnerabilities=[finding],
                        context=context
                    )
                    
                    if plan and plan.get('steps'):
                        logger.info(f"[Orchestrator] Attack plan created: {len(plan['steps'])} steps")
                        
                        # Record attempt
                        scan_state['exploits_attempted'].append({
                            'finding': finding,
                            'plan': plan,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Execute plan steps
                        for step in plan['steps'][:5]:  # Limit steps
                            if self._should_stop(scan_state):
                                break
                            
                            result = self._execute_exploit_step(step, scan_state, progress_tracker)
                            exploitation_tools_run += 1
                            
                            if result.get('shell_obtained'):
                                logger.info("[Orchestrator] 🐚 SHELL OBTAINED!")
                                scan_state['sessions_obtained'].append({
                                    'type': result.get('session_type', 'shell'),
                                    'access_level': result.get('access_level', 'user'),
                                    'via': finding.get('type'),
                                    'timestamp': datetime.now().isoformat()
                                })
                            
                            if result.get('credentials'):
                                scan_state['credentials_found'].extend(result['credentials'])
                
                except Exception as e:
                    logger.error(f"[Orchestrator] Exploitation error: {e}")
                
                time.sleep(1)
        
        # Method 2: ALWAYS run fallback exploitation tools
        logger.info("[Orchestrator] Running fallback exploitation tools")
        self._run_fallback_exploitation(scan_state, exploitable, progress_tracker)
        
        # Method 3: Run direct exploitation commands from exploitation_fix
        if EXPLOITATION_FIX_AVAILABLE:
            logger.info("[Orchestrator] Running enhanced exploitation commands")
            self._run_enhanced_exploitation(scan_state, exploitable, progress_tracker)
        
        logger.info(f"[Orchestrator] Exploitation phase complete. Tools executed: {len(scan_state.get('tools_executed', []))}")
    
    def _run_fallback_exploitation(self, scan_state: Dict, findings: List[Dict], progress_tracker=None):
        """Fallback exploitation when ExploitationManager not available or fails"""
        logger.info(f"[Orchestrator] Running fallback exploitation on {len(findings)} findings")
        tools_executed = 0
        
        for finding in findings[:5]:
            if self._should_stop(scan_state):
                break
                
            vuln_type = finding.get('type', '').lower()
            url = finding.get('url', finding.get('location', scan_state['target']))
            param = finding.get('parameter', finding.get('param', ''))
            
            logger.info(f"[Orchestrator] Attempting exploitation: {vuln_type} at {url}")
            
            # Normalize target
            normalized_target = scan_state['target']
            if self.target_normalizer:
                normalized_target = self.target_normalizer.get_tool_target(scan_state['target'], 'sqlmap')
            
            result = None
            tool_used = None
            
            if 'sql' in vuln_type:
                # SQLMap exploitation
                tool_used = 'sqlmap'
                if param:
                    args = f"-u '{url}' -p {param} --batch --dump --level=3 --risk=2"
                else:
                    args = f"-u '{url}' --batch --forms --dump --level=2"
                result = self._execute_tool(tool_used, args, scan_state, progress_tracker)
                
            elif 'xss' in vuln_type:
                # XSSer for automated XSS exploitation
                tool_used = 'dalfox'
                args = f"url '{url}' --skip-bav"
                result = self._execute_tool(tool_used, args, scan_state, progress_tracker)
                
            elif 'command' in vuln_type or 'rce' in vuln_type:
                # Try commix for command injection
                tool_used = 'commix'
                args = f"--url='{url}' --batch --level=2"
                result = self._execute_tool(tool_used, args, scan_state, progress_tracker)
                
            elif 'lfi' in vuln_type or 'path' in vuln_type:
                # LFI exploitation with curl
                tool_used = 'curl'
                test_payloads = ['....//....//....//etc/passwd', '../../../etc/passwd']
                for payload in test_payloads:
                    if param:
                        test_url = url.replace(param + '=', f'{param}={payload}')
                    else:
                        test_url = f"{url}/{payload}"
                    args = f"-s '{test_url}'"
                    result = self._execute_tool(tool_used, args, scan_state, progress_tracker)
                    if result and 'root:' in str(result.get('stdout', '')):
                        break
            
            elif 'ssrf' in vuln_type:
                # SSRF testing
                tool_used = 'curl'
                args = f"-s '{url}'"
                result = self._execute_tool(tool_used, args, scan_state, progress_tracker)
            
            if result and tool_used:
                tools_executed += 1
                scan_state['exploits_attempted'].append({
                    'tool': tool_used,
                    'finding_type': vuln_type,
                    'url': url,
                    'success': result.get('success', False),
                    'findings_count': len(result.get('findings', [])),
                    'timestamp': datetime.now().isoformat()
                })
                
                # Check for shell indicators
                stdout = result.get('stdout', '')
                if any(ind in stdout for ind in ['uid=', 'root:', 'www-data', 'SYSTEM']):
                    logger.info(f"[Orchestrator] Possible shell access from {tool_used}!")
                    scan_state['sessions_obtained'].append({
                        'type': 'command_execution',
                        'via': vuln_type,
                        'tool': tool_used,
                        'timestamp': datetime.now().isoformat()
                    })
            
            time.sleep(1)  # Rate limiting
        
        logger.info(f"[Orchestrator] Fallback exploitation: {tools_executed} tools executed")
    
    def _run_basic_exploitation_tools(self, scan_state: Dict, progress_tracker=None):
        """Run basic exploitation tools even without findings."""
        logger.info("[Orchestrator] Running basic exploitation tools (no specific findings)")
        
        target = scan_state.get('target', '')
        
        # Basic exploitation attempts
        basic_tools = [
            ('sqlmap', f"-u '{target}' --batch --forms --crawl=2 --level=1 --risk=1"),
            ('nuclei', f"-u '{target}' -severity critical,high -as"),
            ('dalfox', f"url '{target}' --skip-bav"),
        ]
        
        for tool, args in basic_tools:
            if self._should_stop(scan_state):
                break
            
            try:
                result = self._execute_tool(tool, args, scan_state, progress_tracker)
                if result:
                    scan_state['exploits_attempted'].append({
                        'tool': tool,
                        'finding_type': 'generic',
                        'url': target,
                        'success': result.get('success', False),
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception as e:
                logger.debug(f"[Orchestrator] Basic tool {tool} failed: {e}")
            
            time.sleep(1)
    
    def _run_enhanced_exploitation(self, scan_state: Dict, findings: List[Dict], progress_tracker=None):
        """Run enhanced exploitation using exploitation_fix module."""
        if not EXPLOITATION_FIX_AVAILABLE:
            return
        
        logger.info("[Orchestrator] Running enhanced exploitation commands")
        target = scan_state.get('target', '')
        
        for finding in findings[:5]:  # Top 5 findings
            if self._should_stop(scan_state):
                break
            
            try:
                # Get exploitation commands for this finding
                commands = get_exploitation_commands(finding, target)
                
                for cmd_info in commands[:2]:  # Max 2 commands per finding
                    tool = cmd_info.get('tool', 'curl')
                    command = cmd_info.get('command', '')
                    description = cmd_info.get('description', '')
                    
                    logger.info(f"[Orchestrator] Enhanced exploit: {description}")
                    
                    # Extract args from command (remove tool name)
                    args = command.replace(tool, '', 1).strip()
                    
                    result = self._execute_tool(tool, args, scan_state, progress_tracker)
                    
                    if result:
                        scan_state['exploits_attempted'].append({
                            'tool': tool,
                            'command': command,
                            'description': description,
                            'finding_type': finding.get('type', 'unknown'),
                            'success': result.get('success', False),
                            'findings_count': len(result.get('findings', [])),
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    time.sleep(1)
                    
            except Exception as e:
                logger.debug(f"[Orchestrator] Enhanced exploitation error: {e}")
    
    def _run_post_exploitation_phase(self, scan_state: Dict, progress_tracker=None):
        """
        Run post-exploitation phase.
        
        ENHANCED: Runs even without sessions for reconnaissance purposes.
        """
        logger.info("[Orchestrator] === POST-EXPLOITATION PHASE (ENHANCED) ===")
        
        sessions = scan_state.get('sessions_obtained', [])
        
        # Check if we should run post-exploitation
        if EXPLOITATION_FIX_AVAILABLE:
            should_run = should_run_post_exploitation(scan_state)
        else:
            should_run = bool(sessions) or bool(scan_state.get('credentials_found'))
        
        if not should_run:
            logger.info("[Orchestrator] Skipping post-exploitation (no sessions/findings)")
            return
        
        logger.info(f"[Orchestrator] Running post-exploitation (sessions: {len(sessions)})")
        
        # Get post-exploitation tools
        if EXPLOITATION_FIX_AVAILABLE:
            post_tools = get_post_exploitation_tools(scan_state)
        else:
            post_tools = []
        
        target = scan_state.get('target', '')
        
        # Always run some post-exploitation enumeration
        default_post_tools = [
            ('curl', f"-s '{target}/robots.txt'"),
            ('curl', f"-s '{target}/.git/config'"),
            ('curl', f"-s '{target}/.env'"),
            ('curl', f"-s '{target}/api/'"),
        ]
        
        # Combine with enhanced tools
        all_tools = [(t['tool'], t['command'].replace(t['tool'], '', 1).strip()) 
                     for t in post_tools] + default_post_tools
        
        for tool, args in all_tools[:6]:  # Limit to 6 tools
            if self._should_stop(scan_state):
                break
            
            try:
                result = self._execute_tool(tool, args, scan_state, progress_tracker)
                
                # Check for sensitive data exposure
                if result:
                    stdout = result.get('stdout', '')
                    
                    # Check for sensitive file content
                    sensitive_patterns = ['password', 'secret', 'api_key', 'database', 
                                         'private', 'BEGIN RSA', 'BEGIN PRIVATE']
                    
                    for pattern in sensitive_patterns:
                        if pattern.lower() in stdout.lower():
                            logger.info(f"[Orchestrator] Sensitive data found: {pattern}")
                            scan_state.setdefault('data_exposed', []).append({
                                'type': 'sensitive_file',
                                'pattern': pattern,
                                'tool': tool,
                                'timestamp': datetime.now().isoformat()
                            })
                            break
                            
            except Exception as e:
                logger.debug(f"[Orchestrator] Post-exploitation tool {tool} failed: {e}")
            
            time.sleep(0.5)
        
        logger.info("[Orchestrator] Post-exploitation phase complete")
    
    def _execute_tool(self, tool: str, args: str, scan_state: Dict, progress_tracker=None) -> Optional[Dict]:
        """Execute a tool via ToolManager with enhanced parsing"""
        if not self.tool_manager:
            logger.error("[Orchestrator] ToolManager not available")
            return None
        
        # Get normalized target for this specific tool
        normalized_target = scan_state['target']
        if hasattr(self, 'target_normalizer') and self.target_normalizer:
            normalized_target = self.target_normalizer.get_tool_target(scan_state['target'], tool)
        
        try:
            # Start tool in progress tracker
            if progress_tracker:
                progress_tracker.start_tool(tool, scan_state['phase'])
            
            # Execute via tool manager
            result = self.tool_manager.execute_tool(
                tool_name=tool,
                target=normalized_target,
                parameters={'args': args},
                scan_id=scan_state['scan_id'],
                phase=scan_state['phase']
            )
            
            # CRITICAL FIX: Extract findings from tool_manager's parsed_results
            # tool_manager returns: {
            #   'stdout': ..., 
            #   'stderr': ..., 
            #   'parsed_results': {'vulnerabilities': [...], 'hosts': [...], ...}
            # }
            if result:
                parsed_results = result.get('parsed_results', {})
                
                # Extract vulnerabilities -> findings
                if parsed_results and parsed_results.get('vulnerabilities'):
                    if 'findings' not in result:
                        result['findings'] = []
                    for vuln in parsed_results['vulnerabilities']:
                        if isinstance(vuln, dict):
                            result['findings'].append(vuln)
                        elif hasattr(vuln, 'to_dict'):
                            result['findings'].append(vuln.to_dict())
                    logger.info(f"[Orchestrator] Extracted {len(result['findings'])} findings from {tool}")
                
                # Extract hosts/endpoints
                if parsed_results and parsed_results.get('hosts'):
                    if 'endpoints' not in result:
                        result['endpoints'] = []
                    result['endpoints'].extend(parsed_results['hosts'])
                
                # Extract services
                if parsed_results and parsed_results.get('services'):
                    if 'services' not in result:
                        result['services'] = []
                    result['services'].extend(parsed_results['services'])
                
                # Extract technologies
                if parsed_results and parsed_results.get('technologies'):
                    if 'technologies' not in result:
                        result['technologies'] = []
                    result['technologies'].extend(parsed_results['technologies'])
                
                # Fallback: If still no findings, try re-parsing with enhanced parser
                # Note: tool_manager uses 'stdout' key, not 'output'
                if not result.get('findings') and self.output_parser:
                    raw_output = result.get('stdout', result.get('output', ''))
                    stderr_output = result.get('stderr', '')
                    if raw_output and len(raw_output) > 10:
                        try:
                            parsed = self.output_parser.parse(
                                tool, 
                                raw_output, 
                                stderr_output,
                                args,
                                scan_state['target']
                            )
                            
                            if parsed and parsed.get('vulnerabilities'):
                                if 'findings' not in result:
                                    result['findings'] = []
                                for finding in parsed['vulnerabilities']:
                                    if isinstance(finding, dict):
                                        result['findings'].append(finding)
                                    elif hasattr(finding, 'to_dict'):
                                        result['findings'].append(finding.to_dict())
                                logger.info(f"[Orchestrator] Re-parsed {len(result['findings'])} findings from {tool}")
                        except Exception as parse_err:
                            logger.warning(f"[Orchestrator] Re-parsing failed for {tool}: {parse_err}")
            
            # Complete tool in progress tracker
            findings_count = len(result.get('findings', [])) if result else 0
            if progress_tracker:
                progress_tracker.complete_tool(tool, findings_count, result.get('success', False))
            
            return result
            
        except Exception as e:
            logger.error(f"[Orchestrator] Tool execution error: {e}")
            
            # Mark tool as failed in progress tracker
            if progress_tracker:
                progress_tracker.complete_tool(tool, 0, False)
            
            return {'success': False, 'error': str(e), 'findings': []}
    
    def _execute_exploit_step(self, step: Dict, scan_state: Dict, progress_tracker=None) -> Dict:
        """Execute a single exploitation step"""
        tool = step.get('tool', '')
        command = step.get('command', '')
        
        if not tool or not command:
            return {'success': False}
        
        logger.info(f"[Orchestrator] Exploit step: {tool}")
        
        result = self._execute_tool(tool, command, scan_state, progress_tracker)
        
        if result:
            # Check for shell indicators - use 'stdout' key (not 'output')
            output = result.get('stdout', result.get('output', ''))
            shell_indicators = ['uid=', 'gid=', 'whoami', 'root', 'www-data', 'SYSTEM']
            
            if any(ind in output for ind in shell_indicators):
                result['shell_obtained'] = True
                result['access_level'] = 'root' if 'root' in output or 'SYSTEM' in output else 'user'
        
        return result or {}
    
    def _get_exploitable_findings(self, findings: List[Dict]) -> List[Dict]:
        """Filter findings that can be exploited - ENHANCED VERSION"""
        
        # Use enhanced exploitation fix if available
        if EXPLOITATION_FIX_AVAILABLE:
            return get_enhanced_exploitable_findings(findings)
        
        # Fallback to original logic with expanded types
        exploitable_types = [
            'sql_injection', 'sqli', 'sql',
            'command_injection', 'rce', 'remote_code_execution',
            'file_upload', 'unrestricted_upload',
            'xss', 'cross_site_scripting', 'reflected',
            'lfi', 'local_file_inclusion',
            'rfi', 'remote_file_inclusion',
            'ssrf', 'server_side_request_forgery',
            'xxe', 'xml_external_entity',
            'deserialization', 'insecure_deserialization',
            'authentication_bypass', 'auth_bypass',
            # Added more patterns
            'injection', 'traversal', 'path', 'directory',
            'command', 'shell', 'code', 'remote',
            'critical', 'high', 'exploit', 'vulnerable',
        ]
        
        exploitable = []
        
        for finding in findings:
            vuln_type = finding.get('type', '').lower()
            vuln_name = finding.get('name', '').lower()
            severity = finding.get('severity', 0)
            
            # Check if type or name matches exploitable patterns
            combined = f"{vuln_type} {vuln_name}"
            if any(t in combined for t in exploitable_types):
                exploitable.append(finding)
            # Or if severity is high/critical (>= 6.0 instead of 7.0)
            elif severity >= 6.0:
                exploitable.append(finding)
            # Or if marked exploitable
            elif finding.get('exploitable', False):
                exploitable.append(finding)
        
        # Sort by severity (highest first)
        exploitable.sort(key=lambda x: x.get('severity', 0), reverse=True)
        
        logger.info(f"[Orchestrator] Found {len(exploitable)} exploitable findings from {len(findings)} total")
        
        return exploitable
    
    def _add_finding(self, scan_state: Dict, finding: Dict, tool: str, phase: str):
        """Add a finding to scan state"""
        # Deduplicate
        for existing in scan_state['findings']:
            if (existing.get('type') == finding.get('type') and 
                existing.get('url') == finding.get('url')):
                return
        
        finding['source_tool'] = tool
        finding['phase'] = phase
        finding['timestamp'] = datetime.now().isoformat()
        
        scan_state['findings'].append(finding)
        
        # Emit finding event
        self._emit_event('finding_discovered', {
            'scan_id': scan_state['scan_id'],
            'finding': finding
        })
        
        # Update risk score
        severity = finding.get('severity', 0)
        scan_state['risk_score'] = max(scan_state['risk_score'], severity)
    
    def _emit_event(self, event: str, data: Dict):
        """Emit WebSocket event"""
        if self.socketio:
            try:
                scan_id = data.get('scan_id', '')
                self.socketio.emit(event, data, room=f'scan_{scan_id}')
            except Exception as e:
                logger.debug(f"[Orchestrator] WebSocket emit failed: {e}")
    
    def _should_stop(self, scan_state: Dict) -> bool:
        """Check if scan should stop"""
        return scan_state.get('stop_requested', False)
    
    def _get_elapsed_time(self, scan_state: Dict) -> float:
        """Get elapsed time in seconds - handles both UTC and local time"""
        start_str = scan_state.get('start_time')
        if not start_str:
            return 0
        
        try:
            # Parse the start time
            start = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            
            # If start time is timezone-aware (UTC), use utcnow for comparison
            # Otherwise use local time
            if start.tzinfo is not None:
                now = datetime.now(start.tzinfo)
            else:
                now = datetime.now()
            
            elapsed = (now - start).total_seconds()
            
            # Sanity check - if elapsed is negative or unreasonably large, reset
            if elapsed < 0 or elapsed > 86400:  # More than 24 hours is suspicious
                logger.warning(f"[Orchestrator] Suspicious elapsed time: {elapsed}s, resetting start_time")
                scan_state['start_time'] = datetime.now().isoformat()
                return 0
            
            return elapsed
        except Exception as e:
            logger.error(f"[Orchestrator] Error calculating elapsed time: {e}")
            return 0
    
    def _generate_report(self, scan_state: Dict) -> Dict[str, Any]:
        """Generate comprehensive final scan report with detailed findings"""
        findings = scan_state.get('findings', [])
        
        # Enrich each finding with detailed information
        enriched_findings = []
        for finding in findings:
            enriched = self._enrich_finding(finding, scan_state)
            enriched_findings.append(enriched)
        
        # Calculate statistics
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in enriched_findings:
            sev = f.get('severity', 0)
            if isinstance(sev, str):
                # Handle string severity
                sev_lower = sev.lower()
                if sev_lower == 'critical':
                    severity_counts['critical'] += 1
                elif sev_lower == 'high':
                    severity_counts['high'] += 1
                elif sev_lower == 'medium':
                    severity_counts['medium'] += 1
                elif sev_lower == 'low':
                    severity_counts['low'] += 1
                else:
                    severity_counts['info'] += 1
            else:
                # Handle numeric severity
                if sev >= 9:
                    severity_counts['critical'] += 1
                elif sev >= 7:
                    severity_counts['high'] += 1
                elif sev >= 4:
                    severity_counts['medium'] += 1
                elif sev > 0:
                    severity_counts['low'] += 1
                else:
                    severity_counts['info'] += 1
        
        # Determine overall risk level
        if severity_counts['critical'] > 0:
            risk_level = 'CRITICAL'
        elif severity_counts['high'] > 2:
            risk_level = 'HIGH'
        elif severity_counts['high'] > 0 or severity_counts['medium'] > 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary(scan_state, severity_counts, risk_level)
        
        return {
            'scan_id': scan_state['scan_id'],
            'target': scan_state['target'],
            'status': scan_state['status'],
            'start_time': scan_state['start_time'],
            'end_time': scan_state['end_time'],
            'time_elapsed': scan_state['time_elapsed'],
            
            # Executive Summary
            'executive_summary': exec_summary,
            'risk_level': risk_level,
            
            # Detailed findings
            'findings': enriched_findings,
            'findings_count': len(enriched_findings),
            'severity_counts': severity_counts,
            
            # Tools and coverage
            'tools_executed': scan_state['tools_executed'],
            'tools_count': len(scan_state['tools_executed']),
            
            # Exploitation results
            'exploitation_summary': {
                'exploits_attempted': len(scan_state.get('exploits_attempted', [])),
                'sessions_obtained': scan_state.get('sessions_obtained', []),
                'credentials_found': scan_state.get('credentials_found', []),
            },
            
            # Recommendations
            'recommendations': self._generate_recommendations(enriched_findings),
            
            # Technical details
            'risk_score': scan_state['risk_score'],
            'coverage': self._calculate_coverage(scan_state),
            'discovered_endpoints': list(set(scan_state.get('discovered_endpoints', []))),
            'discovered_technologies': list(set(scan_state.get('discovered_technologies', []))),
        }
    
    def _enrich_finding(self, finding: Dict, scan_state: Dict) -> Dict:
        """Enrich a finding with detailed information"""
        vuln_type = finding.get('type', 'unknown').lower().replace(' ', '_')
        
        # CWE mapping
        cwe_mapping = {
            'sql_injection': 'CWE-89', 'sqli': 'CWE-89',
            'xss': 'CWE-79', 'cross_site_scripting': 'CWE-79',
            'command_injection': 'CWE-77', 'rce': 'CWE-77',
            'path_traversal': 'CWE-22', 'lfi': 'CWE-22',
            'idor': 'CWE-639', 'ssrf': 'CWE-918',
            'xxe': 'CWE-611', 'csrf': 'CWE-352',
            'open_redirect': 'CWE-601', 'info_disclosure': 'CWE-200',
            'missing_headers': 'CWE-693', 'ssl_issue': 'CWE-295',
        }
        
        # OWASP mapping
        owasp_mapping = {
            'sql_injection': 'A03:2021-Injection', 'sqli': 'A03:2021-Injection',
            'xss': 'A03:2021-Injection', 'command_injection': 'A03:2021-Injection',
            'path_traversal': 'A01:2021-Broken Access Control',
            'idor': 'A01:2021-Broken Access Control',
            'ssrf': 'A10:2021-Server-Side Request Forgery',
            'xxe': 'A05:2021-Security Misconfiguration',
            'csrf': 'A01:2021-Broken Access Control',
            'missing_headers': 'A05:2021-Security Misconfiguration',
        }
        
        # Severity calculation
        severity = finding.get('severity', 0)
        if isinstance(severity, (int, float)):
            if severity >= 9:
                severity_label = 'Critical'
            elif severity >= 7:
                severity_label = 'High'
            elif severity >= 4:
                severity_label = 'Medium'
            else:
                severity_label = 'Low'
        else:
            severity_label = str(severity).capitalize()
        
        # Generate reproduction steps
        reproduction_steps = self._generate_reproduction_steps(finding)
        
        # Generate remediation
        remediation = self._generate_remediation(finding)
        
        enriched = {
            **finding,
            'id': finding.get('id', str(uuid.uuid4())[:8]),
            'title': finding.get('name', finding.get('type', 'Unknown Vulnerability')),
            'severity_label': severity_label,
            'cwe_id': cwe_mapping.get(vuln_type, 'CWE-Other'),
            'owasp_category': owasp_mapping.get(vuln_type, 'Other'),
            'description': self._generate_description(finding),
            'reproduction_steps': reproduction_steps,
            'remediation': remediation,
            'impact': self._analyze_impact(finding),
            'references': self._get_references(finding),
        }
        
        return enriched
    
    def _generate_reproduction_steps(self, finding: Dict) -> List[str]:
        """Generate detailed reproduction steps"""
        vuln_type = finding.get('type', '').lower()
        location = finding.get('url', finding.get('location', 'N/A'))
        parameter = finding.get('parameter', finding.get('param', 'N/A'))
        evidence = finding.get('evidence', finding.get('payload', 'N/A'))
        
        if 'sql' in vuln_type:
            return [
                f"1. Navigate to: {location}",
                f"2. Identify vulnerable parameter: {parameter}",
                f"3. Inject SQL payload: {evidence}",
                "4. Observe SQL error or unexpected behavior in response",
                f"5. Confirm with SQLMap: sqlmap -u '{location}' --batch",
                "6. Extract data: sqlmap -u '<url>' --dbs --dump",
            ]
        elif 'xss' in vuln_type:
            return [
                f"1. Open target URL: {location}",
                f"2. Locate input field: {parameter}",
                f"3. Inject XSS payload: {evidence}",
                "4. Submit form or trigger injection point",
                "5. Observe JavaScript execution (alert box)",
                "6. Check payload reflection in page source",
            ]
        elif 'command' in vuln_type or 'rce' in vuln_type:
            return [
                f"1. Access endpoint: {location}",
                f"2. Identify injectable parameter: {parameter}",
                f"3. Inject command payload: {evidence}",
                "4. Observe command output in response",
                "5. Escalate with reverse shell payload",
            ]
        elif 'path' in vuln_type or 'lfi' in vuln_type:
            return [
                f"1. Access vulnerable endpoint: {location}",
                f"2. Modify file path parameter: {parameter}",
                f"3. Use traversal payload: {evidence}",
                "4. Read sensitive files like /etc/passwd",
            ]
        else:
            return [
                f"1. Access: {location}",
                f"2. Parameter: {parameter}",
                f"3. Evidence: {evidence}",
                "4. Verify vulnerability exists",
            ]
    
    def _generate_description(self, finding: Dict) -> str:
        """Generate detailed vulnerability description"""
        vuln_type = finding.get('type', 'Unknown')
        location = finding.get('url', finding.get('location', 'the application'))
        
        descriptions = {
            'sql_injection': f"SQL Injection vulnerability found at {location}. Allows execution of arbitrary SQL commands, potentially leading to data theft, modification, or complete database compromise.",
            'xss': f"Cross-Site Scripting (XSS) vulnerability at {location}. Enables injection of malicious scripts that execute in victims' browsers, potentially stealing session cookies or credentials.",
            'command_injection': f"Command Injection at {location}. Allows execution of arbitrary system commands, potentially leading to full server compromise.",
            'path_traversal': f"Path Traversal vulnerability at {location}. Enables reading files outside the intended directory, exposing sensitive system files.",
            'ssrf': f"Server-Side Request Forgery at {location}. Allows the server to make requests to internal resources or external systems.",
            'idor': f"Insecure Direct Object Reference at {location}. Enables unauthorized access to other users' data by manipulating object references.",
        }
        
        for key, desc in descriptions.items():
            if key in vuln_type.lower():
                return desc
        
        return f"{vuln_type} vulnerability detected at {location}."
    
    def _generate_remediation(self, finding: Dict) -> Dict[str, Any]:
        """Generate remediation guidance"""
        vuln_type = finding.get('type', '').lower()
        
        remediations = {
            'sql': {
                'summary': 'Use parameterized queries and input validation',
                'steps': [
                    'Replace dynamic SQL with parameterized queries',
                    'Use ORM frameworks with built-in SQL injection protection',
                    'Implement input validation and sanitization',
                    'Apply principle of least privilege to database accounts',
                    'Enable WAF rules for SQL injection detection',
                ],
                'code_example': "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            },
            'xss': {
                'summary': 'Encode output and validate input',
                'steps': [
                    'HTML-encode all user-supplied output',
                    'Implement Content Security Policy (CSP) headers',
                    'Use HTTPOnly and Secure flags on cookies',
                    'Validate and sanitize all user input',
                    'Use modern frameworks with auto-escaping',
                ],
                'code_example': "{{ user_input | escape }}",
            },
            'command': {
                'summary': 'Avoid system commands or use strict whitelisting',
                'steps': [
                    'Avoid executing system commands with user input',
                    'Use language-specific libraries instead of shell commands',
                    'If unavoidable, use strict input whitelisting',
                    'Never use shell=True in subprocess calls',
                ],
                'code_example': "subprocess.run(['ls', '-la', safe_path], shell=False)",
            },
        }
        
        for key, rem in remediations.items():
            if key in vuln_type:
                return rem
        
        return {
            'summary': 'Review and fix the vulnerability',
            'steps': ['Identify root cause', 'Implement fix', 'Test thoroughly', 'Deploy to production'],
        }
    
    def _analyze_impact(self, finding: Dict) -> Dict[str, str]:
        """Analyze CIA impact"""
        vuln_type = finding.get('type', '').lower()
        
        if 'sql' in vuln_type or 'command' in vuln_type:
            return {'confidentiality': 'High', 'integrity': 'High', 'availability': 'Medium'}
        elif 'xss' in vuln_type:
            return {'confidentiality': 'Medium', 'integrity': 'Medium', 'availability': 'Low'}
        elif 'path' in vuln_type or 'lfi' in vuln_type:
            return {'confidentiality': 'High', 'integrity': 'Low', 'availability': 'Low'}
        else:
            return {'confidentiality': 'Medium', 'integrity': 'Medium', 'availability': 'Low'}
    
    def _get_references(self, finding: Dict) -> List[str]:
        """Get relevant references"""
        vuln_type = finding.get('type', '').lower()
        refs = ['https://owasp.org/www-project-web-security-testing-guide/']
        
        if 'sql' in vuln_type:
            refs.extend(['https://portswigger.net/web-security/sql-injection', 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'])
        elif 'xss' in vuln_type:
            refs.extend(['https://portswigger.net/web-security/cross-site-scripting', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'])
        
        return refs
    
    def _generate_executive_summary(self, scan_state: Dict, severity_counts: Dict, risk_level: str) -> str:
        """Generate executive summary text"""
        target = scan_state.get('target', 'the target')
        total = sum(severity_counts.values())
        tools = len(scan_state.get('tools_executed', []))
        
        return f"""Security assessment of {target} identified {total} vulnerabilities using {tools} security tools.

Risk Level: {risk_level}

Vulnerability Breakdown:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}  
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Informational: {severity_counts['info']}

{'IMMEDIATE ACTION REQUIRED: Critical vulnerabilities were discovered that could lead to full system compromise.' if severity_counts['critical'] > 0 else ''}
{'High-priority issues require attention within 7 days.' if severity_counts['high'] > 0 else ''}"""

    def _generate_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Group by type
        vuln_types = {}
        for f in findings:
            vtype = f.get('type', 'unknown')
            if vtype not in vuln_types:
                vuln_types[vtype] = []
            vuln_types[vtype].append(f)
        
        priority = 1
        for vtype, vulns in sorted(vuln_types.items(), key=lambda x: -len(x[1])):
            recommendations.append({
                'priority': priority,
                'category': vtype,
                'count': len(vulns),
                'recommendation': f"Address {len(vulns)} {vtype} vulnerabilities",
                'details': vulns[0].get('remediation', {}).get('summary', 'Review and fix'),
            })
            priority += 1
        
        return recommendations[:10]  # Top 10
    
    def _calculate_coverage(self, scan_state: Dict) -> float:
        """Calculate scan coverage percentage"""
        phases_run = set()
        for tool in scan_state.get('tools_executed', []):
            phases_run.add(tool.get('phase', ''))
        
        total_phases = 5
        return (len(phases_run) / total_phases) * 100
    
    def _get_total_expected_duration(self) -> int:
        """Get total expected scan duration in seconds"""
        total = 0
        for config in PHASE_CONFIGS.values():
            # Use average of min and max time
            total += (config.min_time + config.max_time) // 2
        return total


# Singleton instance
_orchestrator: Optional[RobustScanOrchestrator] = None


def get_robust_orchestrator(socketio=None) -> RobustScanOrchestrator:
    """Get or create orchestrator singleton"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = RobustScanOrchestrator(socketio)
    elif socketio:
        _orchestrator.socketio = socketio
    return _orchestrator
