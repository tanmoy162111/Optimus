"""Fully Autonomous Pentest Agent - INTELLIGENT, Adaptive, Self-Learning"""
import uuid
import logging
import time
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# Add intelligence import
try:
    from intelligence import get_optimus_brain
    INTELLIGENCE_AVAILABLE = True
except ImportError:
    INTELLIGENCE_AVAILABLE = False
    logger.warning("Intelligence module not available")

from inference.tool_selector import PhaseAwareToolSelector
from inference.phase_controller import PhaseController
from inference.tool_manager import ToolManager
from knowledge.vulnerability_kb import VulnerabilityKnowledgeBase
from inference.dynamic_tool_database import DynamicToolDatabase
from inference.target_analyzer import TargetAnalyzer
from inference.strategy_selector import StrategySelector
from inference.learning_module import RealTimeLearningModule

logger = logging.getLogger(__name__)

class AutonomousPentestAgent:
    """Main autonomous pentesting orchestration engine"""
    
    def __init__(self, socketio=None):
        print(f"\n[AutonomousPentestAgent] Initializing...")
        
        print("[AutonomousPentestAgent] Creating PhaseAwareToolSelector...")
        self.tool_selector = PhaseAwareToolSelector()
        
        print("[AutonomousPentestAgent] Creating PhaseController...")
        self.phase_controller = PhaseController()
        
        print("[AutonomousPentestAgent] Creating ToolManager...")
        self.tool_manager = ToolManager(socketio)  # Pass socketio to ToolManager
        
        print("[AutonomousPentestAgent] Creating VulnerabilityKnowledgeBase...")
        self.knowledge_base = VulnerabilityKnowledgeBase()
        
        print("[AutonomousPentestAgent] Creating DynamicToolDatabase...")
        self.tool_db = DynamicToolDatabase()
        
        print("[AutonomousPentestAgent] Creating StrategySelector...")
        self.strategy_selector = StrategySelector()  # NEW
        
        print("[AutonomousPentestAgent] Creating RealTimeLearningModule...")
        self.learning_module = RealTimeLearningModule()  # NEW
        
        # Initialize Deep RL agent
        self.deep_rl_agent = None
        try:
            from training.deep_rl_agent import DeepRLAgent
            from config import Config
            
            if getattr(Config, 'DEEP_RL_ENABLED', True):
                self.deep_rl_agent = DeepRLAgent(
                    num_actions=getattr(Config, 'DEEP_RL_NUM_ACTIONS', 35),
                    state_dim=getattr(Config, 'DEEP_RL_STATE_DIM', 128),
                    use_per=getattr(Config, 'DEEP_RL_USE_PER', True),
                    use_noisy=getattr(Config, 'DEEP_RL_USE_NOISY', True)
                )
                # Try to load existing weights
                self.deep_rl_agent.load()
                print("[AutonomousPentestAgent] Deep RL agent initialized")
        except Exception as e:
            logger.warning(f"[AutonomousPentestAgent] Deep RL not available: {e}")
        
        # Initialize intelligence layer (optional but enhances decisions)
        self.optimus_brain = None
        if INTELLIGENCE_AVAILABLE:
            try:
                self.optimus_brain = get_optimus_brain()
                print("[AutonomousPentestAgent] OptimusBrain initialized")
            except Exception as e:
                logger.warning(f"Could not initialize OptimusBrain: {e}")
        
        self.socketio = socketio  # Store socketio reference
        print("[AutonomousPentestAgent]  Initialization complete!")
        logger.info("🤖 Autonomous Pentest Agent initialized")
    
    def run_autonomous_scan(self, target: str, scan_config: Dict = None) -> Dict[str, Any]:
        """Main autonomous scanning loop - FULLY INTELLIGENT"""
        print(f"\n{'='*60}")
        print(f"[AutonomousPentestAgent] run_autonomous_scan starting!")
        print(f"  target: {target}")
        print(f"  config: {scan_config}")
        print(f"{'='*60}")
        
        if scan_config is None:
            scan_config = {}
            
        # Check if this is fully autonomous mode
        if scan_config.get('self_directed', False):
            return self._run_fully_autonomous_scan(target, scan_config)
        
        print("[AutonomousPentestAgent] Initializing scan state...")
        scan_state = self._initialize_scan_state(target, scan_config)
        print(f"[AutonomousPentestAgent] Scan state initialized: {scan_state.get('scan_id')}")
        
        max_iterations = 100
        iteration = 0
        stalled_iterations = 0
        last_findings_count = 0
        
        # Track tool execution attempts
        tool_execution_attempts = {}
        max_tool_attempts = 5
        
        # Track approach changes
        approach_changes = 0
        max_approach_changes = 3
        
        consecutive_empty_recommendations = 0
        MAX_EMPTY_RECOMMENDATIONS = 5
        MAX_STALLED_ITERATIONS = 20
        
        while not self._is_scan_complete(scan_state) and iteration < max_iterations:
            iteration += 1
            logger.info(f"=== Iteration {iteration} | Phase: {scan_state['phase']} ===")
            
            elapsed_time = (datetime.now() - datetime.fromisoformat(scan_state['start_time'])).total_seconds()
            if elapsed_time < 60:
                stalled_iterations = 0
            
            # NEW: Check if strategy should change
            if self.strategy_selector.should_change_strategy(scan_state):
                new_strategy = self.strategy_selector.select_strategy(scan_state)
                old_strategy = scan_state.get('strategy', 'none')
                
                if new_strategy != old_strategy:
                    logger.info("Strategy change: %s -> %s", old_strategy, new_strategy)
                    scan_state['strategy'] = new_strategy
                    scan_state['strategy_changes'] += 1
                    
                    # Reset tool execution limits for new strategy
                    tool_execution_attempts = {}
                    stalled_iterations = 0
            
            # Check progress
            current_findings_count = len(scan_state['findings'])
            if current_findings_count > last_findings_count:
                # New finding! Update tracking
                scan_state['last_finding_iteration'] = len(scan_state['tools_executed'])
                stalled_iterations = 0
            else:
                stalled_iterations += 1
                
            last_findings_count = current_findings_count
            
            # Force phase change if stalled too long
            if stalled_iterations >= MAX_STALLED_ITERATIONS:
                logger.warning("Scan stalled for %d iterations, forcing phase transition", stalled_iterations)
                next_phase = self.phase_controller.get_next_phase(scan_state['phase'], scan_state)
                scan_state['phase'] = next_phase
                scan_state['phase_start_time'] = datetime.now().isoformat()
                scan_state['strategy'] = self.strategy_selector.select_strategy(scan_state)
                stalled_iterations = 0
                continue
            
            # Get tool recommendation
            tool_recommendation = self._get_tool_recommendation(scan_state)
            recommended_tools = tool_recommendation.get('tools', [])
            
            # Handle empty recommendations
            if not recommended_tools:
                consecutive_empty_recommendations += 1
                logger.warning("No tools recommended (%d/%d)", consecutive_empty_recommendations, MAX_EMPTY_RECOMMENDATIONS)
                
                if consecutive_empty_recommendations >= MAX_EMPTY_RECOMMENDATIONS:
                    suggested_next = tool_recommendation.get('suggested_next_phase')
                    current_phase = scan_state['phase']
                    
                    if suggested_next and suggested_next != current_phase:
                        logger.info("Forcing phase transition: %s -> %s", current_phase, suggested_next)
                        scan_state['phase'] = suggested_next
                        scan_state['phase_start_time'] = datetime.now().isoformat()
                        consecutive_empty_recommendations = 0
                        
                        if self.socketio:
                            self.socketio.emit('phase_transition', {
                                'scan_id': scan_state['scan_id'],
                                'from': current_phase,
                                'to': suggested_next
                            }, room=f"scan_{scan_state['scan_id']}")
                        continue
                    else:
                        logger.info("No more phases, ending scan")
                        break
                
                time.sleep(1)
                continue
            
            consecutive_empty_recommendations = 0
            
            # Execute tool
            tool_to_execute = recommended_tools[0]
            
            # Check repetition
            tools_executed = [t['tool'] if isinstance(t, dict) else t 
                             for t in scan_state.get('tools_executed', [])]
            tool_count = tools_executed.count(tool_to_execute)
            
            if tool_count >= 3:
                logger.warning(f"Tool {tool_to_execute} executed {tool_count} times, blacklisting")
                if 'blacklisted_tools' not in scan_state:
                    scan_state['blacklisted_tools'] = []
                if tool_to_execute not in scan_state['blacklisted_tools']:
                    scan_state['blacklisted_tools'].append(tool_to_execute)
                continue
            
            # Generate parameters and execute
            parameters = self._generate_tool_parameters(tool_to_execute, scan_state, {})
            
            logger.info(f"Executing tool: {tool_to_execute}")
            result = self._execute_tool_real(tool_to_execute, target, scan_state, parameters)
            
            # Update state
            self._update_scan_state_real(scan_state, result)
            
            # Check for phase transition
            next_phase = self.phase_controller.should_transition(scan_state)
            if next_phase != scan_state['phase']:
                logger.info(f"📍 Phase transition: {scan_state['phase']} → {next_phase}")
                scan_state['phase'] = next_phase
                scan_state['phase_start_time'] = datetime.now().isoformat()
                scan_state['strategy'] = self.strategy_selector.select_strategy(scan_state)
                stalled_iterations = 0
                approach_changes = 0  # Reset approach changes when moving to new phase
            
            time.sleep(0.5)
            
        scan_state['status'] = 'completed'
        return self._generate_final_report(scan_state)

    def _run_fully_autonomous_scan(self, target: str, scan_config: Dict) -> Dict[str, Any]:
        """Run fully autonomous scan with intelligent decision making"""
        scan_state = self._initialize_fully_autonomous_state(target, scan_config)
        decision_log = []
        
        print("[AutonomousAgent] Starting fully autonomous scan...")
        
        iteration = 0
        max_iterations = scan_config.get('max_iterations', 50)
        
        while not self._is_fully_autonomous_scan_complete(scan_state) and iteration < max_iterations:
            iteration += 1
            print(f"\n[AutonomousAgent] Iteration {iteration}")
            
            # Analyze current situation
            analysis = self._analyze_situation_fully_autonomous(scan_state)
            
            # Make autonomous decision
            decision = self._make_autonomous_decision(scan_state, analysis)
            decision['iteration'] = iteration
            decision['timestamp'] = datetime.now().isoformat()
            decision_log.append(decision)
            
            print(f"[AutonomousAgent] Decision: {decision['action']} - {decision['reason']}")
            
            # Execute decision
            if decision['action'] == 'execute_tool':
                tool_name = decision['tool']
                parameters = decision['parameters']
                
                print(f"[AutonomousAgent] Executing {tool_name} with params: {parameters}")
                
                # Execute tool
                result = self._execute_tool_with_timeout(tool_name, target, parameters)
                
                # Process results
                self._process_tool_results(scan_state, result)
                
                # Learn from execution
                self._learn_from_execution(tool_name, result, scan_state)
                
            elif decision['action'] == 'change_approach':
                new_approach = decision['new_approach']
                print(f"[AutonomousAgent] Changing approach to: {new_approach}")
                scan_state['current_approach'] = new_approach
                scan_state['adaptive_choices'].append({
                    'type': 'approach_change',
                    'from': scan_state.get('current_approach', 'initial'),
                    'to': new_approach,
                    'reason': decision['reason'],
                    'iteration': iteration
                })
                
            elif decision['action'] == 'change_phase':  # NEW: Handle phase changes
                new_phase = decision['new_phase']
                print(f"[AutonomousAgent] Changing phase to: {new_phase}")
                scan_state['phase'] = new_phase
                scan_state['phase_start_time'] = datetime.now().isoformat()
                scan_state['adaptive_choices'].append({
                    'type': 'phase_change',
                    'from': scan_state.get('phase', 'reconnaissance'),
                    'to': new_phase,
                    'reason': decision['reason'],
                    'iteration': iteration
                })
                
            elif decision['action'] == 'terminate':
                print(f"[AutonomousAgent] Terminating scan: {decision['reason']}")
                break
            
            # Update coverage
            scan_state['coverage'] = self._calculate_coverage_real(scan_state)
            
            # Small delay to prevent overwhelming the system
            time.sleep(0.1)
        
        print("[AutonomousAgent] Fully autonomous scan completed.")
        scan_state['decision_log'] = decision_log
        return self._generate_fully_autonomous_report(scan_state)

    def _initialize_fully_autonomous_state(self, target: str, scan_config: Dict) -> Dict[str, Any]:
        """Initialize fully autonomous scan state"""
        from inference.target_analyzer import TargetAnalyzer
        
        # Perform target analysis
        analyzer = TargetAnalyzer()
        target_profile = analyzer.analyze_target(target)
        
        scan_state = {
            'scan_id': str(uuid.uuid4()),
            'target': target,
            'target_profile': target_profile,
            'phase': 'reconnaissance',  # Add phase for compatibility
            'findings': [],
            'tools_executed': [],
            'coverage': 0,
            'start_time': datetime.now().isoformat(),
            'config': scan_config,
            'technologies_detected': target_profile.get('technologies', []),
            'current_approach': 'initial_reconnaissance',
            'adaptive_choices': [],
            'strategy': 'adaptive',
            'strategy_changes': 0,
        }
        
        return scan_state

    def _is_fully_autonomous_scan_complete(self, scan_state: Dict) -> bool:
        """Determine if fully autonomous scan is complete"""
        # Check time budget
        time_budget = scan_state.get('config', {}).get('max_time', 3600)
        start_time = datetime.fromisoformat(scan_state['start_time'])
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if elapsed >= time_budget:
            logger.info(f"Time budget exhausted: {elapsed}s / {time_budget}s")
            return True
            
        # Check for completion criteria
        findings = scan_state.get('findings', [])
        tools_executed = scan_state.get('tools_executed', [])
        
        # Complete if we have substantial findings and have tried many tools
        if len(findings) >= 10 and len(tools_executed) >= 20:
            return True
            
        return False

    def _analyze_situation_fully_autonomous(self, scan_state: Dict) -> Dict[str, Any]:
        """Analyze current situation in fully autonomous mode"""
        findings = scan_state.get('findings', [])
        tools_executed = scan_state.get('tools_executed', [])
        technologies = scan_state.get('technologies_detected', [])
        
        # Count unique tools executed
        unique_tools = list(set([t['tool'] if isinstance(t, dict) else t for t in tools_executed]))
        
        # Analyze findings
        finding_types = {}
        severity_levels = []
        
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            finding_types[ftype] = finding_types.get(ftype, 0) + 1
            severity = finding.get('severity', 0)
            severity_levels.append(severity)
        
        avg_severity = sum(severity_levels) / len(severity_levels) if severity_levels else 0
        
        # NEW: Match findings with knowledge base to determine attack patterns
        attack_patterns = self._match_findings_to_attack_patterns(findings)
        suggested_phases = self._suggest_next_phases_based_on_findings(findings, scan_state.get('phase', 'reconnaissance'))
        
        analysis = {
            'total_findings': len(findings),
            'unique_tools_executed': len(unique_tools),
            'finding_types': finding_types,
            'average_severity': avg_severity,
            'technologies_detected': technologies,
            'coverage_estimate': min(len(findings) / 5.0, 1.0),  # Estimate coverage
            'tools_executed_recently': [t['tool'] if isinstance(t, dict) else t 
                                       for t in tools_executed[-5:]],  # Last 5 tools
            'attack_patterns': attack_patterns,  # NEW: Identified attack patterns
            'suggested_phases': suggested_phases  # NEW: Suggested next phases
        }
        
        print(f"[DEBUG] Analysis - Total findings: {len(findings)}")
        print(f"[DEBUG] Analysis - Unique tools executed: {len(unique_tools)}")
        print(f"[DEBUG] Analysis - Finding types: {finding_types}")
        print(f"[DEBUG] Analysis - Average severity: {avg_severity}")
        print(f"[DEBUG] Analysis - Technologies detected: {technologies}")
        print(f"[DEBUG] Analysis - Attack patterns: {attack_patterns}")  # NEW
        print(f"[DEBUG] Analysis - Suggested phases: {suggested_phases}")  # NEW
        
        return analysis

    def _match_findings_to_attack_patterns(self, findings: List[Dict]) -> List[Dict]:
        """
        Match findings with knowledge base to identify attack patterns
        """
        attack_patterns = []
        
        # Group findings by type
        findings_by_type = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            if ftype not in findings_by_type:
                findings_by_type[ftype] = []
            findings_by_type[ftype].append(finding)
        
        # For each finding type, get attack pattern information from knowledge base
        for ftype, ffindings in findings_by_type.items():
            # Get exploitation technique from knowledge base
            technique_info = self.knowledge_base.get_exploitation_technique(ftype)
            if technique_info:
                pattern = {
                    'type': ftype,
                    'count': len(ffindings),
                    'techniques': technique_info.get('techniques', []),
                    'tools': technique_info.get('tools', []),
                    'detection_signatures': technique_info.get('detection_signatures', []),
                    'cwe_id': self.knowledge_base.map_to_cwe({'type': ftype}),
                    'severity_range': [min(f.get('severity', 0) for f in ffindings),
                                     max(f.get('severity', 0) for f in ffindings)]
                }
                attack_patterns.append(pattern)
        
        return attack_patterns

    def _suggest_next_phases_based_on_findings(self, findings: List[Dict], current_phase: str) -> List[str]:
        """
        Suggest next phases based on findings and current phase
        """
        # Phase progression logic based on findings
        phase_suggestions = {
            'reconnaissance': ['scanning', 'exploitation'],
            'scanning': ['exploitation', 'post_exploitation'],
            'exploitation': ['post_exploitation', 'covering_tracks'],
            'post_exploitation': ['covering_tracks'],
            'covering_tracks': []
        }
        
        # If we have high-severity findings, suggest exploitation
        high_severity_findings = [f for f in findings if f.get('severity', 0) >= 7.0]
        if high_severity_findings and current_phase in ['reconnaissance', 'scanning']:
            return ['exploitation'] + phase_suggestions.get(current_phase, [])
        
        # If we have exploitable findings, suggest post-exploitation
        exploitable_findings = [f for f in findings if f.get('exploitable', False)]
        if exploitable_findings and current_phase in ['exploitation']:
            return ['post_exploitation'] + phase_suggestions.get(current_phase, [])
        
        # Default suggestions based on current phase
        return phase_suggestions.get(current_phase, [])
    
    def _make_autonomous_decision(self, scan_state: Dict, analysis: Dict) -> Dict[str, Any]:
        """
        Make autonomous decision based on current state and analysis
        
        Returns:
            Decision dictionary with action and parameters
        """
        findings = analysis['total_findings']
        unique_tools = analysis['unique_tools_executed']
        finding_types = analysis['finding_types']
        recent_tools = analysis['tools_executed_recently']
        attack_patterns = analysis.get('attack_patterns', [])  # NEW: Attack patterns from knowledge
        suggested_phases = analysis.get('suggested_phases', [])  # NEW: Suggested phases
        
        # FIXED: Get tools from BOTH databases
        current_phase = scan_state.get('phase', 'reconnaissance')
        dynamic_tools = list(self.tool_db.tools.keys())
        kb_tools = list(self.tool_manager.tool_kb.command_templates.keys()) if hasattr(self.tool_manager, 'tool_kb') else []
        
        # Also get phase-appropriate tools from tool_selector
        phase_tools = self.tool_selector.phase_configs.get(current_phase, {}).get('allowed_tools', [])
        
        # Merge all tool sources, removing duplicates
        all_tools = list(set(dynamic_tools + kb_tools + phase_tools))
        
        print(f"[DEBUG] All available tools (merged): {len(all_tools)}")
        print(f"[DEBUG] Sources - Dynamic: {len(dynamic_tools)}, KB: {len(kb_tools)}, Phase: {len(phase_tools)}")
        print(f"[DEBUG] Recently executed tools: {recent_tools}")
        
        # Filter out recently executed and blacklisted tools
        blacklisted = scan_state.get('blacklisted_tools', [])
        available_tools = [tool for tool in all_tools 
                          if tool not in recent_tools and tool not in blacklisted]
        print(f"[DEBUG] Available tools after filtering: {len(available_tools)}")
        
        # NEW: If we have identified attack patterns, prioritize tools for those patterns
        if attack_patterns:
            pattern_tools = []
            for pattern in attack_patterns:
                pattern_tools.extend(pattern.get('tools', []))
            
            # Filter to available tools only
            pattern_tools = [tool for tool in pattern_tools if tool in available_tools]
            
            if pattern_tools:
                print(f"[DEBUG] Pattern-based tools: {pattern_tools}")
                return {
                    'action': 'execute_tool',
                    'tool': pattern_tools[0],
                    'parameters': self._generate_tool_parameters(pattern_tools[0], scan_state, analysis),
                    'reason': f'Executing {pattern_tools[0]} based on identified attack patterns: {[p["type"] for p in attack_patterns]}'
                }
        
        # If we have findings, explore related tools
        if findings > 0:
            # Prioritize tools based on finding types
            priority_tools = self._get_priority_tools_for_findings(finding_types, available_tools)
            print(f"[DEBUG] Priority tools based on findings: {priority_tools}")
            if priority_tools:
                return {
                    'action': 'execute_tool',
                    'tool': priority_tools[0],
                    'parameters': self._generate_tool_parameters(priority_tools[0], scan_state, analysis),
                    'reason': f'Exploring {priority_tools[0]} based on findings: {list(finding_types.keys())}'
                }
        
        # NEW: If we have suggested phases and current approach isn't working, consider phase change
        if suggested_phases and unique_tools >= 10 and findings < 3:
            # Consider transitioning to a suggested phase
            if suggested_phases and suggested_phases[0] != current_phase:
                print(f"[DEBUG] Suggested phase transition: {current_phase} -> {suggested_phases[0]}")
                return {
                    'action': 'change_phase',
                    'new_phase': suggested_phases[0],
                    'reason': f'Transitioning to {suggested_phases[0]} based on findings analysis'
                }
        
        # If we haven't executed many tools, try exploration
        if unique_tools < 15 and available_tools:  # Increased from 10 to 15
            exploration_tool = available_tools[0] if available_tools else 'nmap'
            print(f"[DEBUG] Exploring new tool: {exploration_tool}")
            return {
                'action': 'execute_tool',
                'tool': exploration_tool,
                'parameters': self._generate_tool_parameters(exploration_tool, scan_state, analysis),
                'reason': f'Exploring new tool: {exploration_tool}'
            }
        
        # If we've executed many tools but have few findings, change approach
        if unique_tools >= 15 and findings < 5:  # Increased thresholds
            print(f"[DEBUG] Many tools executed ({unique_tools}) but few findings ({findings}), changing approach")
            return {
                'action': 'change_approach',
                'new_approach': 'intensive_exploitation',
                'reason': f'Many tools executed ({unique_tools}) but few findings ({findings}), switching to intensive exploitation'
            }
        
        # Default: execute a random available tool
        if available_tools:
            tool = available_tools[0]
            print(f"[DEBUG] Default execution of tool: {tool}")
            return {
                'action': 'execute_tool',
                'tool': tool,
                'parameters': self._generate_tool_parameters(tool, scan_state, analysis),
                'reason': f'Default execution of {tool}'
            }
        
        # If no tools available, terminate
        print(f"[DEBUG] No more tools available to execute")
        return {
            'action': 'terminate',
            'reason': 'No more tools available to execute'
        }

    def _get_priority_tools_for_findings(self, finding_types: Dict[str, int], available_tools: List[str]) -> List[str]:
        """Get priority tools based on finding types"""
        tool_priorities = {
            'sql_injection': ['sqlmap', 'commix'],
            'xss': ['dalfox', 'xsser'],  # Add xsser as alternative to dalfox
            'web_vulnerabilities': ['nikto', 'nuclei'],
            'subdomains': ['subfinder', 'amass'],
            'ports_open': ['nmap', 'masscan'],
            'wordpress': ['wpscan'],
            'directories': ['ffuf', 'gobuster', 'dirb'],
            'cms': ['wpscan'],
            'outdated_software': ['nikto'],
            'misconfigurations': ['nuclei'],
            'information_disclosure': ['nikto'],
            'command_injection': ['commix']
        }
        
        priority_tools = []
        for ftype, count in finding_types.items():
            if count > 0 and ftype in tool_priorities:
                priority_tools.extend(tool_priorities[ftype])
        
        # Filter to available tools only
        priority_tools = [tool for tool in priority_tools if tool in available_tools]
        
        # Remove duplicates while preserving order
        seen = set()
        unique_priority_tools = []
        for tool in priority_tools:
            if tool not in seen:
                unique_priority_tools.append(tool)
                seen.add(tool)
        
        print(f"[DEBUG] Finding types: {finding_types}")
        print(f"[DEBUG] Priority tools before filtering: {[tool for ftype in finding_types.keys() if ftype in tool_priorities for tool in tool_priorities[ftype]]}")
        print(f"[DEBUG] Priority tools after filtering: {unique_priority_tools}")
        
        return unique_priority_tools

    def _generate_tool_parameters(self, tool_name: str, scan_state: Dict, analysis: Dict) -> Dict[str, Any]:
        """Generate appropriate parameters for a tool based on current state"""
        target = scan_state['target']
        findings = scan_state.get('findings', [])
        technologies = scan_state.get('technologies_detected', [])
        phase = scan_state.get('phase', 'reconnaissance')
        
        # Base parameters with ALL required fields
        parameters = {
            'aggressive': len(findings) < 3,
            'timeout': 180,  # Reasonable default
            'target_type': scan_state.get('target_profile', {}).get('type', 'web'),
            'autonomous_mode': True,
            'phase': phase,
            'findings': findings,
            'tools_executed': scan_state.get('tools_executed', []),
            'technologies_detected': technologies,
            'stealth_required': scan_state.get('stealth_required', False),
            'waf_detected': scan_state.get('waf_detected', False),
            'coverage': scan_state.get('coverage', 0.0),
        }
        
        # Tool-specific parameter generation
        if tool_name == 'nmap':
            parameters.update({
                'ports': '1-10000',
                'service_detection': True,
                'version_detection': True,
                'os_detection': False,  # Can be slow
            })
        elif tool_name == 'sqlmap':
            parameters.update({
                'level': 2 if phase == 'scanning' else 3,
                'risk': 2 if phase == 'scanning' else 3,
                'dbs': True,
                'batch': True,
            })
        elif tool_name == 'nikto':
            parameters.update({
                'ssl': 'https' in target.lower(),
                'tuning': '123456789' if len(findings) > 0 else '1234',
            })
        elif tool_name == 'nuclei':
            parameters.update({
                'severity': 'critical,high,medium' if phase == 'exploitation' else 'critical,high',
                'rate_limit': 150,
            })
        elif tool_name in ['gobuster', 'ffuf', 'dirb']:
            parameters.update({
                'wordlist': '/usr/share/dirb/wordlists/common.txt',
                'extensions': 'php,html,js,txt',
                'threads': 10,
            })
        elif tool_name in ['dalfox', 'xsser']:
            parameters.update({
                'blind': False,
                'skip_bav': True,
            })
        elif tool_name == 'commix':
            parameters.update({
                'level': 2,
                'batch': True,
            })
        elif tool_name == 'whatweb':
            parameters.update({
                'aggression': 3 if not scan_state.get('stealth_required') else 1,
            })
        elif tool_name in ['sublist3r', 'amass', 'subfinder']:
            parameters.update({
                'passive': True,
            })
        elif tool_name == 'wpscan':
            parameters.update({
                'enumerate': 'vp,vt,u',  # vulnerable plugins, themes, users
            })
        
        return parameters

    def conduct_scan(self, target: str, scan_config: Dict = None) -> Dict[str, Any]:
        """
        Alias for run_autonomous_scan to maintain compatibility with workflow engine
        """
        return self.run_autonomous_scan(target, scan_config)

    def _initialize_scan_state(self, target: str, scan_config: Dict) -> Dict[str, Any]:
        """Initialize scan state with intelligent target analysis"""
        from inference.target_analyzer import TargetAnalyzer
        
        # Perform target analysis
        analyzer = TargetAnalyzer()
        target_profile = analyzer.analyze_target(target)
        
        scan_state = {
            'scan_id': str(uuid.uuid4()),
            'target': target,
            'target_profile': target_profile,  # NEW: Store target profile
            'phase': 'reconnaissance',
            'findings': [],
            'tools_executed': [],
            'coverage': 0,
            'start_time': datetime.now().isoformat(),
            'config': scan_config,
            'technologies_detected': target_profile.get('technologies', []),
            'recently_used_tools': [],
            'phase_data': {},
            'blacklisted_tools': [],
            'strategy': 'adaptive',  # NEW: Current strategy
            'strategy_changes': 0,   # NEW: Track strategy changes
            'last_finding_iteration': 0,  # NEW: Track when we last found something
            'phase_start_time': datetime.now().isoformat(),
        }
        
        return scan_state

    def _is_scan_complete(self, scan_state: Dict) -> bool:
        """Determine if scan is complete based on coverage and phase"""
        phase = scan_state['phase']
        coverage = scan_state.get('coverage', 0.0)
        
        # Complete if we've reached covering_tracks phase with good coverage
        if phase == 'covering_tracks' and coverage >= 0.7:
            return True
            
        # Or if we've hit time limit
        time_budget = scan_state.get('config', {}).get('max_time', 3600)
        start_time = datetime.fromisoformat(scan_state['start_time'])
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if elapsed >= time_budget:
            logger.info(f"Time budget exhausted: {elapsed}s / {time_budget}s")
            return True
            
        return False

    def _analyze_situation_ml(self, scan_state: Dict) -> Dict[str, Any]:
        """Deep analysis using ML models - NOT hardcoded logic"""
        analysis = {
            'phase': scan_state['phase'],
            'coverage': self._calculate_coverage_real(scan_state),
            'attack_surface': self._map_attack_surface_real(scan_state),
            'vulnerabilities_found': len(scan_state['findings']),
            'high_value_targets': self._identify_hvt_ml(scan_state),
            'unexplored_areas': self._find_gaps_ml(scan_state),
            'risk_level': self._assess_risk_ml(scan_state),
        }
        
        return analysis

    def _calculate_coverage_real(self, scan_state: Dict) -> float:
        """Calculate REAL coverage based on findings AND tool diversity - FIXED"""
        phase = scan_state['phase']
        tools_executed = [t['tool'] if isinstance(t, dict) else t 
                          for t in scan_state.get('tools_executed', [])]
        findings = scan_state.get('findings', [])
        
        # Phase-specific tool requirements
        phase_requirements = {
            'reconnaissance': ['sublist3r', 'whatweb', 'dnsenum'],
            'scanning': ['nmap', 'nikto', 'nuclei'],
            'exploitation': ['sqlmap', 'dalfox'],
            'post_exploitation': ['linpeas'],
            'covering_tracks': ['clear_logs']
        }
        
        required_tools = phase_requirements.get(phase, [])
        if not required_tools:
            return 0.5
            
        # Calculate unique tools executed (not total count)
        unique_tools_executed = list(set([t['tool'] if isinstance(t, dict) else t for t in tools_executed]))
        executed_count = sum(1 for tool in required_tools if tool in unique_tools_executed)
        
        # Base coverage on unique tool diversity
        tool_coverage = executed_count / len(required_tools)
        
        # NEW: Penalize if tools ran multiple times without findings
        total_executions = len(tools_executed)
        unique_executions = len(unique_tools_executed)
        
        if total_executions > unique_executions * 2:
            # Too many duplicate executions
            repetition_penalty = 0.5
        else:
            repetition_penalty = 1.0
            
        # NEW: Boost based on actual findings
        findings_boost = min(len(findings) * 0.05, 0.3)  # Max 30% boost
        
        # NEW: Penalize if no findings despite many tools
        if len(findings) == 0 and unique_executions >= 3:
            no_findings_penalty = 0.3
        else:
            no_findings_penalty = 0.0
            
        total_coverage = (tool_coverage * repetition_penalty) + findings_boost - no_findings_penalty
        total_coverage = max(0.0, min(total_coverage, 1.0))
        
        print(f"[Coverage] Phase: {phase}, Unique tools: {unique_executions}, "
              f"Findings: {len(findings)}, Coverage: {total_coverage:.2f}")
        
        return total_coverage

    def _map_attack_surface_real(self, scan_state: Dict) -> List[str]:
        """Map the attack surface based on findings"""
        attack_surface = []
        findings = scan_state['findings']
        
        # Extract unique vulnerability types
        vuln_types = list(set(f.get('type') for f in findings if f.get('type')))
        attack_surface.extend(vuln_types)
        
        # Extract technologies
        technologies = scan_state.get('technologies_detected', [])
        attack_surface.extend(technologies)
        
        return list(set(attack_surface))

    def _identify_hvt_ml(self, scan_state: Dict) -> List[str]:
        """Identify high-value targets using ML classification"""
        hvt = []
        
        for finding in scan_state['findings']:
            severity = finding.get('severity', 0)
            exploitable = finding.get('exploitable', False)
            
            # High-value: high severity + exploitable
            if severity >= 8.0 and exploitable:
                location = finding.get('location', 'unknown')
                if location not in hvt:
                    hvt.append(location)
                    
        return hvt

    def _find_gaps_ml(self, scan_state: Dict) -> List[str]:
        """Find unexplored areas using intelligent analysis"""
        gaps = []
        phase = scan_state['phase']
        tools_executed = [t['tool'] if isinstance(t, dict) else t 
                          for t in scan_state.get('tools_executed', [])]
        
        # Check what's missing in current phase
        if phase == 'reconnaissance':
            if 'sublist3r' not in tools_executed:
                gaps.append('subdomain_enumeration')
            if 'whatweb' not in tools_executed:
                gaps.append('technology_detection')
                
        elif phase == 'scanning':
            if 'nmap' not in tools_executed:
                gaps.append('port_scanning')
            if 'nikto' not in tools_executed:
                gaps.append('web_vulnerability_scan')
                
        elif phase == 'exploitation':
            # Check for unaddressed vulnerability types
            vuln_types = [f.get('type') for f in scan_state['findings']]
            
            if 'sql_injection' in vuln_types and 'sqlmap' not in tools_executed:
                gaps.append('sql_injection_exploitation')
            if 'xss' in vuln_types and 'dalfox' not in tools_executed:
                gaps.append('xss_exploitation')
                
        return gaps

    def _assess_risk_ml(self, scan_state: Dict) -> float:
        """Assess overall risk level"""
        findings = scan_state['findings']
        
        if not findings:
            return 0.1
            
        # Weighted risk assessment
        total_risk = 0.0
        total_weight = 0.0
        
        for finding in findings:
            severity = finding.get('severity', 0)
            exploitable = finding.get('exploitable', False)
            
            # Higher weight for exploitable findings
            weight = 2.0 if exploitable else 1.0
            total_risk += severity * weight
            total_weight += weight
            
        if total_weight > 0:
            avg_risk = total_risk / total_weight
            normalized_risk = min(avg_risk / 10.0, 1.0)  # Normalize to 0-1
            return normalized_risk
        else:
            return 0.1

    def _execute_tool_real(self, tool_name: str, target: str, 
                          scan_state: Dict, parameters: Dict = None) -> Dict[str, Any]:
        """Execute tool with real Kali VM connection"""
        try:
            # Calculate time remaining for dynamic timeout adjustment
            time_budget = scan_state.get('config', {}).get('max_time', 3600)
            start_time = datetime.fromisoformat(scan_state['start_time'])
            elapsed = (datetime.now() - start_time).total_seconds()
            time_remaining = max(0.0, (time_budget - elapsed) / time_budget)  # Normalized 0-1
            
            # Use the existing tool manager with proper socketio
            # Merge default parameters with provided parameters
            tool_params = {
                'timeout': 600,  # Changed from 300 to 600 seconds (10 minutes)
                'aggressive': scan_state.get('aggressive', False),
                'stealth_required': scan_state.get('stealth_required', False),
                'phase': scan_state.get('phase', 'reconnaissance'),
                'findings': scan_state.get('findings', []),
                'tools_executed': scan_state.get('tools_executed', []),
                'target_type': scan_state.get('target_type', 'web'),
                'waf_detected': scan_state.get('waf_detected', False),
                'technologies_detected': scan_state.get('technologies_detected', []),
                'time_remaining': time_remaining,
                'coverage': scan_state.get('coverage', 0.0)
            }
            
            # Override with provided parameters
            if parameters:
                tool_params.update(parameters)
            
            result = self.tool_manager.execute_tool(
                tool_name=tool_name,
                target=target,
                parameters=tool_params,
                scan_id=scan_state['scan_id'],
                phase=scan_state.get('phase', 'reconnaissance')
            )
            
            # Record tool execution
            scan_state['tools_executed'].append({
                'tool': tool_name,
                'timestamp': datetime.now().isoformat(),
                'success': result.get('success', False),
                'exit_code': result.get('exit_code', -1)
            })
            
            return result
                
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'findings': []
            }

    def _update_scan_state_real(self, scan_state: Dict, result: Dict):
        """Update scan state with REAL tool results - FIXED to always process findings"""
        # NOTE: Tool is already recorded in _execute_tool_real
        
        # Always try to extract findings, even from "failed" tools
        # Many security tools return non-zero exit codes when they find vulnerabilities
        parsed_results = result.get('parsed_results', {})
        new_vulns = parsed_results.get('vulnerabilities', [])
        
        # Log the result
        exit_code = result.get('exit_code', -1)
        success = result.get('success', False)
        
        print(f"[DEBUG] Tool result - exit_code: {exit_code}, success: {success}, vulns found: {len(new_vulns)}")
        
        # Only skip if truly failed AND no findings
        if not success and not new_vulns:
            logger.warning(f"Tool failed with no findings: {result.get('error')}")
            return
        
        # Log if we're processing findings from a "failed" tool
        if not success and new_vulns:
            logger.info(f"Processing {len(new_vulns)} findings from tool with exit_code {exit_code}")
        
        print(f"[DEBUG] Tool execution found {len(new_vulns)} vulnerabilities")
        if new_vulns:
            for i, vuln in enumerate(new_vulns):
                print(f"[DEBUG] Vulnerability {i+1}: {vuln.get('type')} - {vuln.get('name', '')[:50]}")
            
            logger.info(f"✓ Found {len(new_vulns)} new vulnerabilities")
            
            # Add to scan findings
            for vuln in new_vulns:
                # Ensure each finding has an ID
                if 'id' not in vuln:
                    vuln['id'] = str(uuid.uuid4())
                
                # Add timestamp if missing
                if 'timestamp' not in vuln:
                    vuln['timestamp'] = datetime.now().isoformat()
                    
                scan_state['findings'].append(vuln)
                
                # Update knowledge base
                self.knowledge_base.add_finding(vuln)
                
                # Emit finding via WebSocket for real-time updates
                if self.socketio:
                    try:
                        self.socketio.emit('finding_discovered', {
                            'scan_id': scan_state.get('scan_id'),
                            'finding': vuln
                        })
                    except Exception as e:
                        logger.warning(f"Failed to emit finding: {e}")
                
        # Update coverage
        scan_state['coverage'] = self._calculate_coverage_real(scan_state)
        
        # Update phase data
        self._update_phase_data(scan_state, parsed_results)
        
        # Log current findings count
        total_findings = len(scan_state.get('findings', []))
        print(f"[DEBUG] Total findings in scan_state: {total_findings}")
        
    def _update_phase_data(self, scan_state: Dict, parsed_results: Dict):
        """Update phase-specific data for transition logic"""
        if 'phase_data' not in scan_state:
            scan_state['phase_data'] = {}
            
        # Provide default value for phase
        phase = scan_state.get('phase', 'reconnaissance')
        
        if phase == 'reconnaissance':
            # Count technologies and subdomains
            subdomains = parsed_results.get('subdomains', [])
            technologies = parsed_results.get('technologies', [])
            
            scan_state['phase_data']['subdomains'] = len(subdomains)
            scan_state['phase_data']['technologies'] = len(technologies)
            
        elif phase == 'scanning':
            # Count services and open ports
            services = parsed_results.get('services', [])
            hosts = parsed_results.get('hosts', [])
            
            scan_state['phase_data']['services_found'] = len(services)
            scan_state['phase_data']['hosts_found'] = len(hosts)
            
        elif phase == 'exploitation':
            # Track exploitation success
            vulns = parsed_results.get('vulnerabilities', [])
            exploitable = [v for v in vulns if v.get('exploitable', False)]
            
            if exploitable:
                scan_state['phase_data']['access_gained'] = True
                scan_state['phase_data']['shells_obtained'] = len(exploitable)

    def _get_tool_recommendation(self, scan_state: Dict) -> Dict[str, Any]:
        """
        Get unified tool recommendation using all available intelligence.
        
        Priority order:
        1. OptimusBrain (if available and confident)
        2. PhaseAwareToolSelector (main recommendation engine)
        3. Strategy-based enhancements
        
        Returns:
            Dict with 'tools', 'method', 'reasoning', 'confidence'
        """
        phase = scan_state.get('phase', 'reconnaissance')
        findings = scan_state.get('findings', [])
        tools_executed = [t['tool'] if isinstance(t, dict) else t
                          for t in scan_state.get('tools_executed', [])]
        
        # LAYER 1: Try OptimusBrain for intelligent selection
        if self.optimus_brain:
            try:
                # Prepare context for intelligence layer
                context = {
                    'target': scan_state.get('target', ''),
                    'phase': phase,
                    'findings': findings,
                    'tools_executed': tools_executed,
                    'strategy': scan_state.get('strategy', 'adaptive'),
                    'target_type': scan_state.get('target_type', 'web'),
                }
                
                # Get available tools from tool_selector first
                base_recommendation = self.tool_selector.recommend_tools(scan_state)
                available_tools = base_recommendation.get('tools', [])
                
                if available_tools:
                    # Let OptimusBrain select the best from available tools
                    brain_result = self.optimus_brain.select_tool(available_tools, context)
                    
                    if brain_result.get('confidence', 0) >= 0.6:
                        # Use brain's recommendation
                        selected = brain_result.get('selected_tool')
                        alternatives = [a['tool'] for a in brain_result.get('alternatives', [])]
                        
                        # Put selected tool first, then alternatives, then rest
                        final_tools = [selected] if selected else []
                        final_tools.extend([t for t in alternatives if t not in final_tools])
                        final_tools.extend([t for t in available_tools if t not in final_tools])
                        
                        return {
                            'tools': final_tools[:5],
                            'method': 'optimus_brain',
                            'confidence': brain_result.get('confidence', 0.6),
                            'reasoning': brain_result.get('reasoning', [])
                        }
            except Exception as e:
                logger.warning(f"OptimusBrain selection failed: {e}")
        
        # LAYER 2: Use PhaseAwareToolSelector (primary recommendation)
        recommendation = self.tool_selector.recommend_tools(scan_state)
        
        # LAYER 3: Strategy enhancements
        current_strategy = scan_state.get('strategy', 'adaptive')
        strategy_tools = self.strategy_selector.strategies.get(current_strategy, {}).get('tools', [])
        
        # Boost strategy-relevant tools to front of list
        if strategy_tools and recommendation.get('tools'):
            tools = recommendation['tools']
            strategy_boost = [t for t in tools if t in strategy_tools]
            other_tools = [t for t in tools if t not in strategy_tools]
            recommendation['tools'] = (strategy_boost + other_tools)[:5]
            recommendation['strategy_applied'] = current_strategy
        
        return recommendation

    def _learn_from_execution(self, tool_name: str, result: Dict, scan_state: Dict):
        """Learn from tool execution and update all learning systems."""
        success = result.get('success', False)
        findings = result.get('parsed_results', {}).get('vulnerabilities', [])
        execution_time = result.get('execution_time', 0)
        
        # 1. Update local learning module
        insights = self.learning_module.learn_from_execution(tool_name, result, scan_state)
        
        # 2. Update rule-based selector's effectiveness tracking
        if hasattr(self.tool_selector, 'rule_selector'):
            self.tool_selector.rule_selector.learn_from_execution(tool_name, findings, execution_time)
        
        # 3. Update strategy selector's performance tracking
        current_strategy = scan_state.get('strategy', 'adaptive')
        self.strategy_selector.update_strategy_performance(
            current_strategy, 
            len(findings) > 0, 
            len(findings)
        )
        
        # 4. Update OptimusBrain if available
        if self.optimus_brain:
            try:
                context = {
                    'target': scan_state.get('target', ''),
                    'phase': scan_state.get('phase', ''),
                    'target_type': scan_state.get('target_type', 'web'),
                }
                self.optimus_brain.process_tool_result(
                    tool_name, context, 
                    result.get('raw_output', ''), 
                    findings
                )
            except Exception as e:
                logger.warning(f"OptimusBrain learning failed: {e}")
        
        # 5. Check if tool should be blacklisted
        self._update_blacklist(scan_state, tool_name)
        
        # 6. Log learning insights
        if insights.get('recommendations'):
            logger.info(f"Learning insights: {insights['recommendations']}")

    def _should_blacklist_tool(self, tool: str, scan_state: Dict) -> bool:
        """
        Centralized blacklist decision.
        A tool should be blacklisted if:
        1. Executed 5+ times with 0 findings from it
        2. Consistently fails (3+ failures)
        3. Not appropriate for current phase
        """
        tools_executed = scan_state.get('tools_executed', [])
        
        # Count executions of this tool
        execution_count = sum(1 for t in tools_executed 
                             if (t.get('tool') if isinstance(t, dict) else t) == tool)
        
        if execution_count < 5:
            return False  # Not enough data
        
        # Count findings from this tool
        tool_findings = sum(1 for t in tools_executed 
                           if isinstance(t, dict) and t.get('tool') == tool 
                           and t.get('findings_count', 0) > 0)
        
        # Blacklist if 5+ executions with 0 findings
        if execution_count >= 5 and tool_findings == 0:
            return True
        
        # Count failures
        tool_failures = sum(1 for t in tools_executed 
                           if isinstance(t, dict) and t.get('tool') == tool 
                           and not t.get('success', False))
        
        # Blacklist if 3+ consecutive failures
        if tool_failures >= 3:
            return True
        
        return False

    def _update_blacklist(self, scan_state: Dict, tool: str):
        """Update blacklist after tool execution"""
        if self._should_blacklist_tool(tool, scan_state):
            blacklist = scan_state.get('blacklisted_tools', [])
            if tool not in blacklist:
                blacklist.append(tool)
                scan_state['blacklisted_tools'] = blacklist
                logger.info(f"Blacklisted {tool} due to ineffectiveness")

    def _generate_final_report(self, scan_state: Dict) -> Dict[str, Any]:
        """
        Generate final scan report
        """
        return {
            'scan_id': scan_state['scan_id'],
            'target': scan_state['target'],
            'target_profile': scan_state.get('target_profile', {}),
            'findings': scan_state['findings'],
            'tools_executed': scan_state['tools_executed'],
            'coverage': scan_state['coverage'],
            'duration': (datetime.now() - datetime.fromisoformat(scan_state['start_time'])).total_seconds(),
            'strategy_changes': scan_state.get('strategy_changes', 0),
        }

    def _generate_fully_autonomous_report(self, scan_state: Dict) -> Dict[str, Any]:
        """
        Generate final report for fully autonomous scan
        """
        duration = (datetime.now() - datetime.fromisoformat(scan_state['start_time'])).total_seconds()
        
        return {
            'scan_id': scan_state['scan_id'],
            'target': scan_state['target'],
            'target_profile': scan_state.get('target_profile', {}),
            'findings': scan_state['findings'],
            'tools_executed': scan_state['tools_executed'],
            'coverage': scan_state['coverage'],
            'duration': duration,
            'strategy_changes': scan_state.get('strategy_changes', 0),
            'decision_log': scan_state.get('decision_log', []),
            'adaptive_choices': scan_state.get('adaptive_choices', []),
            'mode': 'fully_autonomous'
        }

    def _get_finding_types(self, findings: List[Dict]) -> Dict[str, int]:
        """Get count of findings by type"""
        finding_types = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            finding_types[ftype] = finding_types.get(ftype, 0) + 1
        return finding_types

    def _calculate_average_severity(self, findings: List[Dict]) -> float:
        """Calculate average severity of findings"""
        if not findings:
            return 0.0
        severity_levels = [f.get('severity', 0) for f in findings]
        return sum(severity_levels) / len(severity_levels) if severity_levels else 0.0
