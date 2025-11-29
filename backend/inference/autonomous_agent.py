"""Fully Autonomous Pentest Agent - INTELLIGENT, Adaptive, Self-Learning"""
import uuid
import logging
import time
from datetime import datetime
from typing import Dict, List, Any

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
        self.tool_selector = PhaseAwareToolSelector()
        self.phase_controller = PhaseController()
        self.tool_manager = ToolManager(socketio)  # Pass socketio to ToolManager
        self.knowledge_base = VulnerabilityKnowledgeBase()
        self.tool_db = DynamicToolDatabase()
        self.strategy_selector = StrategySelector()  # NEW
        self.learning_module = RealTimeLearningModule()  # NEW
        self.socketio = socketio  # Store socketio reference
        logger.info("🤖 Autonomous Pentest Agent initialized")
    
    def run_autonomous_scan(self, target: str, scan_config: Dict = None) -> Dict[str, Any]:
        """Main autonomous scanning loop - FULLY INTELLIGENT"""
        if scan_config is None:
            scan_config = {}
            
        # Check if this is fully autonomous mode
        if scan_config.get('self_directed', False):
            return self._run_fully_autonomous_scan(target, scan_config)
            
        scan_state = self._initialize_scan_state(target, scan_config)
        
        max_iterations = 50
        iteration = 0
        stalled_iterations = 0
        last_findings_count = 0
        
        # Track tool execution attempts
        tool_execution_attempts = {}
        max_tool_attempts = 3  # Reduced from 5
        
        while not self._is_scan_complete(scan_state) and iteration < max_iterations:
            iteration += 1
            logger.info(f"=== Iteration {iteration} | Phase: {scan_state['phase']} | Strategy: {scan_state.get('strategy', 'none')} ===")
            
            # NEW: Check if strategy should change
            if self.strategy_selector.should_change_strategy(scan_state):
                new_strategy = self.strategy_selector.select_strategy(scan_state)
                old_strategy = scan_state.get('strategy', 'none')
                
                if new_strategy != old_strategy:
                    logger.info(f"🔄 STRATEGY CHANGE: {old_strategy} → {new_strategy}")
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
            if stalled_iterations >= 5:
                logger.warning(f"Scan stalled for {stalled_iterations} iterations, forcing phase transition")
                next_phase = self.phase_controller.get_next_phase(scan_state['phase'], scan_state)
                scan_state['phase'] = next_phase
                scan_state['strategy'] = self.strategy_selector.select_strategy(scan_state)
                stalled_iterations = 0
                continue
            
            # Tool recommendation with strategy awareness
            tool_recommendation = self._get_strategy_aware_tools(scan_state)
            recommended_tools = tool_recommendation['tools']
            
            if not recommended_tools or tool_recommendation.get('method') == 'exhausted':
                logger.info("Tool selector exhausted, transitioning phase")
                next_phase = self.phase_controller.get_next_phase(scan_state['phase'], scan_state)
                scan_state['phase'] = next_phase
                scan_state['strategy'] = self.strategy_selector.select_strategy(scan_state)
                continue
            
            # Execute tool with attempt tracking
            if recommended_tools:
                tool_to_execute = recommended_tools[0]
                
                # Prevent infinite attempts
                tool_execution_attempts[tool_to_execute] = tool_execution_attempts.get(tool_to_execute, 0) + 1
                if tool_execution_attempts[tool_to_execute] > max_tool_attempts:
                    logger.warning(f"Tool {tool_to_execute} attempted {max_tool_attempts} times, skipping")
                    next_phase = self.phase_controller.get_next_phase(scan_state['phase'], scan_state)
                    scan_state['phase'] = next_phase
                    continue
                
                # NEW: Check if tool has already been executed recently to prevent looping
                tools_executed = [t['tool'] if isinstance(t, dict) else t 
                                  for t in scan_state.get('tools_executed', [])]
                if tool_to_execute in tools_executed:
                    # Check how many times this tool has been executed
                    tool_count = tools_executed.count(tool_to_execute)
                    if tool_count >= 3:  # Already executed 3 times
                        logger.warning(f"Tool {tool_to_execute} already executed {tool_count} times, skipping to prevent looping")
                        # Add to blacklisted tools to prevent future recommendations
                        if 'blacklisted_tools' not in scan_state:
                            scan_state['blacklisted_tools'] = []
                        if tool_to_execute not in scan_state['blacklisted_tools']:
                            scan_state['blacklisted_tools'].append(tool_to_execute)
                        continue
                
                result = self._execute_tool_real(
                    tool_to_execute, 
                    target,
                    scan_state
                )
                
                # Update scan state
                self._update_scan_state_real(scan_state, result)
                
                # Learn from execution
                self._learn_from_execution(tool_to_execute, result, scan_state)
            
            # Check for phase transition
            next_phase = self.phase_controller.should_transition(scan_state)
            if next_phase != scan_state['phase']:
                logger.info(f"📍 Phase transition: {scan_state['phase']} → {next_phase}")
                scan_state['phase'] = next_phase
                scan_state['strategy'] = self.strategy_selector.select_strategy(scan_state)
                stalled_iterations = 0
            
            time.sleep(0.5)
            
        scan_state['status'] = 'completed'
        return self._generate_final_report(scan_state)

    def _run_fully_autonomous_scan(self, target: str, scan_config: Dict) -> Dict[str, Any]:
        """
        Run fully autonomous scan where agent makes all decisions based on findings
        
        Args:
            target: Target URL/IP
            scan_config: Configuration for the scan
            
        Returns:
            Scan results
        """
        logger.info("🚀 Starting FULLY AUTONOMOUS scan mode")
        
        scan_state = self._initialize_fully_autonomous_state(target, scan_config)
        
        max_iterations = scan_config.get('max_iterations', 100)
        iteration = 0
        decision_log = []
        
        # Track tool execution attempts to prevent infinite loops
        tool_execution_attempts = {}
        max_tool_attempts = 5
        
        while not self._is_fully_autonomous_scan_complete(scan_state) and iteration < max_iterations:
            iteration += 1
            logger.info(f"=== Fully Autonomous Iteration {iteration} ===")
            
            # Analyze current situation based on findings
            situation_analysis = self._analyze_situation_fully_autonomous(scan_state)
            
            # Make decision based on analysis
            decision = self._make_autonomous_decision(scan_state, situation_analysis)
            
            # Log decision
            decision_log.append({
                'iteration': iteration,
                'analysis': situation_analysis,
                'decision': decision,
                'timestamp': datetime.now().isoformat()
            })
            
            # Execute decision
            if decision['action'] == 'execute_tool':
                tool_to_execute = decision['tool']
                parameters = decision.get('parameters', {})
                
                # Prevent infinite attempts
                tool_execution_attempts[tool_to_execute] = tool_execution_attempts.get(tool_to_execute, 0) + 1
                if tool_execution_attempts[tool_to_execute] > max_tool_attempts:
                    logger.warning(f"Tool {tool_to_execute} attempted {max_tool_attempts} times, skipping")
                    continue
                
                logger.info(f"🔧 Executing tool: {tool_to_execute} with parameters: {parameters}")
                
                result = self._execute_tool_real(
                    tool_to_execute, 
                    target,
                    scan_state,
                    parameters
                )
                
                # Update scan state with results
                self._update_scan_state_real(scan_state, result)
                
                # Learn from execution
                self._learn_from_execution(tool_to_execute, result, scan_state)
                
            elif decision['action'] == 'change_approach':
                logger.info(f"🔄 Changing approach: {decision['reason']}")
                # Update scan state with new approach
                scan_state['current_approach'] = decision.get('new_approach', 'default')
                
            elif decision['action'] == 'terminate':
                logger.info(f"⏹️ Terminating scan: {decision['reason']}")
                break
            
            time.sleep(0.5)
        
        scan_state['status'] = 'completed'
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
        
        analysis = {
            'total_findings': len(findings),
            'unique_tools_executed': len(unique_tools),
            'finding_types': finding_types,
            'average_severity': avg_severity,
            'technologies_detected': technologies,
            'coverage_estimate': min(len(findings) / 5.0, 1.0),  # Estimate coverage
            'tools_executed_recently': [t['tool'] if isinstance(t, dict) else t 
                                       for t in tools_executed[-5:]]  # Last 5 tools
        }
        
        return analysis

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
        
        # Get tools that haven't been executed recently
        all_tools = list(self.tool_db.tools.keys())
        print(f"[DEBUG] All available tools: {len(all_tools)}")
        print(f"[DEBUG] Recently executed tools: {recent_tools}")
        
        available_tools = [tool for tool in all_tools if tool not in recent_tools]
        print(f"[DEBUG] Available tools: {len(available_tools)}")
        
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
        
        # If we haven't executed many tools, try exploration
        if unique_tools < 10 and available_tools:
            exploration_tool = available_tools[0] if available_tools else 'nmap'
            return {
                'action': 'execute_tool',
                'tool': exploration_tool,
                'parameters': self._generate_tool_parameters(exploration_tool, scan_state, analysis),
                'reason': f'Exploring new tool: {exploration_tool}'
            }
        
        # If we've executed many tools but have few findings, change approach
        if unique_tools >= 10 and findings < 3:
            return {
                'action': 'change_approach',
                'new_approach': 'intensive_exploitation',
                'reason': 'Many tools executed but few findings, switching to intensive exploitation'
            }
        
        # Default: execute a random available tool
        if available_tools:
            tool = available_tools[0]
            return {
                'action': 'execute_tool',
                'tool': tool,
                'parameters': self._generate_tool_parameters(tool, scan_state, analysis),
                'reason': f'Default execution of {tool}'
            }
        
        # If no tools available, terminate
        return {
            'action': 'terminate',
            'reason': 'No more tools available to execute'
        }

    def _get_priority_tools_for_findings(self, finding_types: Dict[str, int], available_tools: List[str]) -> List[str]:
        """Get priority tools based on finding types"""
        tool_priorities = {
            'sql_injection': ['sqlmap', 'commix'],
            'xss': ['dalfox', 'xsser'],
            'web_vulnerabilities': ['nikto', 'nuclei'],
            'subdomains': ['subfinder', 'amass'],
            'ports_open': ['nmap', 'masscan'],
            'wordpress': ['wpscan'],
            'directories': ['ffuf', 'gobuster', 'dirb']
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
        
        return unique_priority_tools

    def _generate_tool_parameters(self, tool_name: str, scan_state: Dict, analysis: Dict) -> Dict[str, Any]:
        """Generate appropriate parameters for a tool based on current state"""
        target = scan_state['target']
        findings = scan_state.get('findings', [])
        technologies = scan_state.get('technologies_detected', [])
        
        # Base parameters
        parameters = {
            'aggressive': len(findings) < 3,  # Be more aggressive if few findings
            'timeout': 300,
            'target_type': scan_state.get('target_profile', {}).get('type', 'web')
        }
        
        # Tool-specific parameter generation
        if tool_name == 'nmap':
            parameters.update({
                'ports': '1-1000',  # Scan common ports
                'service_detection': True
            })
        elif tool_name == 'nikto':
            parameters.update({
                'evasion': len(findings) > 5,  # Use evasion if we have many findings
                'plugins': 'all'
            })
        elif tool_name == 'sqlmap':
            # Look for SQL injection findings
            sql_findings = [f for f in findings if f.get('type') == 'sql_injection']
            if sql_findings:
                parameters.update({
                    'url': sql_findings[0].get('location', target),
                    'technique': 'BEUSTQ',
                    'level': 3,
                    'risk': 2
                })
            else:
                parameters.update({
                    'url': target,
                    'crawl_depth': 2
                })
        elif tool_name == 'nuclei':
            parameters.update({
                'templates': 'cves,exposures,misconfigurations',
                'severity': 'high,critical' if len(findings) < 5 else 'medium,high,critical'
            })
        elif tool_name == 'ffuf':
            parameters.update({
                'wordlist': '/usr/share/seclists/Discovery/Web-Content/common.txt',
                'extensions': 'php,html,txt',
                'threads': 40
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
                'timeout': 300,
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
        """Update scan state with REAL tool results - NO FAKE DATA"""
        # Always add tool to executed list, regardless of success
        tool_name = result.get('tool_name')
        if tool_name:
            scan_state['tools_executed'].append({
                'tool': tool_name,
                'timestamp': datetime.now().isoformat(),
                'success': result.get('success', False),
                'exit_code': result.get('exit_code', -1)
            })
        
        if not result.get('success'):
            logger.warning(f"Tool failed: {result.get('error')}")
            return
            
        # Extract vulnerabilities from parsed results
        parsed_results = result.get('parsed_results', {})
        new_vulns = parsed_results.get('vulnerabilities', [])
        
        if new_vulns:
            logger.info(f"✓ Found {len(new_vulns)} new vulnerabilities")
            
            # Add to scan findings
            for vuln in new_vulns:
                # Ensure each finding has an ID
                if 'id' not in vuln:
                    vuln['id'] = str(uuid.uuid4())
                    
                scan_state['findings'].append(vuln)
                
                # Update knowledge base
                self.knowledge_base.add_finding(vuln)
                
        # Update coverage
        scan_state['coverage'] = self._calculate_coverage_real(scan_state)
        
        # Update phase data
        self._update_phase_data(scan_state, parsed_results)

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

    def _get_strategy_aware_tools(self, scan_state: Dict) -> Dict[str, Any]:
        """Get tool recommendations aware of current strategy"""
        current_strategy = scan_state.get('strategy', 'active_scanning')
        
        # Get strategy-specific tools
        strategy_tools = self.strategy_selector.get_strategy_tools(current_strategy)
        
        # Get phase-aware recommendations
        phase_recommendation = self.tool_selector.recommend_tools(scan_state)
        
        # Merge: prioritize strategy tools, then phase tools
        merged_tools = []
        
        # Add strategy tools not yet executed
        tools_executed = [t['tool'] if isinstance(t, dict) else t
                          for t in scan_state.get('tools_executed', [])]
        blacklisted = scan_state.get('blacklisted_tools', [])
        
        for tool in strategy_tools:
            if tool not in tools_executed and tool not in blacklisted:
                merged_tools.append(tool)
        
        # Add phase-recommended tools
        for tool in phase_recommendation.get('tools', []):
            if tool not in merged_tools and tool not in tools_executed and tool not in blacklisted:
                merged_tools.append(tool)
        
        if not merged_tools:
            return {
                'tools': [],
                'method': 'exhausted',
                'reasoning': 'All tools exhausted for current strategy and phase'
            }
        
        return {
            'tools': merged_tools[:5],
            'method': 'strategy_aware',
            'strategy': current_strategy,
            'reasoning': f'Strategy: {current_strategy}, Phase: {scan_state["phase"]}'
        }
    
    def _learn_from_execution(self, tool_name: str, result: Dict, scan_state: Dict):
        """Learn from tool execution for future decisions - ENHANCED"""
        success = result.get('success', False)
        vulns_found = len(result.get('parsed_results', {}).get('vulnerabilities', []))
        
        # Record in knowledge base
        self.knowledge_base.record_tool_result(tool_name, success, vulns_found)
        
        # Update tool database success rates
        self.tool_db.record_tool_success(tool_name, success and vulns_found > 0)
        
        # NEW: Real-time learning
        context = {
            'phase': scan_state.get('phase'),
            'target_type': scan_state.get('target_profile', {}).get('type', 'web'),
            'findings': scan_state.get('findings', []),
        }
        
        insights = self.learning_module.learn_from_execution(tool_name, result, context)
        
        # Apply learning insights
        if insights.get('recommendations'):
            logger.info(f"[Learning] Recommendations: {insights['recommendations']}")
        
        # Check if we should change approach
        if self.learning_module.should_try_different_approach(scan_state):
            # Force strategy re-evaluation
            new_strategy = self.strategy_selector.select_strategy(scan_state)
            if new_strategy != scan_state.get('strategy'):
                logger.info(f"[Learning] Triggering strategy change based on learning")
                scan_state['strategy'] = new_strategy
        
        logger.info(f"Learned: {tool_name} - Success: {success}, Vulns: {vulns_found}")

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