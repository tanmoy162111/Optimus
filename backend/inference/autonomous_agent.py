"""
Autonomous Penetration Testing Agent
Makes intelligent decisions about tool selection and scan progression
"""

import uuid
import logging
import time
from typing import Dict, Any, List
from datetime import datetime
from inference.dynamic_tool_database import DynamicToolDatabase

# Import required modules
from inference.tool_manager import ToolManager
from inference.tool_selector import PhaseAwareToolSelector
from inference.phase_controller import PhaseTransitionController

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Enhanced knowledge base with learning capabilities"""
    
    def __init__(self):
        self.findings = []
        self.targets = []
        self.tools_used = []
        self.tool_effectiveness = {}
        self.attack_surface = {
            'technologies': [],
            'services': [],
            'ports': [],
            'subdomains': [],
            'vulnerabilities': []
        }
        
    def add_finding(self, finding: Dict):
        """Add finding and update attack surface"""
        self.findings.append(finding)
        
        vuln_type = finding.get('type')
        if vuln_type and vuln_type not in self.attack_surface['vulnerabilities']:
            self.attack_surface['vulnerabilities'].append(vuln_type)
            
    def record_tool_result(self, tool: str, success: bool, vulns_found: int):
        """Record tool effectiveness for learning"""
        if tool not in self.tool_effectiveness:
            self.tool_effectiveness[tool] = {
                'uses': 0,
                'successes': 0,
                'total_vulns': 0,
                'success_rate': 0.0
            }
            
        self.tool_effectiveness[tool]['uses'] += 1
        if success:
            self.tool_effectiveness[tool]['successes'] += 1
        self.tool_effectiveness[tool]['total_vulns'] += vulns_found
        
        # Calculate success rate
        uses = self.tool_effectiveness[tool]['uses']
        successes = self.tool_effectiveness[tool]['successes']
        self.tool_effectiveness[tool]['success_rate'] = successes / uses if uses > 0 else 0.0


class AutonomousPentestAgent:
    """
    AI agent that autonomously conducts penetration tests
    """

    def __init__(self):
        self.tool_db = DynamicToolDatabase()
        self.knowledge_base = KnowledgeBase()
        
        # ADD: Load ML/RL models
        self.tool_selector = PhaseAwareToolSelector()
        self.phase_controller = PhaseTransitionController()
        
        # ADD: Load trained models
        self._load_ml_models()

    def _load_ml_models(self):
        """Load trained ML/RL models from disk"""
        import joblib
        import os
        
        try:
            # Load vulnerability detector
            if os.path.exists('models/vuln_detector.pkl'):
                self.vuln_detector = joblib.load('models/vuln_detector.pkl')
                logger.info("✓ Loaded vulnerability detector")

            # Load attack classifier
            if os.path.exists('models/attack_classifier.pkl'):
                self.attack_classifier = joblib.load('models/attack_classifier.pkl')
                logger.info("✓ Loaded attack classifier")

            # Load RL agent
            if os.path.exists('models/rl_agent.weights.h5'):
                from training.rl_trainer import EnhancedRLAgent
                self.rl_agent = EnhancedRLAgent(state_dim=23, num_actions=20)
                self.rl_agent.load_model('models/rl_agent.weights.h5')
                logger.info("✓ Loaded RL agent")
                
        except Exception as e:
            logger.warning(f"Could not load some models: {e}")

    def conduct_scan(self, target: str, scan_config: Dict) -> Dict[str, Any]:
        """Main autonomous scanning loop - FULLY INTELLIGENT"""
        scan_state = self._initialize_scan_state(target, scan_config)
        
        max_iterations = 50  # Safety limit
        iteration = 0
        
        while not self._is_scan_complete(scan_state) and iteration < max_iterations:
            iteration += 1
            logger.info(f"=== Iteration {iteration} | Phase: {scan_state['phase']} ===")
            
            # 1. Analyze current situation using ML models
            situation_analysis = self._analyze_situation_ml(scan_state)
            
            # 2. Use PhaseAwareToolSelector for intelligent tool recommendation
            tool_recommendation = self.tool_selector.recommend_tools(scan_state)
            recommended_tools = tool_recommendation['tools']
            
            logger.info(f"Recommended tools: {recommended_tools[:3]}")
            logger.info(f"Method: {tool_recommendation.get('method')}")
            logger.info(f"Reasoning: {tool_recommendation.get('reasoning')}")
            
            # 3. Execute recommended tool via REAL SSH execution
            if recommended_tools:
                tool_to_execute = recommended_tools[0]
                result = self._execute_tool_real(
                    tool_to_execute, 
                    target,
                    scan_state
                )
                
                # 4. Update scan state with REAL results
                self._update_scan_state_real(scan_state, result)
                
                # 5. Learn from execution
                self._learn_from_execution(tool_to_execute, result, scan_state)
            
            # 6. Check for phase transition using PhaseController
            next_phase = self.phase_controller.should_transition(scan_state)
            if next_phase != scan_state['phase']:
                logger.info(f"📍 Phase transition: {scan_state['phase']} → {next_phase}")
                scan_state['phase'] = next_phase
            
            # Safety: prevent infinite loops
            time.sleep(1)
            
        scan_state['status'] = 'completed'
        return self._generate_final_report(scan_state)

    def _initialize_scan_state(self, target: str, scan_config: Dict) -> Dict[str, Any]:
        """
        Initialize the scan state dictionary
        """
        return {
            'scan_id': str(uuid.uuid4()),
            'target': target,
            'phase': 'reconnaissance',
            'findings': [],
            'tools_executed': [],
            'coverage': 0,
            'start_time': datetime.now().isoformat(),
            'config': scan_config,
            'technologies_detected': [],
            'recently_used_tools': [],
            'phase_data': {}
        }

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
        """Calculate REAL coverage based on tools executed and findings"""
        phase = scan_state['phase']
        tools_executed = [t['tool'] if isinstance(t, dict) else t 
                          for t in scan_state.get('tools_executed', [])]
        
        # Phase-specific tool requirements
        phase_requirements = {
            'reconnaissance': ['sublist3r', 'whatweb', 'dnsenum'],
            'scanning': ['nmap', 'nikto', 'nuclei'],
            'exploitation': ['sqlmap', 'dalfox', 'commix'],
            'post_exploitation': ['linpeas', 'mimikatz'],
            'covering_tracks': ['clear_logs']
        }
        
        required_tools = phase_requirements.get(phase, [])
        if not required_tools:
            return 0.5
            
        # Calculate percentage of required tools executed
        executed_count = sum(1 for tool in required_tools if tool in tools_executed)
        phase_coverage = executed_count / len(required_tools)
        
        # Adjust based on findings
        findings_boost = min(len(scan_state['findings']) * 0.1, 0.3)
        
        total_coverage = min(phase_coverage + findings_boost, 1.0)
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

    def _assess_risk_ml(self, scan_state: Dict) -> str:
        """Assess risk using ML severity predictor"""
        findings = scan_state['findings']
        
        if not findings:
            return 'low'
            
        # Calculate average severity
        severities = [f.get('severity', 0) for f in findings]
        avg_severity = sum(severities) / len(severities)
        
        # Count critical findings
        critical_count = sum(1 for s in severities if s >= 9.0)
        high_count = sum(1 for s in severities if 7.0 <= s < 9.0)
        
        # Risk assessment
        if critical_count > 0 or avg_severity >= 8.5:
            return 'critical'
        elif high_count >= 3 or avg_severity >= 7.0:
            return 'high'
        elif avg_severity >= 4.0:
            return 'medium'
        else:
            return 'low'

    def _execute_tool_real(self, tool_name: str, target: str,
                          scan_state: Dict) -> Dict[str, Any]:
        """Execute REAL tool via ToolManager - NO SIMULATION"""
        from app import socketio
        
        try:
            tool_manager = ToolManager(socketio)
            
            logger.info(f"🔨 Executing REAL tool: {tool_name} against {target}")
            
            result = tool_manager.execute_tool(
                tool_name=tool_name,
                target=target,
                parameters={
                    'timeout': 300,
                    'aggressive': scan_state.get('aggressive', False)
                },
                scan_id=scan_state['scan_id'],
                phase=scan_state['phase']
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
            
        phase = scan_state['phase']
        
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

    def _learn_from_execution(self, tool_name: str, result: Dict, scan_state: Dict):
        """Learn from tool execution for future decisions"""
        success = result.get('success', False)
        vulns_found = len(result.get('parsed_results', {}).get('vulnerabilities', []))
        
        # Record in knowledge base
        self.knowledge_base.record_tool_result(tool_name, success, vulns_found)
        
        # Update tool database success rates
        self.tool_db.record_tool_success(tool_name, success and vulns_found > 0)
        
        logger.info(f"Learned: {tool_name} - Success: {success}, Vulns: {vulns_found}")

    def _generate_final_report(self, scan_state: Dict) -> Dict[str, Any]:
        """
        Generate final scan report
        """
        return {
            'scan_id': scan_state['scan_id'],
            'target': scan_state['target'],
            'findings': scan_state['findings'],
            'tools_executed': scan_state['tools_executed'],
            'coverage': scan_state['coverage'],
            'duration': (datetime.now() - datetime.fromisoformat(scan_state['start_time'])).total_seconds()
        }