import uuid
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import asdict
import logging

# Import the autonomous agent
from inference.autonomous_agent import AutonomousPentestAgent

logger = logging.getLogger(__name__)

class WorkflowEngine:
    def __init__(self, socketio, active_scans_ref=None):
        self.socketio = socketio
        self.active_scans = active_scans_ref if active_scans_ref is not None else {}
        self.scan_threads: Dict[str, threading.Thread] = {}
        
    def start_scan_async(self, scan_id: str, target: str, config: Dict[str, Any] = None):
        """
        Start scan in background thread
        
        Args:
            scan_id: Unique scan identifier
            target: Target URL/IP
            config: Optional scan configuration
        """
        # Get existing scan state (created by scan_routes)
        if scan_id not in self.active_scans:
            logger.error(f"Scan {scan_id} not found in active_scans")
            return
        
        scan_state = self.active_scans[scan_id]
        scan_state['status'] = 'running'
        
        # Start scan in thread
        thread = threading.Thread(
            target=self.orchestrate_scan,
            args=(scan_state,),
            daemon=True
        )
        thread.start()
        
        self.scan_threads[scan_id] = thread
        
        logger.info(f"Started workflow for scan {scan_id}")
        
    def orchestrate_scan(self, scan_state: Dict):
        """Main scan orchestration - DELEGATE TO AUTONOMOUS AGENT"""
        try:
            scan_id = scan_state['scan_id']
            target = scan_state['target']
            
            # Emit scan started
            self.socketio.emit('scan_started', {
                'scan_id': scan_id,
                'target': target,
                'timestamp': scan_state['start_time']
            })
            
            logger.info(f"🚀 Starting autonomous scan for {target}")
            
            # IMPORTANT: Let the AutonomousPentestAgent drive everything
            agent = AutonomousPentestAgent()
            
            # Configure the agent properly
            scan_config = {
                'max_time': scan_state.get('time_budget', 3600),
                'depth': scan_state.get('depth', 'normal'),
                'stealth': scan_state.get('stealth', False),
                'aggressive': scan_state.get('aggressive', True),
                'target_type': self._detect_target_type(target)
            }
            
            # Run autonomous scan - agent handles EVERYTHING
            agent_result = agent.conduct_scan(target, scan_config)
            
            # Update scan_state with agent's REAL results
            scan_state['findings'] = agent_result['findings']
            scan_state['tools_executed'] = agent_result['tools_executed']
            scan_state['coverage'] = agent_result['coverage']
            scan_state['status'] = 'completed'
            scan_state['end_time'] = datetime.now().isoformat()
            
            logger.info(f"✅ Scan complete: {len(scan_state['findings'])} findings, "
                       f"{len(scan_state['tools_executed'])} tools used")
            
            # Generate report
            report = self._generate_report(scan_state)
            
            # Emit completion
            self.socketio.emit('scan_complete', {
                'scan_id': scan_id,
                'findings_count': len(scan_state['findings']),
                'time_elapsed': self._calculate_elapsed_time(scan_state),
                'report': report
            })
            
        except Exception as e:
            logger.error(f"Scan orchestration error: {e}")
            scan_state['status'] = 'error'
            self.socketio.emit('scan_error', {
                'scan_id': scan_state['scan_id'],
                'error': str(e)
            })
    
    def _detect_target_type(self, target: str) -> str:
        """
        Detect target type based on target string
        """
        if target.startswith('http://') or target.startswith('https://'):
            return 'http_service'
        elif ':' in target and target.replace(':', '').replace('.', '').isdigit():
            # IP:port format
            return 'network_service'
        elif target.replace('.', '').isdigit():
            # IP address
            return 'ip_address'
        else:
            # Assume domain name
            return 'domain_target'
    
    def cleanup_tool_manager(self):
        """Cleanup ToolManager at end of scan"""
        # Not needed anymore since agent manages its own tool manager
        pass
    
    def _handle_phase_transition(self, scan_state: Dict, new_phase: str):
        """Handle phase transition"""
        scan_id = scan_state['scan_id']
        old_phase = scan_state.get('previous_phase', 'none')
        scan_state['previous_phase'] = new_phase
        
        self.socketio.emit('phase_transition', {
            'scan_id': scan_id,
            'from': old_phase,
            'to': new_phase,
            'timestamp': datetime.now().isoformat()
        })
        
        logger.info(f"📍 Phase transition: {old_phase} → {new_phase}")
    
    def _get_phase_tools(self, phase: str) -> List[str]:
        """Get recommended tools for phase"""
        phase_tools = {
            'reconnaissance': ['sublist3r', 'whatweb', 'dnsenum'],
            'scanning': ['nmap', 'nikto', 'nuclei'],
            'exploitation': ['sqlmap', 'dalfox', 'commix'],
            'post_exploitation': ['linpeas'],
            'covering_tracks': ['clear_logs']
        }
        return phase_tools.get(phase, [])
    
    def _calculate_coverage(self, scan_state: Dict, phase: str) -> float:
        """Calculate scan coverage"""
        phase_weights = {
            'reconnaissance': 0.15,
            'scanning': 0.30,
            'exploitation': 0.30,
            'post_exploitation': 0.20,
            'covering_tracks': 0.05
        }
        
        # Simple coverage based on tools executed
        tools_in_phase = len(self._get_phase_tools(phase))
        tools_executed = len([t for t in scan_state['tools_executed'] if t in self._get_phase_tools(phase)])
        
        if tools_in_phase == 0:
            phase_coverage = 1.0
        else:
            phase_coverage = min(tools_executed / tools_in_phase, 1.0)
        
        return phase_coverage * phase_weights.get(phase, 0.1)
    
    def _calculate_elapsed_time(self, scan_state: Dict) -> int:
        """Calculate elapsed time in seconds"""
        start = datetime.fromisoformat(scan_state['start_time'])
        end = datetime.fromisoformat(scan_state.get('end_time', datetime.now().isoformat()))
        return int((end - start).total_seconds())
    
    def _generate_report(self, scan_state: Dict) -> Dict:
        """Generate simple scan report"""
        findings = scan_state.get('findings', [])
        
        return {
            'summary': {
                'total_findings': len(findings),
                'critical': len([f for f in findings if f.get('severity', 0) >= 9.0]),
                'high': len([f for f in findings if 7.0 <= f.get('severity', 0) < 9.0]),
                'medium': len([f for f in findings if 4.0 <= f.get('severity', 0) < 7.0]),
                'low': len([f for f in findings if f.get('severity', 0) < 4.0])
            },
            'tools_used': scan_state['tools_executed'],
            'coverage': scan_state['coverage'],
            'elapsed_time': self._calculate_elapsed_time(scan_state)
        }
    
    def stop_scan(self, scan_id: str):
        """Stop active scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['status'] = 'stopped'
            logger.info(f"🛑 Scan {scan_id} stopped")
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get current scan status"""
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            return {
                'scan_id': scan_id,
                'target': scan['target'],
                'phase': scan['phase'],
                'status': scan['status'],
                'findings_count': len(scan['findings']),
                'coverage': scan['coverage'],
                'time_elapsed': self._calculate_elapsed_time(scan) if 'start_time' in scan else 0
            }
        return {'error': 'Scan not found'}
    
    def get_scan_results(self, scan_id: str) -> Dict:
        """Get complete scan results"""
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            return {
                'scan_id': scan_id,
                'target': scan['target'],
                'phase': scan['phase'],
                'status': scan['status'],
                'findings': scan['findings'],
                'tools_executed': scan['tools_executed'],
                'time_elapsed': self._calculate_elapsed_time(scan) if 'start_time' in scan else 0,
                'coverage': scan['coverage']
            }
        return {'error': 'Scan not found'}