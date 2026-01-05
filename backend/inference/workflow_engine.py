"""
Fixed Workflow Engine - Properly calls autonomous agent
"""
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
        """Start scan in background thread"""
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
        """Main scan orchestration - FIXED to call correct method"""
        try:
            scan_id = scan_state['scan_id']
            target = scan_state['target']
            
            # Emit scan started
            self.socketio.emit('scan_started', {
                'scan_id': scan_id,
                'target': target,
                'timestamp': scan_state['start_time']
            }, room=f'scan_{scan_id}')
            
            logger.info(f"🚀 Starting autonomous scan for {target}")
            
            # CRITICAL FIX: Create agent and call correct method
            agent = AutonomousPentestAgent()
            
            # Configure the agent properly
            scan_config = {
                'max_time': scan_state.get('time_budget', 3600),
                'depth': scan_state.get('depth', 'normal'),
                'stealth': scan_state.get('stealth', False),
                'aggressive': scan_state.get('aggressive', True),
                'target_type': self._detect_target_type(target)
            }
            
            # FIXED: Call the actual method that exists
            agent_result = agent.run_autonomous_scan(target, scan_config)
            
            # Update scan_state with agent's REAL results
            scan_state['findings'] = agent_result.get('findings', [])
            scan_state['tools_executed'] = agent_result.get('tools_executed', [])
            scan_state['coverage'] = agent_result.get('coverage', 0.0)
            scan_state['status'] = 'completed'
            scan_state['end_time'] = datetime.now().isoformat()
            
            logger.info(f"Scan complete: {len(scan_state['findings'])} findings, "
                       f"{len(scan_state['tools_executed'])} tools used")
            
            # Generate report
            report = self._generate_report(scan_state)
            
            # Emit completion
            self.socketio.emit('scan_complete', {
                'scan_id': scan_id,
                'findings_count': len(scan_state['findings']),
                'time_elapsed': self._calculate_elapsed_time(scan_state),
                'report': report
            }, room=f'scan_{scan_id}')
            
        except Exception as e:
            logger.error(f"Scan orchestration error: {e}")
            import traceback
            traceback.print_exc()
            scan_state['status'] = 'error'
            scan_state['error'] = str(e)
            self.socketio.emit('scan_error', {
                'scan_id': scan_state['scan_id'],
                'error': str(e)
            }, room=f'scan_{scan_id}')
    
    def _detect_target_type(self, target: str) -> str:
        """Detect target type based on target string"""
        if target.startswith('http://') or target.startswith('https://'):
            return 'http_service'
        elif ':' in target and target.replace(':', '').replace('.', '').isdigit():
            return 'network_service'
        elif target.replace('.', '').isdigit():
            return 'ip_address'
        else:
            return 'domain_target'
    
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
            'tools_used': scan_state.get('tools_executed', []),
            'coverage': scan_state.get('coverage', 0.0),
            'elapsed_time': self._calculate_elapsed_time(scan_state)
        }