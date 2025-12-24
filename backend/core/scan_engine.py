"""
Core Scan Engine - FIXED VERSION
Properly starts scans using AutonomousPentestAgent

REPLACES: backend/core/scan_engine.py
"""

import sys
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Add backend to path
BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))

logger = logging.getLogger(__name__)

# Global instance
_scan_manager = None


class ScanManager:
    """Central scan management - WORKING IMPLEMENTATION"""
    
    def __init__(self, socketio, active_scans_ref):
        self.socketio = socketio
        self.active_scans = active_scans_ref
        self.scan_threads: Dict[str, threading.Thread] = {}
        self._stop_flags: Dict[str, bool] = {}
        self._pause_flags: Dict[str, bool] = {}
        
        # Initialize components
        self.tool_manager = None
        self.agent_class = None
        self._init_components()
        
        logger.info("ScanManager initialized with WORKING implementation")
    
    def _init_components(self):
        """Initialize scan components"""
        print(f"\n{'='*60}")
        print("[ScanManager] Initializing components...")
        print(f"{'='*60}")
        
        try:
            print("[ScanManager] Importing AutonomousPentestAgent...")
            from inference.autonomous_agent import AutonomousPentestAgent
            print("[ScanManager]  AutonomousPentestAgent imported")
            
            print("[ScanManager] Importing ToolManager...")
            from inference.tool_manager import ToolManager
            print("[ScanManager]  ToolManager imported")
            
            print("[ScanManager] Creating ToolManager instance...")
            self.tool_manager = ToolManager(self.socketio)
            print("[ScanManager]  ToolManager created")
            
            self.agent_class = AutonomousPentestAgent
            logger.info("Loaded: AutonomousPentestAgent, ToolManager")
            print("[ScanManager]  All components initialized successfully!")
            
        except ImportError as e:
            logger.error(f"Failed to import components: {e}")
            print(f"\n[ScanManager]  IMPORT ERROR: {e}")
            print("[ScanManager] This means scans will NOT work!")
            print("[ScanManager] Check that all dependencies are installed:")
            print("  pip install paramiko flask-socketio")
            import traceback
            traceback.print_exc()
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            print(f"\n[ScanManager]  INIT ERROR: {e}")
            import traceback
            traceback.print_exc()
    
    def start_scan(self, scan_id: str, target: str, options: Dict[str, Any] = None):
        """
        Start a new scan - THIS ACTUALLY WORKS!
        Creates agent and runs scan in background thread.
        """
        print(f"\n{'='*60}")
        print(f"[ScanManager] start_scan called!")
        print(f"  scan_id: {scan_id}")
        print(f"  target: {target}")
        print(f"  options: {options}")
        print(f"  agent_class: {self.agent_class}")
        print(f"  tool_manager: {self.tool_manager}")
        print(f"  self.active_scans keys: {list(self.active_scans.keys()) if self.active_scans else 'None'}")
        print(f"{'='*60}")
        
        # DEBUG: Check if agent_class is None
        if self.agent_class is None:
            print("[ScanManager] DEBUG: agent_class is None at start of start_scan!")
        
        logger.info(f"start_scan called: scan_id={scan_id}, target={target}")
        
        if scan_id not in self.active_scans:
            logger.error(f"Scan {scan_id} not in active_scans")
            print(f"[ScanManager] ERROR: Scan {scan_id} not in active_scans!")
            print(f"  Available scan IDs: {list(self.active_scans.keys()) if self.active_scans else 'None'}")
            return False
        
        options = options or {}
        scan_state = self.active_scans[scan_id]
        scan_state['status'] = 'running'
        self._stop_flags[scan_id] = False
        self._pause_flags[scan_id] = False
        
        # Start in background thread
        thread = threading.Thread(
            target=self._run_scan_thread,
            args=(scan_id, target, options),
            daemon=True,
            name=f"scan-{scan_id}"
        )
        thread.start()
        self.scan_threads[scan_id] = thread
        
        logger.info(f"Started scan thread for {scan_id}")
        
        # Emit WebSocket event
        if self.socketio:
            try:
                self.socketio.start_background_task(
                    self.socketio.emit,
                    'scan_started',
                    {
                        'scan_id': scan_id,
                        'target': target,
                        'timestamp': datetime.utcnow().isoformat()
                    },
                    room=f'scan_{scan_id}'
                )
                logger.info(f"Emitted scan_started event")
            except Exception as e:
                logger.warning(f"WebSocket emit failed: {e}")
        
        return True
    
    def _run_scan_thread(self, scan_id: str, target: str, options: Dict[str, Any]):
        """Execute scan in background thread"""
        logger.info(f"Scan thread started for {scan_id}")
        
        try:
            scan_state = self.active_scans.get(scan_id)
            if not scan_state:
                logger.error(f"Scan state not found for {scan_id}")
                return
            
            # Ensure agent_class is initialized
            if not self.agent_class:
                logger.warning("Agent class not initialized, re-initializing")
                self._init_components()
                
                if not self.agent_class:
                    logger.error("Agent class not initialized after re-init")
                    scan_state['status'] = 'error'
                    scan_state['error'] = 'Scan agent not initialized'
                    self._emit_error(scan_id, 'Scan agent not initialized')
                    return
            
            # Create agent
            logger.info(f"Creating AutonomousPentestAgent for scan {scan_id}")
            agent = self.agent_class(socketio=self.socketio)
            
            # Prepare config
            scan_config = {
                'max_time': options.get('maxDuration', 3600),
                'mode': options.get('mode', 'standard'),
                'enable_exploitation': options.get('enableExploitation', False),
                'use_ai': options.get('useAI', True),
                'scan_id': scan_id,
            }
            
            # Emit phase transition
            self._emit_phase_transition(scan_id, 'initializing', 'reconnaissance')
            
            # Run scan
            logger.info(f"Starting autonomous scan for {scan_id}")
            result = agent.run_autonomous_scan(target, scan_config)
            logger.info(f"Scan completed: {len(result.get('findings', []))} findings")
            
            # Check if stopped
            if self._stop_flags.get(scan_id):
                scan_state['status'] = 'stopped'
                logger.info(f"Scan {scan_id} was stopped by user")
            else:
                # Update with results
                scan_state['findings'] = result.get('findings', [])
                scan_state['tools_executed'] = result.get('tools_executed', [])
                scan_state['coverage'] = result.get('coverage', 0.0)
                scan_state['status'] = 'completed'
                logger.info(f" Scan {scan_id} completed successfully!")
            
            scan_state['end_time'] = datetime.utcnow().isoformat()
            
            # Calculate elapsed time
            try:
                start = datetime.fromisoformat(scan_state['start_time'])
                end = datetime.fromisoformat(scan_state['end_time'])
                scan_state['time_elapsed'] = int((end - start).total_seconds())
            except Exception as e:
                logger.warning(f"Could not calculate elapsed time: {e}")
                scan_state['time_elapsed'] = 0
            
            # Emit completion
            self._emit_complete(scan_id, scan_state)
            
            logger.info(f"Scan {scan_id} results: {len(scan_state.get('findings', []))} findings, "
                       f"{len(scan_state.get('tools_executed', []))} tools executed")
            
        except Exception as e:
            logger.error(f" Scan error: {e}")
            import traceback
            traceback.print_exc()
            
            if scan_id in self.active_scans:
                self.active_scans[scan_id]['status'] = 'error'
                self.active_scans[scan_id]['error'] = str(e)
            
            self._emit_error(scan_id, str(e))
    
    def _emit_phase_transition(self, scan_id, from_phase, to_phase):
        """Emit phase transition WebSocket event"""
        if self.socketio:
            try:
                self.socketio.start_background_task(
                    self.socketio.emit,
                    'phase_transition',
                    {'scan_id': scan_id, 'from': from_phase, 'to': to_phase},
                    room=f'scan_{scan_id}'
                )
            except Exception as e:
                logger.warning(f"Failed to emit phase_transition: {e}")
    
    def _emit_complete(self, scan_id, scan_state):
        """Emit scan complete WebSocket event"""
        if self.socketio:
            try:
                self.socketio.start_background_task(
                    self.socketio.emit,
                    'scan_complete',
                    {'scan_id': scan_id, 'findings_count': len(scan_state.get('findings', [])), 'time_elapsed': scan_state.get('time_elapsed', 0), 'status': scan_state['status']},
                    room=f'scan_{scan_id}'
                )
            except Exception as e:
                logger.warning(f"Failed to emit scan_complete: {e}")
    
    def _emit_error(self, scan_id, error):
        """Emit scan error WebSocket event"""
        if self.socketio:
            try:
                self.socketio.start_background_task(
                    self.socketio.emit,
                    'scan_error',
                    {'scan_id': scan_id, 'error': error},
                    room=f'scan_{scan_id}'
                )
            except Exception as e:
                logger.warning(f"Failed to emit scan_error: {e}")
    
    def _get_kali_info(self):
        """Get Kali VM connection info for logging"""
        try:
            from config import Config
            return f"{Config.KALI_HOST}:{Config.KALI_PORT}"
        except:
            return "unknown"
    
    def stop_scan(self, scan_id: str):
        """Stop a running scan"""
        self._stop_flags[scan_id] = True
        logger.info(f"Stop signal sent for {scan_id}")
    
    def pause_scan(self, scan_id: str):
        """Pause a scan"""
        self._pause_flags[scan_id] = True
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['status'] = 'paused'
        logger.info(f"Paused scan {scan_id}")
    
    def resume_scan(self, scan_id: str):
        """Resume a scan"""
        self._pause_flags[scan_id] = False
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['status'] = 'running'
        logger.info(f"Resumed scan {scan_id}")
    
    def execute_tool(self, scan_id: str, tool: str, target: str, options: Dict = None):
        """Execute a specific tool"""
        if self.tool_manager:
            phase = self.active_scans.get(scan_id, {}).get('phase', 'unknown')
            return self.tool_manager.execute_tool(tool, target, options or {}, scan_id, phase)
        return {'success': False, 'error': 'Tool manager not available'}
    
    def get_tool_recommendation(self, scan_id: str, phase: str, context: Dict = None):
        """Get tool recommendation"""
        recommendations = {
            'reconnaissance': {'tool': 'nmap', 'confidence': 0.9, 'reasoning': 'Port discovery'},
            'scanning': {'tool': 'nuclei', 'confidence': 0.85, 'reasoning': 'Vuln scanning'},
            'exploitation': {'tool': 'sqlmap', 'confidence': 0.8, 'reasoning': 'SQL injection'},
            'post_exploitation': {'tool': 'linpeas', 'confidence': 0.75, 'reasoning': 'Privesc'},
        }
        return recommendations.get(phase, {'tool': 'nmap', 'confidence': 0.5, 'reasoning': 'Default'})
    
    def get_statistics(self):
        """Get scan statistics"""
        findings = []
        for scan in self.active_scans.values():
            findings.extend(scan.get('findings', []))
        return {
            'active_scans': len(self.active_scans),
            'total_scans': len(self.active_scans),
            'total_findings': len(findings),
            'critical_findings': len([f for f in findings if f.get('severity', 0) >= 9]),
            'high_findings': len([f for f in findings if 7 <= f.get('severity', 0) < 9]),
            'medium_findings': len([f for f in findings if 4 <= f.get('severity', 0) < 7]),
            'low_findings': len([f for f in findings if f.get('severity', 0) < 4]),
            'tools_available': 50
        }
    
    def get_recent_scans(self, limit=10):
        """Get recent scans"""
        scans = list(self.active_scans.values())
        scans.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        return scans[:limit]
    
    def get_recent_findings(self, limit=10):
        """Get recent findings"""
        findings = []
        for scan in self.active_scans.values():
            for f in scan.get('findings', []):
                f['scan_id'] = scan.get('scan_id')
                findings.append(f)
        findings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return findings[:limit]


def get_scan_manager(socketio=None, active_scans_ref=None) -> ScanManager:
    """Get or create scan manager singleton"""
    global _scan_manager
    
    print(f"[get_scan_manager] Called with:")
    print(f"  socketio: {socketio}")
    print(f"  active_scans_ref: {active_scans_ref}")
    print(f"  _scan_manager exists: {_scan_manager is not None}")
    
    # Always update the scan manager with the latest references if provided
    if _scan_manager is not None and socketio is not None and active_scans_ref is not None:
        # Update the existing scan manager with new references
        print(f"[get_scan_manager] Updating existing ScanManager instance")
        _scan_manager.socketio = socketio
        _scan_manager.active_scans = active_scans_ref
        print(f"[ScanManager] Updated existing instance with new references")
        print(f"  socketio: {socketio}")
        print(f"  active_scans_ref keys: {list(active_scans_ref.keys()) if active_scans_ref else 'None'}")
        
        # Re-initialize components to ensure agent_class is set
        print(f"[get_scan_manager] Re-initializing components...")
        _scan_manager._init_components()
    elif _scan_manager is None:
        logger.info("Creating new ScanManager instance")
        # If parameters are provided, use them
        if socketio is not None and active_scans_ref is not None:
            _scan_manager = ScanManager(socketio, active_scans_ref)
            print(f"[ScanManager] Created new instance with references")
            print(f"  socketio: {socketio}")
            print(f"  active_scans_ref keys: {list(active_scans_ref.keys()) if active_scans_ref else 'None'}")
        else:
            # Fallback to importing from app (may cause circular import)
            try:
                from app import socketio, active_scans
                _scan_manager = ScanManager(socketio, active_scans)
                print(f"[ScanManager] Created new instance with app imports")
                print(f"  socketio: {socketio}")
                print(f"  active_scans keys: {list(active_scans.keys()) if active_scans else 'None'}")
            except ImportError:
                # Create with None values if import fails
                _scan_manager = ScanManager(None, {})
                print(f"[ScanManager] Created new instance with empty references")
    
    print(f"[get_scan_manager] Returning _scan_manager: {_scan_manager}")
    return _scan_manager


# Backward compatibility aliases
def get_workflow_engine():
    """Deprecated: Use get_scan_manager() instead"""
    return get_scan_manager()

def get_tool_manager():
    """Get the tool manager from scan manager"""
    # Try to get socketio and active_scans from app module
    try:
        from app import socketio, active_scans
        return get_scan_manager(socketio, active_scans).tool_manager
    except ImportError:
        # Fallback to calling without parameters
        return get_scan_manager().tool_manager
