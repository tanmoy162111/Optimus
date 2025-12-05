"""
Hybrid Scan Engine - Integrates the hybrid tool system with the autonomous agent
"""
import uuid
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading

# Import the hybrid tool system
try:
    from tools import get_hybrid_tool_system, ToolSource, ResolutionStatus
    from tools.hybrid_tool_system import ToolResolution
    HYBRID_TOOLS_AVAILABLE = True
except ImportError:
    HYBRID_TOOLS_AVAILABLE = False
    print("Warning: Hybrid tools module not available")

from inference.autonomous_agent import AutonomousPentestAgent
from inference.tool_manager import ToolManager

logger = logging.getLogger(__name__)

class HybridScanEngine:
    """Scan engine that uses the hybrid tool system for enhanced tool resolution"""
    
    def __init__(self, socketio, active_scans_ref=None):
        self.socketio = socketio
        self.active_scans = active_scans_ref if active_scans_ref is not None else {}
        self.scan_threads: Dict[str, threading.Thread] = {}
        
        # Initialize hybrid tool system if available
        if HYBRID_TOOLS_AVAILABLE:
            self.tool_system = get_hybrid_tool_system()
            logger.info("Hybrid tool system initialized")
        else:
            self.tool_system = None
            logger.warning("Hybrid tool system not available")
    
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
        logger.info(f"Started hybrid workflow for scan {scan_id}")
    
    def orchestrate_scan(self, scan_state: Dict):
        """Main scan orchestration with hybrid tool system integration"""
        try:
            scan_id = scan_state['scan_id']
            target = scan_state['target']
            
            # Emit scan started
            self.socketio.emit('scan_started', {
                'scan_id': scan_id,
                'target': target,
                'timestamp': scan_state['start_time']
            }, room=f'scan_{scan_id}')
            
            logger.info(f"🚀 Starting hybrid autonomous scan for {target}")
            
            # Use the existing autonomous agent but enhance it with hybrid tool system
            agent = AutonomousPentestAgent(self.socketio)
            
            # Configure the agent properly
            scan_config = {
                'max_time': scan_state.get('time_budget', 3600),
                'depth': scan_state.get('depth', 'normal'),
                'stealth': scan_state.get('stealth', False),
                'aggressive': scan_state.get('aggressive', True),
                'target_type': self._detect_target_type(target),
                'use_hybrid_tools': True  # Enable hybrid tool system
            }
            
            # Run the scan with hybrid tool enhancement
            agent_result = self._run_hybrid_scan(agent, target, scan_config, scan_state)
            
            # Update scan_state with agent's REAL results
            scan_state['findings'] = agent_result.get('findings', [])
            scan_state['tools_executed'] = agent_result.get('tools_executed', [])
            scan_state['coverage'] = agent_result.get('coverage', 0.0)
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
    
    def _run_hybrid_scan(self, agent: AutonomousPentestAgent, target: str, 
                        scan_config: Dict, scan_state: Dict) -> Dict[str, Any]:
        """
        Run scan with hybrid tool system integration
        """
        # Store original tool manager
        original_tool_manager = agent.tool_manager
        
        # Create enhanced tool manager that uses hybrid system
        if self.tool_system:
            enhanced_tool_manager = HybridToolManager(
                self.socketio, 
                self.tool_system,
                original_tool_manager
            )
            agent.tool_manager = enhanced_tool_manager
        
        try:
            # Run the scan with the enhanced tool manager
            result = agent.run_autonomous_scan(target, scan_config)
            return result
        finally:
            # Restore original tool manager
            agent.tool_manager = original_tool_manager
    
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
            'elapsed_time': self._calculate_elapsed_time(scan_state),
            'hybrid_tools_used': self._count_hybrid_tools(scan_state)
        }
    
    def _count_hybrid_tools(self, scan_state: Dict) -> Dict[str, int]:
        """Count tools resolved by different hybrid system sources"""
        if not self.tool_system:
            return {}
        
        # This would need to be enhanced to track which tools were resolved by which source
        # For now, we'll return a placeholder
        return {
            'knowledge_base': 0,
            'discovered': 0,
            'llm_generated': 0,
            'web_research': 0
        }

class HybridToolManager:
    """Enhanced tool manager that uses the hybrid tool system"""
    
    def __init__(self, socketio, hybrid_tool_system, original_tool_manager):
        self.socketio = socketio
        self.hybrid_system = hybrid_tool_system
        self.original_manager = original_tool_manager
        self.tool_execution_history = {}
    
    def execute_tool(self, tool_name: str, target: str, parameters: Dict[str, Any],
                     scan_id: str, phase: str) -> Dict[str, Any]:
        """
        Execute tool with hybrid system resolution
        """
        # Try to resolve tool using hybrid system first
        if self.hybrid_system:
            task_description = self._generate_task_description(tool_name, phase, parameters)
            
            try:
                # Resolve tool through hybrid system
                resolution = self.hybrid_system.resolve_tool(
                    tool_name=tool_name,
                    task=task_description,
                    target=target,
                    context={
                        'phase': phase,
                        'parameters': parameters,
                        'scan_id': scan_id
                    }
                )
                
                # Stream resolution info to frontend
                if self.socketio:
                    self.socketio.emit('tool_resolution', {
                        'scan_id': scan_id,
                        'tool': tool_name,
                        'source': resolution.source.value,
                        'confidence': resolution.confidence,
                        'status': resolution.status.value,
                        'explanation': resolution.explanation
                    }, room=f'scan_{scan_id}')
                
                # If resolution was successful, use the generated command
                if resolution.status in [ResolutionStatus.RESOLVED, ResolutionStatus.PARTIAL]:
                    # Override the tool name and command with hybrid system results
                    actual_tool_name = resolution.tool_name
                    command_override = resolution.command
                    
                    logger.info(f"Using hybrid system resolved command for {tool_name}: {command_override}")
                    
                    # Execute with the resolved command
                    return self._execute_with_resolved_command(
                        actual_tool_name, command_override, target, parameters,
                        scan_id, phase, resolution
                    )
                else:
                    logger.warning(f"Hybrid system failed to resolve {tool_name}, falling back to original")
            except Exception as e:
                logger.error(f"Hybrid system resolution failed: {e}")
        
        # Fall back to original tool manager
        return self.original_manager.execute_tool(
            tool_name, target, parameters, scan_id, phase
        )
    
    def _generate_task_description(self, tool_name: str, phase: str, parameters: Dict) -> str:
        """Generate task description for tool resolution"""
        task_descriptions = {
            'reconnaissance': f"Perform reconnaissance scan with {tool_name}",
            'scanning': f"Scan target for vulnerabilities using {tool_name}",
            'exploitation': f"Exploit identified vulnerabilities with {tool_name}",
            'post_exploitation': f"Gather intelligence from compromised system using {tool_name}",
            'covering_tracks': f"Clean up traces after penetration test using {tool_name}"
        }
        
        return task_descriptions.get(phase, f"Execute {tool_name} in {phase} phase")
    
    def _execute_with_resolved_command(self, tool_name: str, command: str, target: str,
                                     parameters: Dict[str, Any], scan_id: str, phase: str,
                                     resolution: ToolResolution) -> Dict[str, Any]:
        """Execute tool with resolved command"""
        start_time = datetime.now()
        
        try:
            # Notify frontend of execution
            if self.socketio:
                self.socketio.emit('tool_executing', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'command': command,
                    'source': resolution.source.value
                }, room=f'scan_{scan_id}')
            
            # Execute using original tool manager but with resolved command
            # We'll need to modify the parameters to use the resolved command
            modified_parameters = parameters.copy()
            modified_parameters['resolved_command'] = command
            
            result = self.original_manager.execute_tool(
                tool_name, target, modified_parameters, scan_id, phase
            )
            
            # Record result for learning
            execution_time = (datetime.now() - start_time).total_seconds()
            findings_count = len(result.get('parsed_results', {}).get('vulnerabilities', []))
            
            self.hybrid_system.record_execution_result(
                tool_name=tool_name,
                command=command,
                success=result.get('success', False),
                output=result.get('stdout', '') + result.get('stderr', ''),
                findings=result.get('parsed_results', {}).get('vulnerabilities', [])
            )
            
            # Notify completion
            if self.socketio:
                self.socketio.emit('tool_complete', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'findings_count': findings_count,
                    'source_used': resolution.source.value
                }, room=f'scan_{scan_id}')
            
            return result
            
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            if self.socketio:
                self.socketio.emit('tool_error', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'message': str(e)
                }, room=f'scan_{scan_id}')
            
            return {
                'success': False,
                'error': str(e),
                'findings': []
            }
    
    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self.original_manager, 'cleanup'):
            self.original_manager.cleanup()