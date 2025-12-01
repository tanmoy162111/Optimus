"""
Enhanced Scan Engine with Optimus Intelligence Integration
Bridges the workflow engine with the intelligence module
"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class IntelligentScanEngine:
    """
    Wraps existing scan engine with intelligence capabilities
    """
    
    def __init__(self, workflow_engine, tool_manager, socketio, brain=None):
        """
        Initialize intelligent scan engine
        
        Args:
            workflow_engine: Existing WorkflowEngine instance
            tool_manager: Existing ToolManager instance
            socketio: Socket.IO for streaming
            brain: OptimusBrain instance (optional)
        """
        self.workflow = workflow_engine
        self.tool_manager = tool_manager
        self.socketio = socketio
        self.brain = brain
        self.logger = logger
        
    async def run_intelligent_scan(self, scan_id: str, target: str, options: Dict = None):
        """
        Run a scan with intelligence enhancements
        
        Args:
            scan_id: Unique scan identifier
            target: Target URL/IP
            options: Scan options
            
        Returns:
            Complete scan results with intelligence insights
        """
        try:
            # Start with intelligence gathering if brain available
            scan_context = {}
            if self.brain:
                self.logger.info(f"Starting intelligent scan {scan_id} for {target}")
                scan_context = self.brain.start_scan(target, options or {})
                
                # Stream initial intelligence
                await self._stream_update(scan_id, {
                    'type': 'intelligence_initialized',
                    'context': scan_context,
                    'message': 'Intelligence systems initialized'
                })
            
            # Run standard workflow
            all_findings = []
            
            # Get phases from workflow
            phases = ['reconnaissance', 'scanning', 'exploitation', 'post_exploitation', 'covering_tracks']
            
            for phase in phases:
                self.logger.info(f"Running phase: {phase}")
                
                # Get tools for this phase
                available_tools = self._get_phase_tools(phase)
                
                # Intelligent tool selection
                selected_tool = available_tools[0]  # Default
                tool_confidence = 1.0
                reasoning = []
                
                if self.brain and available_tools:
                    try:
                        tool_decision = self.brain.select_tool(
                            tools=available_tools,
                            context={
                                'target': target,
                                'phase': phase,
                                'target_type': scan_context.get('target_type', 'web'),
                                'technologies': scan_context.get('technologies', []),
                                'scan_id': scan_id,
                                **scan_context
                            }
                        )
                        selected_tool = tool_decision.get('selected_tool', available_tools[0])
                        tool_confidence = tool_decision.get('confidence', 1.0)
                        reasoning = tool_decision.get('reasoning', [])
                        
                        # Stream tool selection
                        await self._stream_update(scan_id, {
                            'type': 'intelligence_tool_selection',
                            'tool': selected_tool,
                            'confidence': tool_confidence,
                            'reasoning': reasoning,
                            'alternatives': tool_decision.get('alternatives', [])
                        })
                    except Exception as e:
                        self.logger.warning(f"Intelligence tool selection failed: {e}, using default")
                
                # Execute tool
                try:
                    output, findings = await self.tool_manager.execute_tool(
                        tool_name=selected_tool,
                        target=target,
                        parameters=options or {},
                        scan_id=scan_id,
                        phase=phase
                    )
                    
                    # Process through intelligence if available
                    if self.brain and findings:
                        try:
                            result = self.brain.process_tool_result(
                                tool=selected_tool,
                                context={'target': target, 'phase': phase, 'scan_id': scan_id},
                                output=output,
                                findings=findings
                            )
                            
                            # Stream adaptation if needed
                            if result.get('should_retry') and result.get('adapted_params'):
                                await self._stream_update(scan_id, {
                                    'type': 'intelligence_adaptation',
                                    'message': f'Adapting {selected_tool} parameters',
                                    'defenses': result.get('defenses_detected', []),
                                    'adaptations': list(result.get('adapted_params', {}).keys())
                                })
                            
                            # Stream chains if discovered
                            if result.get('chains_found'):
                                await self._stream_update(scan_id, {
                                    'type': 'intelligence_chains_discovered',
                                    'count': len(result['chains_found']),
                                    'chains': result['chains_found'][:5]  # Top 5
                                })
                        except Exception as e:
                            self.logger.warning(f"Intelligence processing failed: {e}")
                    
                    all_findings.extend(findings)
                    
                except Exception as e:
                    self.logger.error(f"Tool execution failed: {e}")
                    await self._stream_update(scan_id, {
                        'type': 'tool_error',
                        'tool': selected_tool,
                        'error': str(e)
                    })
            
            # Generate exploitation plan if brain available
            exploitation_plan = None
            if self.brain and all_findings:
                try:
                    exploitation_plan = self.brain.get_exploitation_plan(
                        all_findings,
                        scan_context
                    )
                    
                    await self._stream_update(scan_id, {
                        'type': 'intelligence_exploitation_plan',
                        'plan': exploitation_plan
                    })
                except Exception as e:
                    self.logger.warning(f"Exploitation planning failed: {e}")
            
            # Generate intelligent report
            report = None
            if self.brain:
                try:
                    report = self.brain.generate_report(
                        scan_id=scan_id,
                        findings=all_findings,
                        context=scan_context,
                        report_type='technical'
                    )
                except Exception as e:
                    self.logger.warning(f"Intelligent report generation failed: {e}")
            
            return {
                'scan_id': scan_id,
                'findings': all_findings,
                'exploitation_plan': exploitation_plan,
                'report': report,
                'context': scan_context
            }
            
        except Exception as e:
            self.logger.error(f"Intelligent scan failed: {e}", exc_info=True)
            raise
    
    async def _stream_update(self, scan_id: str, update: Dict):
        """Stream update to frontend via WebSocket"""
        try:
            self.socketio.emit('intelligence_update', {
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                **update
            })
        except Exception as e:
            self.logger.warning(f"Failed to stream update: {e}")
    
    def _get_phase_tools(self, phase: str) -> List[str]:
        """Get available tools for a phase"""
        phase_tools = {
            'reconnaissance': ['sublist3r', 'whatweb', 'dnsenum'],
            'scanning': ['nmap', 'nikto', 'nuclei'],
            'exploitation': ['sqlmap', 'dalfox', 'commix'],
            'post_exploitation': ['linpeas'],
            'covering_tracks': []
        }
        return phase_tools.get(phase, [])
