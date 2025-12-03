"""
Enhanced Scan Engine with Intelligence Integration
Provides backward compatibility while adding intelligence capabilities
"""

import sys
import os
from pathlib import Path

# Add backend to path to ensure imports work correctly
BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))

# Import the actual implementations
from inference.workflow_engine import WorkflowEngine
from inference.tool_manager import ToolManager
from inference.scan_engine_intelligence import IntelligentScanEngine

# Global instances
_scan_manager = None
_workflow_engine = None
_tool_manager = None
_intelligent_engine = None

def get_scan_manager():
    """
    Get or create scan manager instance.
    This maintains compatibility with existing code while using the actual implementations.
    """
    global _scan_manager, _workflow_engine, _tool_manager, _intelligent_engine
    
    # Import here to avoid circular imports
    from app import socketio
    
    if _scan_manager is None:
        # Create the actual implementations
        if _tool_manager is None:
            _tool_manager = ToolManager(socketio)
        
        if _workflow_engine is None:
            # Pass the active_scans reference from app.py
            from app import active_scans
            _workflow_engine = WorkflowEngine(socketio, active_scans)
        
        # Try to get intelligence brain
        brain = None
        try:
            from intelligence import get_optimus_brain
            brain = get_optimus_brain()
        except ImportError:
            pass
        
        # Create intelligent scan engine
        _intelligent_engine = IntelligentScanEngine(_workflow_engine, _tool_manager, socketio, brain)
        
        # Create a manager that delegates to the actual implementations
        class ScanManager:
            def __init__(self, workflow_engine, tool_manager, intelligent_engine):
                self.workflow_engine = workflow_engine
                self.tool_manager = tool_manager
                self.intelligent_engine = intelligent_engine
            
            def start_scan(self, scan_id, target, options):
                """Start a scan - delegate to workflow engine"""
                # For now, we'll use the standard workflow engine
                # In the future, we could switch to intelligent scanning based on options
                self.workflow_engine.start_scan_async(scan_id, target, options)
            
            def stop_scan(self, scan_id):
                """Stop a scan"""
                # Implementation would go here
                pass
            
            def pause_scan(self, scan_id):
                """Pause a scan"""
                # Implementation would go here
                pass
            
            def resume_scan(self, scan_id):
                """Resume a scan"""
                # Implementation would go here
                pass
            
            def execute_tool(self, scan_id, tool, target, options):
                """Execute a tool - delegate to tool manager"""
                return self.tool_manager.execute_tool(tool, target, options, scan_id, 'unknown')
            
            def get_tool_recommendation(self, scan_id, phase, context):
                """Get tool recommendation"""
                # If we have intelligence, use it
                if hasattr(self.intelligent_engine, 'brain') and self.intelligent_engine.brain:
                    try:
                        tools = self.intelligent_engine._get_phase_tools(phase)
                        if tools:
                            decision = self.intelligent_engine.brain.select_tool(
                                tools=tools,
                                context={
                                    'target': context.get('target', ''),
                                    'phase': phase,
                                    **context
                                }
                            )
                            return decision
                    except Exception as e:
                        pass
                # Fallback to default
                return {'tool': 'default', 'confidence': 1.0, 'reasoning': 'default recommendation'}
            
            def get_statistics(self):
                """Get statistics"""
                # Delegate to workflow engine
                from app import active_scans, scan_history
                
                all_scans = list(active_scans.values()) + scan_history
                all_findings = []
                for scan in all_scans:
                    all_findings.extend(scan.get('findings', []))
                
                return {
                    'active_scans': len(active_scans),
                    'total_scans': len(all_scans),
                    'total_findings': len(all_findings),
                    'critical_findings': len([f for f in all_findings if f.get('severity', 0) >= 9.0]),
                    'high_findings': len([f for f in all_findings if 7.0 <= f.get('severity', 0) < 9.0]),
                    'medium_findings': len([f for f in all_findings if 4.0 <= f.get('severity', 0) < 7.0]),
                    'low_findings': len([f for f in all_findings if f.get('severity', 0) < 4.0]),
                    'tools_available': 50  # Approximate
                }
            
            def get_recent_scans(self, limit=10):
                """Get recent scans"""
                from app import active_scans, scan_history
                all_scans = list(active_scans.values()) + scan_history
                all_scans.sort(key=lambda x: x.get('start_time', ''), reverse=True)
                return all_scans[:limit]
            
            def get_recent_findings(self, limit=10):
                """Get recent findings"""
                from app import active_scans, scan_history
                all_findings = []
                for scan in list(active_scans.values()) + scan_history:
                    for finding in scan.get('findings', []):
                        finding['scan_id'] = scan.get('scan_id')
                        all_findings.append(finding)
                all_findings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                return all_findings[:limit]
        
        _scan_manager = ScanManager(_workflow_engine, _tool_manager, _intelligent_engine)
    
    return _scan_manager

# For backward compatibility
def get_workflow_engine():
    """Get workflow engine instance"""
    global _workflow_engine
    if _workflow_engine is None:
        from app import socketio
        from app import active_scans
        _workflow_engine = WorkflowEngine(socketio, active_scans)
    return _workflow_engine

def get_tool_manager():
    """Get tool manager instance"""
    global _tool_manager
    if _tool_manager is None:
        from app import socketio
        _tool_manager = ToolManager(socketio)
    return _tool_manager

def get_intelligent_engine():
    """Get intelligent engine instance"""
    global _intelligent_engine
    if _intelligent_engine is None:
        from app import socketio
        workflow_engine = get_workflow_engine()
        tool_manager = get_tool_manager()
        
        # Try to get intelligence brain
        brain = None
        try:
            from intelligence import get_optimus_brain
            brain = get_optimus_brain()
        except ImportError:
            pass
            
        _intelligent_engine = IntelligentScanEngine(workflow_engine, tool_manager, socketio, brain)
    return _intelligent_engine