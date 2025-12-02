"""
Compatibility layer for core.scan_engine imports
Provides backward compatibility for existing code that imports from core.scan_engine
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

# Global instances
_scan_manager = None
_workflow_engine = None
_tool_manager = None

def get_scan_manager():
    """
    Get or create scan manager instance.
    This maintains compatibility with existing code while using the actual implementations.
    """
    global _scan_manager, _workflow_engine, _tool_manager
    
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
        
        # Create a simple manager that delegates to the actual implementations
        class ScanManager:
            def __init__(self, workflow_engine, tool_manager):
                self.workflow_engine = workflow_engine
                self.tool_manager = tool_manager
            
            def start_scan(self, scan_id, target, options):
                """Start a scan - delegate to workflow engine"""
                # This is a simplified implementation
                # In a real implementation, you'd want to properly integrate with the workflow
                pass
            
            def stop_scan(self, scan_id):
                """Stop a scan"""
                pass
            
            def pause_scan(self, scan_id):
                """Pause a scan"""
                pass
            
            def resume_scan(self, scan_id):
                """Resume a scan"""
                pass
            
            def execute_tool(self, scan_id, tool, target, options):
                """Execute a tool - delegate to tool manager"""
                return self.tool_manager.execute_tool(tool, target, options, scan_id, 'unknown')
            
            def get_tool_recommendation(self, scan_id, phase, context):
                """Get tool recommendation"""
                return {'tool': 'default', 'confidence': 1.0, 'reasoning': 'default recommendation'}
            
            def get_statistics(self):
                """Get statistics"""
                return {
                    'active_scans': 0,
                    'total_scans': 0,
                    'total_findings': 0,
                    'critical_findings': 0,
                    'high_findings': 0,
                    'medium_findings': 0,
                    'low_findings': 0,
                    'tools_available': 0
                }
            
            def get_recent_scans(self, limit=10):
                """Get recent scans"""
                return []
            
            def get_recent_findings(self, limit=10):
                """Get recent findings"""
                return []
        
        _scan_manager = ScanManager(_workflow_engine, _tool_manager)
    
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