"""
WebSocket Event Handlers
Real-time communication for scan updates and tool execution
"""

import logging
from datetime import datetime
from flask_socketio import join_room, leave_room, emit

logger = logging.getLogger(__name__)

# Store connected clients
connected_clients = {}

# Import global scan storage from globals.py
from globals import active_scans, scan_history

def register_socket_handlers(socketio):
    """Register all WebSocket event handlers."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        from flask import request
        client_id = request.sid
        connected_clients[client_id] = {
            'connected_at': datetime.utcnow().isoformat(),
            'rooms': []
        }
        logger.info(f'Client connected: {client_id}')
        emit('system_status', {'status': 'connected', 'message': 'Connected to Optimus'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection."""
        from flask import request
        client_id = request.sid
        if client_id in connected_clients:
            del connected_clients[client_id]
        logger.info(f'Client disconnected: {client_id}')
    
    @socketio.on('join_scan')
    def handle_join_scan(data):
        """Join a scan room for real-time updates."""
        from flask import request
        scan_id = data.get('scan_id')
        if scan_id:
            room = f'scan_{scan_id}'
            join_room(room)
            if request.sid in connected_clients:
                connected_clients[request.sid]['rooms'].append(room)
            logger.info(f'Client {request.sid} joined room {room}')
            emit('system_status', {'status': 'joined', 'message': f'Joined scan {scan_id}'})
    
    @socketio.on('leave_scan')
    def handle_leave_scan(data):
        """Leave a scan room."""
        from flask import request
        scan_id = data.get('scan_id')
        if scan_id:
            room = f'scan_{scan_id}'
            leave_room(room)
            if request.sid in connected_clients:
                if room in connected_clients[request.sid]['rooms']:
                    connected_clients[request.sid]['rooms'].remove(room)
            logger.info(f'Client {request.sid} left room {room}')
    
    @socketio.on('execute_tool')
    def handle_execute_tool(data):
        """Handle tool execution request."""
        scan_id = data.get('scan_id')
        tool = data.get('tool')
        target = data.get('target')
        options = data.get('options', {})
        
        if not all([scan_id, tool, target]):
            emit('tool_error', {'error': 'Missing required parameters'})
            return
        
        from core.scan_engine import get_scan_manager
        manager = get_scan_manager()
        
        try:
            manager.execute_tool(scan_id, tool, target, options)
        except Exception as e:
            emit('tool_error', {'error': str(e)})
    
    @socketio.on('request_tool_recommendation')
    def handle_tool_recommendation(data):
        """Request tool recommendation for current phase."""
        scan_id = data.get('scan_id')
        phase = data.get('phase')
        context = data.get('context', {})
        
        # Get recommendation from AI
        from core.scan_engine import get_scan_manager
        manager = get_scan_manager()
        
        recommendation = manager.get_tool_recommendation(scan_id, phase, context)
        emit('tool_recommendation', recommendation)
    
    # Helper functions to emit events to scan rooms
    def emit_to_scan(scan_id: str, event: str, data: dict):
        """Emit event to all clients in a scan room."""
        room = f'scan_{scan_id}'
        socketio.emit(event, data, room=room)
    
    # Make emit function available globally
    socketio.emit_to_scan = emit_to_scan
    
    return socketio


# Event emitter functions for use by other modules
def emit_scan_started(socketio, scan_id: str, target: str, config: dict = None):
    """Emit scan started event."""
    socketio.emit_to_scan(scan_id, 'scan_started', {
        'scan_id': scan_id,
        'target': target,
        'config': config or {}
    })

def emit_scan_update(socketio, scan_id: str, phase: str, status: str, coverage: float, time_elapsed: float):
    """Emit scan update event."""
    socketio.emit_to_scan(scan_id, 'scan_update', {
        'phase': phase,
        'status': status,
        'coverage': coverage,
        'time_elapsed': time_elapsed
    })

def emit_phase_transition(socketio, scan_id: str, from_phase: str, to_phase: str, reason: str = None):
    """Emit phase transition event."""
    socketio.emit_to_scan(scan_id, 'phase_transition', {
        'from': from_phase,
        'to': to_phase,
        'reason': reason
    })

def emit_tool_execution_start(socketio, scan_id: str, tool: str, target: str = None):
    """Emit tool execution start event."""
    socketio.emit_to_scan(scan_id, 'tool_execution_start', {
        'tool': tool,
        'target': target,
        'status': 'start'
    })

def emit_tool_output(socketio, scan_id: str, tool: str, output: str, stream: str = 'stdout'):
    """Emit tool output event."""
    socketio.emit_to_scan(scan_id, 'tool_output', {
        'tool': tool,
        'output': output,
        'stream': stream
    })

def emit_tool_execution_complete(socketio, scan_id: str, tool: str, success: bool, findings_count: int = 0, execution_time: float = 0):
    """Emit tool execution complete event."""
    socketio.emit_to_scan(scan_id, 'tool_execution_complete', {
        'tool': tool,
        'status': 'complete',
        'success': success,
        'findings_count': findings_count,
        'execution_time': execution_time
    })

def emit_finding_discovered(socketio, scan_id: str, finding: dict, total_count: int):
    """Emit finding discovered event."""
    socketio.emit_to_scan(scan_id, 'finding_discovered', {
        'finding': finding,
        'total_count': total_count
    })

def emit_scan_complete(socketio, scan_id: str, findings_count: int, time_elapsed: float):
    """Emit scan complete event."""
    socketio.emit_to_scan(scan_id, 'scan_complete', {
        'scan_id': scan_id,
        'findings_count': findings_count,
        'time_elapsed': time_elapsed
    })

def emit_scan_error(socketio, scan_id: str, error: str):
    """Emit scan error event."""
    socketio.emit_to_scan(scan_id, 'scan_error', {
        'scan_id': scan_id,
        'error': error
    })

def emit_tool_resolution(socketio, scan_id: str, tool: str, source: str, confidence: float, status: str, explanation: str):
    """Emit tool resolution event (hybrid system)."""
    socketio.emit_to_scan(scan_id, 'tool_resolution', {
        'tool': tool,
        'source': source,
        'confidence': confidence,
        'status': status,
        'explanation': explanation
    })