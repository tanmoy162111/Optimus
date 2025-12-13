"""
WebSocket Event Handlers
"""
from flask_socketio import emit, join_room, leave_room
import logging

logger = logging.getLogger(__name__)

def register_handlers(socketio):
    """Register all WebSocket event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        logger.info("Client connected")
        emit('connected', {'status': 'connected', 'message': 'Welcome to Optimus'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        logger.info("Client disconnected")
    
    @socketio.on('join_scan')
    def handle_join_scan(data):
        """Join a scan room to receive real-time updates"""
        scan_id = data.get('scan_id')
        if scan_id:
            # Use the same room naming convention as the backend emitters
            room_name = f'scan_{scan_id}'
            join_room(room_name)
            logger.info(f"Client joined scan room: {room_name}")
            emit('joined', {'scan_id': scan_id, 'message': 'Joined scan room'}, room=room_name)
    
    @socketio.on('leave_scan')
    def handle_leave_scan(data):
        """Leave a scan room"""
        scan_id = data.get('scan_id')
        if scan_id:
            room_name = f'scan_{scan_id}'
            leave_room(room_name)
            logger.info(f"Client left scan room: {room_name}")
            emit('left', {'scan_id': scan_id, 'message': 'Left scan room'})    
    @socketio.on('ping')
    def handle_ping():
        """Handle ping from client"""
        emit('pong', {'timestamp': 'now'})
    
    # These events are emitted by the backend during scan execution:
    # - 'scan_started': When a scan begins
    # - 'phase_transition': When phase changes
    # - 'tool_execution_start': When a tool starts
    # - 'tool_output': Real-time tool output (streaming)
    # - 'scan_update': New findings discovered
    # - 'scan_complete': Scan finished
    # - 'error': Error occurred
    
    # === Hybrid Tool System Events ===
    
    @socketio.on('tool_resolution')
    def handle_tool_resolution(data):
        """Handle tool resolution events from hybrid system"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_resolution', data, room=f'scan_{scan_id}')
    
    @socketio.on('tool_executing')
    def handle_tool_executing(data):
        """Handle tool execution start events"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_executing', data, room=f'scan_{scan_id}')
    
    @socketio.on('tool_complete')
    def handle_tool_complete(data):
        """Handle tool completion events"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_complete', data, room=f'scan_{scan_id}')
    
    @socketio.on('tool_error')
    def handle_tool_error(data):
        """Handle tool error events"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_error', data, room=f'scan_{scan_id}')
    
    @socketio.on('tool_fallback')
    def handle_tool_fallback(data):
        """Handle tool fallback events"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_fallback', data, room=f'scan_{scan_id}')
    
    @socketio.on('tool_warning')
    def handle_tool_warning(data):
        """Handle tool warning events"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_warning', data, room=f'scan_{scan_id}')
    
    @socketio.on('tool_blocked')
    def handle_tool_blocked(data):
        """Handle tool blocked events"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_blocked', data, room=f'scan_{scan_id}')
    
    @socketio.on('tool_discovery')
    def handle_tool_discovery(data):
        """Handle tool discovery events"""
        scan_id = data.get('scan_id')
        if scan_id:
            emit('tool_discovery', data, room=f'scan_{scan_id}')
    
    logger.info("WebSocket handlers registered")