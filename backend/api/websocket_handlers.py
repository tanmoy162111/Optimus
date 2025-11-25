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
            join_room(scan_id)
            logger.info(f"Client joined scan room: {scan_id}")
            emit('joined', {'scan_id': scan_id, 'message': 'Joined scan room'}, room=scan_id)
    
    @socketio.on('leave_scan')
    def handle_leave_scan(data):
        """Leave a scan room"""
        scan_id = data.get('scan_id')
        if scan_id:
            leave_room(scan_id)
            logger.info(f"Client left scan room: {scan_id}")
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
    
    logger.info("WebSocket handlers registered")
