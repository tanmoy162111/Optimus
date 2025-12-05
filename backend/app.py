#!/usr/bin/env python3
"""
Optimus Backend - Main Flask Application
AI-Driven Autonomous Penetration Testing Platform
FIXED VERSION - All issues resolved
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from dotenv import load_dotenv

# Load environment variables FIRST
load_dotenv()

# Add backend to path
BACKEND_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

# Create directories BEFORE setting up logging
LOGS_DIR = PROJECT_ROOT / 'logs'
DATA_DIR = BACKEND_DIR / 'data'
LOGS_DIR.mkdir(parents=True, exist_ok=True)
(DATA_DIR / 'scans').mkdir(parents=True, exist_ok=True)
(DATA_DIR / 'reports').mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOGS_DIR / 'backend.log')
    ]
)
logger = logging.getLogger('optimus')

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'optimus-secret-key-change-in-production')
app.config['JSON_SORT_KEYS'] = False

# CORS configuration
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
            "http://localhost:5175",
            "http://127.0.0.1:5175",
            "http://localhost:9007"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Initialize SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
    cors_credentials=True,
    manage_session=False,
    always_connect=True
)

# ========================================
# GLOBAL STATE (Shared across modules)
# ========================================
active_scans = {}
scan_history = []

print(f"[app.py] Initialized active_scans: {active_scans}")
print(f"[app.py] active_scans id: {id(active_scans)}")

# ========================================
# IMPORT AND REGISTER ALL BLUEPRINTS
# ========================================
try:
    from api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    logger.info("Registered: api_bp")
except ImportError as e:
    logger.warning(f"api.routes not available: {e}")

try:
    from api.tool_routes import tool_bp
    app.register_blueprint(tool_bp, url_prefix='/api/tools')
    logger.info("Registered: tool_bp")
except ImportError as e:
    logger.warning(f"api.tool_routes not available: {e}")

try:
    from api.intelligence_routes import intelligence_bp
    app.register_blueprint(intelligence_bp, url_prefix='/api/intelligence')
    logger.info("Registered: intelligence_bp")
except ImportError as e:
    logger.warning(f"api.intelligence_routes not available: {e}")

try:
    from api.metrics_routes import metrics_bp
    app.register_blueprint(metrics_bp, url_prefix='/api/metrics')
    logger.info("Registered: metrics_bp")
except ImportError as e:
    logger.warning(f"api.metrics_routes not available: {e}")

try:
    from api.report_routes import report_bp
    app.register_blueprint(report_bp, url_prefix='/api/reports')
    logger.info("Registered: report_bp")
except ImportError as e:
    logger.warning(f"api.report_routes not available: {e}")

try:
    from api.training_routes import training_bp
    app.register_blueprint(training_bp, url_prefix='/api/training')
    logger.info("Registered: training_bp")
except ImportError as e:
    logger.warning(f"api.training_routes not available: {e}")

# Register WebSocket handlers
try:
    from websocket.handlers import register_socket_handlers
    register_socket_handlers(socketio)
    logger.info("WebSocket handlers registered")
except ImportError as e:
    logger.warning(f"WebSocket handlers not available: {e}")

# ========================================
# INITIALIZE INTELLIGENCE MODULE
# ========================================
optimus_brain = None
try:
    if os.environ.get('OPTIMUS_ENABLE_MEMORY', 'true').lower() == 'true':
        from intelligence import get_optimus_brain
        optimus_brain = get_optimus_brain()
        logger.info("Intelligence module initialized")
except ImportError as e:
    logger.warning(f"Intelligence module not available: {e}")

# ========================================
# INITIALIZE HYBRID TOOL SYSTEM
# ========================================
hybrid_tool_system = None
try:
    from tools import get_hybrid_tool_system
    hybrid_tool_system = get_hybrid_tool_system()
    logger.info("Hybrid tool system initialized")
except ImportError as e:
    logger.warning(f"Hybrid tool system not available: {e}")

# Register scan routes with scan manager (moved here to avoid circular import and undefined variable issues)
try:
    from api.scan_routes import scan_bp
    # Register scan routes with scan manager
    try:
        # Import after socketio is defined to avoid circular imports
        from core.scan_engine import get_scan_manager
        scan_manager = get_scan_manager(socketio, active_scans)
        
        # Update hybrid tool system with SSH client from tool manager
        # Note: SSH client may not be connected yet, it connects on first tool execution
        if hybrid_tool_system and hasattr(scan_manager, 'tool_manager') and scan_manager.tool_manager:
            # Store reference to tool_manager so hybrid system can get ssh_client when needed
            # The ssh_client is created lazily on first connect_ssh() call
            hybrid_tool_system.tool_manager_ref = scan_manager.tool_manager
            logger.info("Hybrid tool system linked to tool manager")
        
        app.register_blueprint(scan_bp, url_prefix='/api/scan')
        logger.info("Registered: scan_bp")
    except ImportError as e:
        logger.error(f"Failed to import scan routes: {e}")
except ImportError as e:
    logger.warning(f"api.scan_routes not available: {e}")

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'components': {
            'api': 'operational',
            'websocket': 'operational',
            'intelligence': 'operational' if optimus_brain else 'disabled',
            'tools': 'operational' if hybrid_tool_system else 'disabled'
        }
    })

@app.route('/')
def index():
    """Root endpoint."""
    return jsonify({
        'name': 'Optimus API',
        'version': '1.0.0',
        'description': 'AI-Driven Autonomous Penetration Testing Platform',
        'endpoints': {
            'health': '/health',
            'api': '/api',
            'scan': '/api/scan',
            'tools': '/api/tools',
            'intelligence': '/api/intelligence',
            'metrics': '/api/metrics',
            'reports': '/api/reports'
        }
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': str(error)}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Internal error: {error}')
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500

# ========================================
# MAIN ENTRY POINT
# ========================================
def main():
    """Run the application."""
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = True  # os.environ.get('DEBUG', 'false').lower() == 'true'
    
    logger.info(f'Starting Optimus Backend on {host}:{port}')
    logger.info(f'Debug mode: {debug}')
    logger.info(f'Kali VM: {os.environ.get("KALI_HOST", "not configured")}')
    
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,  # Disable reloader to avoid duplicate processes
        log_output=True
    )

if __name__ == '__main__':
    main()