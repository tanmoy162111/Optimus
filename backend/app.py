#!/usr/bin/env python3
"""
Optimus Backend - Main Flask Application
AI-Driven Autonomous Penetration Testing Platform
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO

# Add backend to path
BACKEND_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BACKEND_DIR))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(BACKEND_DIR.parent / 'logs' / 'backend.log')
    ]
)
logger = logging.getLogger('optimus')

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'optimus-secret-key-change-in-production')
app.config['JSON_SORT_KEYS'] = False

# CORS configuration - Allow frontend origin
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            os.environ.get('FRONTEND_URL', 'http://localhost:5173')
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Initialize SocketIO with CORS
socketio = SocketIO(
    app,
    cors_allowed_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        os.environ.get('FRONTEND_URL', 'http://localhost:5173')
    ],
    async_mode='threading',
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25
)

# Create data directories
DATA_DIR = BACKEND_DIR / 'data'
(DATA_DIR / 'scans').mkdir(parents=True, exist_ok=True)
(DATA_DIR / 'reports').mkdir(parents=True, exist_ok=True)
(BACKEND_DIR.parent / 'logs').mkdir(parents=True, exist_ok=True)

# Global active scans dictionary for shared access
active_scans = {}
scan_history = []

# Import and register blueprints
from api.routes import api_bp
from api.scan_routes import scan_bp
from api.tool_routes import tool_bp

app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(scan_bp, url_prefix='/api/scan')
app.register_blueprint(tool_bp, url_prefix='/api/tools')

# Import WebSocket handlers
from websocket.handlers import register_socket_handlers
register_socket_handlers(socketio)

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
            'database': 'operational'
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
            'tools': '/api/tools'
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

def main():
    """Run the application."""
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    
    logger.info(f'Starting Optimus Backend on {host}:{port}')
    logger.info(f'Debug mode: {debug}')
    
    # Use socketio.run instead of app.run for WebSocket support
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        use_reloader=debug,
        log_output=True
    )

if __name__ == '__main__':
    main()