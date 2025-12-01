"""
Main Flask Application with SocketIO
"""
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
from config import Config
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Import and register blueprints
from api.scan_routes import scan_bp
from api.training_routes import training_bp
from api.metrics_routes import metrics_bp
from api.report_routes import report_bp
from api.intelligence_routes import intelligence_bp

app.register_blueprint(scan_bp, url_prefix='/api/scan')
app.register_blueprint(training_bp, url_prefix='/api/training')
app.register_blueprint(metrics_bp, url_prefix='/api/metrics')
app.register_blueprint(report_bp, url_prefix='/api/report')
app.register_blueprint(intelligence_bp)

# Import WebSocket handlers
from api.websocket_handlers import register_handlers
register_handlers(socketio)

# Health check endpoint
@app.route('/health')
def health_check():
    return {'status': 'healthy', 'service': 'Optimus Backend'}, 200

@app.route('/')
def index():
    return {
        'name': 'Project Optimus API',
        'version': '1.0.0',
        'description': 'AI-Driven Autonomous Penetration Testing Agent',
        'endpoints': {
            'scan': '/api/scan',
            'training': '/api/training',
            'metrics': '/api/metrics',
            'report': '/api/report',
            'intelligence': '/api/intelligence',
            'websocket': '/socket.io'
        }
    }, 200

if __name__ == '__main__':
    logger.info(f"Starting Optimus Backend on port {Config.FLASK_PORT}")
    socketio.run(
        app,
        host='0.0.0.0',
        port=Config.FLASK_PORT,
        debug=(Config.FLASK_ENV == 'development')
    )