"""
Metrics API Routes
"""
from flask import Blueprint, jsonify
import json
import os
import logging

logger = logging.getLogger(__name__)

metrics_bp = Blueprint('metrics', __name__)

@metrics_bp.route('/ml', methods=['GET'])
def get_ml_metrics():
    """Get ML model performance metrics"""
    try:
        metrics_file = 'data/ml_training_state.json'
        
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                state = json.load(f)
                return jsonify(state.get('ml_metrics', {})), 200
        
        # Return default metrics if file doesn't exist
        return jsonify({
            'vuln_detector': {
                'f1': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'accuracy': 0.0
            },
            'attack_classifier': {
                'f1': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'accuracy': 0.0
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting ML metrics: {e}")
        return jsonify({'error': str(e)}), 500

@metrics_bp.route('/rl', methods=['GET'])
def get_rl_metrics():
    """Get RL agent performance metrics"""
    try:
        metrics_file = 'data/ml_training_state.json'
        
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                state = json.load(f)
                return jsonify(state.get('rl_metrics', {})), 200
        
        # Return default metrics
        return jsonify({
            'avg_episode_reward': 0.0,
            'episodes_trained': 0,
            'vulnerability_discovery_rate': 0.0,
            'time_efficiency': 0.0
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting RL metrics: {e}")
        return jsonify({'error': str(e)}), 500

@metrics_bp.route('/scan-history', methods=['GET'])
def get_scan_history():
    """Get historical scan metrics"""
    try:
        # In production, this would query from database
        history = {
            'total_scans': 0,
            'total_findings': 0,
            'avg_scan_time': 0,
            'recent_scans': []
        }
        
        return jsonify(history), 200
        
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return jsonify({'error': str(e)}), 500

@metrics_bp.route('/system', methods=['GET'])
def get_system_metrics():
    """Get system performance metrics"""
    try:
        import psutil
        
        metrics = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent
        }
        
        return jsonify(metrics), 200
        
    except ImportError:
        return jsonify({
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_percent': 0,
            'note': 'psutil not installed'
        }), 200
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return jsonify({'error': str(e)}), 500
