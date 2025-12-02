"""
Training API Routes
"""
from flask import Blueprint, request, jsonify
import logging

logger = logging.getLogger(__name__)

training_bp = Blueprint('training', __name__)

# Training job storage
training_jobs = {}

@training_bp.route('/start', methods=['POST'])
def start_training():
    """Start ML/RL model training"""
    try:
        data = request.json
        datasets = data.get('datasets', [])
        train_rl = data.get('train_rl', True)
        
        job_id = f"training_{len(training_jobs) + 1}"
        
        job = {
            'job_id': job_id,
            'status': 'started',
            'datasets': datasets,
            'train_rl': train_rl,
            'progress': 0
        }
        
        training_jobs[job_id] = job
        
        logger.info(f"Started training job {job_id}")
        
        # In production, this would start training in background
        
        return jsonify({
            'job_id': job_id,
            'status': 'started'
        }), 200
        
    except Exception as e:
        logger.error(f"Error starting training: {e}")
        return jsonify({'error': str(e)}), 500

@training_bp.route('/status/<job_id>', methods=['GET'])
def get_training_status(job_id):
    """Get training job status"""
    try:
        job = training_jobs.get(job_id)
        
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        
        return jsonify(job), 200
        
    except Exception as e:
        logger.error(f"Error getting training status: {e}")
        return jsonify({'error': str(e)}), 500

@training_bp.route('/models', methods=['GET'])
def list_models():
    """List available trained models"""
    try:
        import os
        from ..config import Config
        
        model_dir = Config.MODEL_PATH
        models = []
        
        if os.path.exists(model_dir):
            for filename in os.listdir(model_dir):
                if filename.endswith('.pkl') or filename.endswith('.h5'):
                    model_info = {
                        'name': filename,
                        'type': 'ML' if filename.endswith('.pkl') else 'RL',
                        'size': os.path.getsize(os.path.join(model_dir, filename))
                    }
                    models.append(model_info)
        
        return jsonify({
            'models': models,
            'count': len(models)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        return jsonify({'error': str(e)}), 500
