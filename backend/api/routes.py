"""
Main API Routes Blueprint
"""

from flask import Blueprint, jsonify, request
from datetime import datetime

api_bp = Blueprint('api', __name__)

@api_bp.route('/')
def api_index():
    """API root endpoint."""
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@api_bp.route('/dashboard/stats')
def dashboard_stats():
    """Get dashboard statistics."""
    # Import here to avoid circular imports
    from core.scan_engine import get_scan_manager
    
    manager = get_scan_manager()
    stats = manager.get_statistics()
    
    return jsonify({
        'active_scans': stats.get('active_scans', 0),
        'total_scans': stats.get('total_scans', 0),
        'total_findings': stats.get('total_findings', 0),
        'critical_findings': stats.get('critical_findings', 0),
        'high_findings': stats.get('high_findings', 0),
        'medium_findings': stats.get('medium_findings', 0),
        'low_findings': stats.get('low_findings', 0),
        'tools_available': stats.get('tools_available', 0),
        'system_health': 'healthy'
    })

@api_bp.route('/dashboard/activity')
def dashboard_activity():
    """Get recent activity."""
    limit = request.args.get('limit', 10, type=int)
    
    from core.scan_engine import get_scan_manager
    manager = get_scan_manager()
    
    recent_scans = manager.get_recent_scans(limit)
    recent_findings = manager.get_recent_findings(limit)
    
    return jsonify({
        'scans': recent_scans,
        'findings': recent_findings
    })