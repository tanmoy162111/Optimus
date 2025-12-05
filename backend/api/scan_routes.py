"""
Scan API Routes - FIXED VERSION
No circular imports, proper error handling

REPLACES: backend/api/scan_routes.py
"""

import uuid
from datetime import datetime
from flask import Blueprint, jsonify, request
import logging

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan', __name__)


# ============================================
# LAZY LOADING TO AVOID CIRCULAR IMPORTS
# ============================================

def get_active_scans():
    """Lazy load active_scans to avoid circular import"""
    from app import active_scans
    print(f"[scan_routes] get_active_scans() called")
    print(f"  active_scans id: {id(active_scans)}")
    print(f"  active_scans keys: {list(active_scans.keys())}")
    return active_scans

def get_scan_history():
    """Lazy load scan_history to avoid circular import"""
    from app import scan_history
    return scan_history


# ============================================
# SCAN ROUTES
# ============================================

@scan_bp.route('/start', methods=['POST'])
def start_scan():
    """Start a new scan."""
    try:
        data = request.get_json()
        
        if not data or 'target' not in data:
            return jsonify({'error': 'Target is required'}), 400
        
        target = data['target']
        options = {
            'mode': data.get('mode', 'standard'),
            'enableExploitation': data.get('enableExploitation', False),
            'useAI': data.get('useAI', True),
            'maxDuration': data.get('maxDuration', 3600),
            'excludePaths': data.get('excludePaths', '')
        }
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())[:8]
        
        # Create scan object
        scan = {
            'scan_id': scan_id,
            'target': target,
            'phase': 'reconnaissance',
            'status': 'initializing',
            'start_time': datetime.utcnow().isoformat(),
            'end_time': None,
            'findings': [],
            'tools_executed': [],
            'time_elapsed': 0,
            'coverage': 0.0,
            'risk_score': 0.0,
            'options': options
        }
        
        # Add to active scans
        active_scans = get_active_scans()
        print(f"[scan_routes] Before adding scan - active_scans keys: {list(active_scans.keys())}")
        active_scans[scan_id] = scan
        logger.info(f"Added scan {scan_id} to active_scans. Active scans count: {len(active_scans)}")
        print(f"[scan_routes] Added scan {scan_id} to active_scans")
        print(f"  active_scans keys: {list(active_scans.keys())}")
        
        logger.info(f"Created scan {scan_id} for target {target}")
        
        # Start scan in background
        try:
            from core.scan_engine import get_scan_manager
            # Pass the active_scans reference to ensure the scan manager has access to the same dictionary
            from app import socketio
            print(f"[scan_routes] Calling get_scan_manager with socketio and active_scans")
            manager = get_scan_manager(socketio, active_scans)
            print(f"[scan_routes] Got scan manager: {manager}")
            print(f"  manager.active_scans keys: {list(manager.active_scans.keys()) if hasattr(manager, 'active_scans') and manager.active_scans else 'None'}")
            
            if manager is None:
                raise Exception("Scan manager not initialized")
            
            result = manager.start_scan(scan_id, target, options)
            
            if result:
                logger.info(f"Scan {scan_id} started successfully")
            else:
                logger.warning(f"Scan {scan_id} start returned False")
                
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            import traceback
            traceback.print_exc()
            scan['status'] = 'error'
            scan['error'] = str(e)
            return jsonify({'error': f'Failed to start scan: {str(e)}', 'scan': scan}), 500
        
        return jsonify(scan), 201
        
    except Exception as e:
        logger.error(f"Error in start_scan route: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@scan_bp.route('/status/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status."""
    active_scans = get_active_scans()
    scan_history = get_scan_history()
    
    scan = active_scans.get(scan_id)
    if not scan:
        for s in scan_history:
            if s['scan_id'] == scan_id:
                return jsonify(s)
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan)


@scan_bp.route('/stop/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan."""
    active_scans = get_active_scans()
    scan_history = get_scan_history()
    
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        from core.scan_engine import get_scan_manager
        # Pass the active_scans reference to ensure the scan manager has access to the same dictionary
        from app import socketio, active_scans
        manager = get_scan_manager(socketio, active_scans)
        if manager:
            manager.stop_scan(scan_id)
    except Exception as e:
        logger.warning(f"Error stopping scan via manager: {e}")
    
    scan['status'] = 'stopped'
    scan['end_time'] = datetime.utcnow().isoformat()
    
    # Move to history
    scan_history.insert(0, active_scans.pop(scan_id))
    
    return jsonify({'success': True, 'message': 'Scan stopped'})


@scan_bp.route('/pause/<scan_id>', methods=['POST'])
def pause_scan(scan_id):
    """Pause a running scan."""
    active_scans = get_active_scans()
    scan = active_scans.get(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        from core.scan_engine import get_scan_manager
        # Pass the active_scans reference to ensure the scan manager has access to the same dictionary
        from app import socketio, active_scans
        manager = get_scan_manager(socketio, active_scans)
        if manager:
            manager.pause_scan(scan_id)
    except Exception as e:
        logger.warning(f"Error pausing scan via manager: {e}")
    
    scan['status'] = 'paused'
    return jsonify({'success': True, 'message': 'Scan paused'})


@scan_bp.route('/resume/<scan_id>', methods=['POST'])
def resume_scan(scan_id):
    """Resume a paused scan."""
    active_scans = get_active_scans()
    scan = active_scans.get(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        from core.scan_engine import get_scan_manager
        # Pass the active_scans reference to ensure the scan manager has access to the same dictionary
        from app import socketio, active_scans
        manager = get_scan_manager(socketio, active_scans)
        if manager:
            manager.resume_scan(scan_id)
    except Exception as e:
        logger.warning(f"Error resuming scan via manager: {e}")
    
    scan['status'] = 'running'
    return jsonify({'success': True, 'message': 'Scan resumed'})


@scan_bp.route('/results/<scan_id>')
def get_scan_results(scan_id):
    """Get scan results."""
    active_scans = get_active_scans()
    scan_history = get_scan_history()
    
    scan = active_scans.get(scan_id)
    if not scan:
        for s in scan_history:
            if s['scan_id'] == scan_id:
                return jsonify(s)
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan)


@scan_bp.route('/list')
def list_scans():
    """List all scans."""
    active_scans = get_active_scans()
    scan_history = get_scan_history()
    
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    status = request.args.get('status')
    
    # Combine active and history
    all_scans = list(active_scans.values()) + scan_history
    
    # Filter by status
    if status:
        all_scans = [s for s in all_scans if s['status'] == status]
    
    # Sort by start time (newest first)
    all_scans.sort(key=lambda x: x['start_time'], reverse=True)
    
    # Paginate
    start = (page - 1) * limit
    end = start + limit
    paginated = all_scans[start:end]
    
    return jsonify({
        'items': paginated,
        'total': len(all_scans),
        'page': page,
        'per_page': limit,
        'total_pages': (len(all_scans) + limit - 1) // limit,
        'active_count': len(active_scans)
    })


@scan_bp.route('/execute-tool', methods=['POST'])
def execute_tool():
    """Execute a specific tool."""
    data = request.get_json()
    
    scan_id = data.get('scan_id')
    tool = data.get('tool')
    target = data.get('target')
    options = data.get('options', {})
    
    if not all([scan_id, tool, target]):
        return jsonify({'error': 'scan_id, tool, and target are required'}), 400
    
    try:
        from core.scan_engine import get_scan_manager
        manager = get_scan_manager()
        
        if manager:
            result = manager.execute_tool(scan_id, tool, target, options)
            return jsonify({'success': True, 'message': f'Executing {tool}', 'result': result})
        else:
            return jsonify({'error': 'Scan manager not available'}), 500
            
    except Exception as e:
        logger.error(f"Error executing tool: {e}")
        return jsonify({'error': str(e)}), 500


@scan_bp.route('/<scan_id>/findings')
def get_scan_findings(scan_id):
    """Get findings for a specific scan."""
    active_scans = get_active_scans()
    scan_history = get_scan_history()
    
    scan = active_scans.get(scan_id)
    if not scan:
        for s in scan_history:
            if s['scan_id'] == scan_id:
                return jsonify({'findings': s.get('findings', [])})
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({'findings': scan.get('findings', [])})


# ============================================
# HELPER FUNCTIONS (for other modules)
# ============================================

def update_scan(scan_id: str, updates: dict):
    """Update scan data."""
    active_scans = get_active_scans()
    if scan_id in active_scans:
        active_scans[scan_id].update(updates)
        return True
    return False

def add_finding(scan_id: str, finding: dict):
    """Add a finding to a scan."""
    active_scans = get_active_scans()
    if scan_id in active_scans:
        active_scans[scan_id]['findings'].append(finding)
        return True
    return False

def complete_scan(scan_id: str):
    """Mark scan as complete and move to history."""
    active_scans = get_active_scans()
    scan_history = get_scan_history()
    
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        scan['status'] = 'completed'
        scan['end_time'] = datetime.utcnow().isoformat()
        scan_history.insert(0, active_scans.pop(scan_id))
        return True
    return False
