"""
Scan API Routes
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import uuid
import logging
import threading
from execution.ssh_client import KaliSSHClient

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan', __name__)

# In-memory scan storage (in production, use database)
active_scans = {}
scan_history = []

@scan_bp.route('/start', methods=['POST'])
def start_scan():
    """Start a new penetration test scan"""
    try:
        data = request.json
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        # Validate target format
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        # Create scan
        scan_id = str(uuid.uuid4())
        scan = {
            'scan_id': scan_id,
            'target': target,
            'phase': 'reconnaissance',
            'status': 'initializing',
            'start_time': datetime.now().isoformat(),
            'findings': [],
            'tools_executed': [],
            'coverage': 0.0,
            'risk_score': 0.0
        }
        
        active_scans[scan_id] = scan
        
        logger.info(f"Created scan {scan_id} for target {target}")
        
        # In production, this would trigger the workflow engine
        # For now, just return the scan info
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'target': target,
            'phase': 'reconnaissance'
        }), 200
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@scan_bp.route('/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get current status of a scan"""
    try:
        scan = active_scans.get(scan_id)
        
        if not scan:
            # Check history
            for historical_scan in scan_history:
                if historical_scan.get('scan_id') == scan_id:
                    return jsonify(historical_scan), 200
            
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(scan), 200
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': str(e)}), 500

@scan_bp.route('/stop/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan"""
    try:
        scan = active_scans.get(scan_id)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan['status'] = 'stopped'
        scan['end_time'] = datetime.now().isoformat()
        
        # Move to history
        scan_history.append(scan)
        del active_scans[scan_id]
        
        logger.info(f"Stopped scan {scan_id}")
        
        return jsonify({'status': 'stopped', 'scan_id': scan_id}), 200
        
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        return jsonify({'error': str(e)}), 500

@scan_bp.route('/results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """Get detailed results of a scan"""
    try:
        scan = active_scans.get(scan_id)
        
        if not scan:
            for historical_scan in scan_history:
                if historical_scan.get('scan_id') == scan_id:
                    scan = historical_scan
                    break
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        results = {
            'scan_id': scan_id,
            'target': scan.get('target'),
            'status': scan.get('status'),
            'phase': scan.get('phase'),
            'start_time': scan.get('start_time'),
            'end_time': scan.get('end_time'),
            'findings': scan.get('findings', []),
            'tools_executed': scan.get('tools_executed', []),
            'coverage': scan.get('coverage', 0.0),
            'risk_score': scan.get('risk_score', 0.0),
            'summary': {
                'total_findings': len(scan.get('findings', [])),
                'critical': len([f for f in scan.get('findings', []) if f.get('severity', 0) >= 9.0]),
                'high': len([f for f in scan.get('findings', []) if 7.0 <= f.get('severity', 0) < 9.0]),
                'medium': len([f for f in scan.get('findings', []) if 4.0 <= f.get('severity', 0) < 7.0]),
                'low': len([f for f in scan.get('findings', []) if f.get('severity', 0) < 4.0])
            }
        }
        
        return jsonify(results), 200
        
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({'error': str(e)}), 500

@scan_bp.route('/execute-tool', methods=['POST'])
def execute_tool():
    """Execute a pentesting tool on Kali VM"""
    try:
        data = request.json
        scan_id = data.get('scan_id')
        tool_name = data.get('tool')
        target = data.get('target')
        options = data.get('options', {})
        
        if not all([scan_id, tool_name, target]):
            return jsonify({'error': 'scan_id, tool, and target required'}), 400
        
        scan = active_scans.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Execute tool in background
        def run_tool():
            from app import socketio
            
            def output_callback(line):
                # Stream output to WebSocket
                socketio.emit('tool_output', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'output': line
                }, room=scan_id)
            
            try:
                socketio.emit('tool_execution_start', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'target': target
                }, room=scan_id)
                
                with KaliSSHClient() as ssh:
                    result = ssh.execute_tool(
                        tool_name=tool_name,
                        target=target,
                        options=options,
                        output_callback=output_callback
                    )
                    
                    # Update scan with results
                    scan['tools_executed'].append(tool_name)
                    scan['status'] = 'running'
                    
                    # Emit completion
                    socketio.emit('tool_execution_complete', {
                        'scan_id': scan_id,
                        'tool': tool_name,
                        'success': result['success'],
                        'exit_code': result['exit_code'],
                        'execution_time': result.get('execution_time', 0)
                    }, room=scan_id)
                    
            except Exception as e:
                logger.error(f"Error executing tool {tool_name}: {e}")
                socketio.emit('error', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'error': str(e)
                }, room=scan_id)
        
        # Start background execution
        thread = threading.Thread(target=run_tool)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'status': 'started',
            'scan_id': scan_id,
            'tool': tool_name,
            'target': target
        }), 200
        
    except Exception as e:
        logger.error(f"Error in execute_tool: {e}")
        return jsonify({'error': str(e)}), 500

@scan_bp.route('/test-connection', methods=['GET'])
def test_kali_connection():
    """Test connection to Kali VM"""
    try:
        ssh = KaliSSHClient()
        result = ssh.test_connection()
        ssh.disconnect()
        
        if result.get('connected'):
            return jsonify(result), 200
        else:
            return jsonify(result), 500
            
    except Exception as e:
        logger.error(f"Error testing connection: {e}")
        return jsonify({
            'connected': False,
            'error': str(e)
        }), 500
@scan_bp.route('/list', methods=['GET'])
def list_scans():
    """List all scans (active and historical)"""
    try:
        all_scans = []
        
        # Add active scans
        for scan_id, scan in active_scans.items():
            all_scans.append({
                'scan_id': scan_id,
                'target': scan.get('target'),
                'status': scan.get('status'),
                'phase': scan.get('phase'),
                'start_time': scan.get('start_time'),
                'findings_count': len(scan.get('findings', []))
            })
        
        # Add historical scans
        for scan in scan_history[-10:]:  # Last 10
            all_scans.append({
                'scan_id': scan.get('scan_id'),
                'target': scan.get('target'),
                'status': scan.get('status'),
                'phase': scan.get('phase'),
                'start_time': scan.get('start_time'),
                'end_time': scan.get('end_time'),
                'findings_count': len(scan.get('findings', []))
            })
        
        return jsonify({
            'scans': all_scans,
            'active_count': len(active_scans),
            'total_count': len(all_scans)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        return jsonify({'error': str(e)}), 500
