"""
Report API Routes
"""

from flask import Blueprint, jsonify, send_file, request
from reporting.report_generator import VulnerabilityReportGenerator
import os
import json

# Lazy load global scan storage from app.py
def get_active_scans():
    """Lazy load active_scans to avoid circular import"""
    from app import active_scans
    return active_scans

def get_scan_history():
    """Lazy load scan_history to avoid circular import"""
    from app import scan_history
    return scan_history

def get_from_history(scan_id):
    """
    Get scan from history storage
    """
    # In a real implementation, this would query a database
    # For now, we'll check the scan_history
    scan_history = get_scan_history()
    for scan in scan_history:
        if scan.get('scan_id') == scan_id:
            return scan
    return None

report_bp = Blueprint('report', __name__)

@report_bp.route('/generate/<scan_id>', methods=['GET'])
def generate_report(scan_id):
    """Generate comprehensive report for scan"""
    # Get scan data
    scan = get_active_scans().get(scan_id) or get_from_history(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Generate report
    generator = VulnerabilityReportGenerator()
    report = generator.generate_detailed_report(scan)
    
    return jsonify(report), 200

@report_bp.route('/download/<scan_id>/<format>', methods=['GET'])
def download_report(scan_id, format):
    """Download report in specified format (json)"""
    scan = get_active_scans().get(scan_id) or get_from_history(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    generator = VulnerabilityReportGenerator()
    report = generator.generate_detailed_report(scan)
    
    # For now, we only support JSON format
    if format.lower() != 'json':
        return jsonify({'error': 'Only JSON format is currently supported'}), 400
    
    # Save report to temporary file
    filename = f'optimus_report_{scan_id}.json'
    filepath = os.path.join('/tmp', filename) if os.name != 'nt' else os.path.join(os.environ.get('TEMP', 'C:\\temp'), filename)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Write report to file
    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2)
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name=f'optimus_report_{scan_id}.{format}'
    )

@report_bp.route('/vulnerability/<scan_id>/<vuln_id>', methods=['GET'])
def get_vulnerability_details(scan_id, vuln_id):
    """Get detailed information about specific vulnerability"""
    scan = get_active_scans().get(scan_id) or get_from_history(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    vuln = next((f for f in scan['findings'] if f.get('id') == vuln_id), None)
    
    if not vuln:
        return jsonify({'error': 'Vulnerability not found'}), 404
    
    generator = VulnerabilityReportGenerator()
    detailed_vuln = generator._generate_vulnerability_entry(vuln)
    
    return jsonify(detailed_vuln), 200

@report_bp.route('/executive-summary/<scan_id>', methods=['GET'])
def get_executive_summary(scan_id):
    """Get high-level executive summary for a scan"""
    scan = get_active_scans().get(scan_id) or get_from_history(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    generator = VulnerabilityReportGenerator()
    report = generator.generate_detailed_report(scan)
    
    return jsonify(report['executive_summary']), 200

@report_bp.route('/remediation-plan/<scan_id>', methods=['GET'])
def get_remediation_plan(scan_id):
    """Get prioritized remediation roadmap"""
    scan = get_active_scans().get(scan_id) or get_from_history(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    generator = VulnerabilityReportGenerator()
    report = generator.generate_detailed_report(scan)
    
    return jsonify(report['recommendations']), 200