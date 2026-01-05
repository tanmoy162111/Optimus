"""
Scan state schema enforcement module.
Ensures consistent scan state structure across all components.
"""
from typing import Dict, Any, List
import copy
from datetime import datetime


def ensure_scan_state(scan_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure scan state has all required fields with default values.
    
    Args:
        scan_state: The scan state to validate and normalize
        
    Returns:
        Dict with all required fields present
    """
    if scan_state is None:
        scan_state = {}
    
    # Create a copy to avoid modifying the original
    normalized_state = copy.deepcopy(scan_state)
    
    # Ensure required fields exist with defaults
    defaults = {
        'findings': [],
        'tools_executed': [],
        'phase': 'reconnaissance',
        'target': '',
        'scan_id': normalized_state.get('scan_id', str(hash(datetime.now()))),
        'start_time': normalized_state.get('start_time', datetime.now().isoformat()),
        'status': 'running',
        'config': {},
        'blacklisted_tools': [],
        'recently_used_tools': [],
        'phase_data': {},
        'coverage': 0.0,
        'strategy': 'adaptive',
        'strategy_changes': 0,
        'last_finding_iteration': 0,
        'phase_start_time': normalized_state.get('phase_start_time', datetime.now().isoformat()),
        'target_profile': {},
        'technologies_detected': [],
        'waf_detected': False,
        'stealth_required': False,
        'exploitation_results': [],
        'shell_sessions': [],
    }
    
    # Apply defaults for missing fields
    for key, default_value in defaults.items():
        if key not in normalized_state:
            normalized_state[key] = copy.deepcopy(default_value)
    
    # Ensure findings is a list
    if not isinstance(normalized_state.get('findings'), list):
        normalized_state['findings'] = []
    
    # Ensure tools_executed is a list
    if not isinstance(normalized_state.get('tools_executed'), list):
        normalized_state['tools_executed'] = []
    
    # Ensure blacklisted_tools is a list
    if not isinstance(normalized_state.get('blacklisted_tools'), list):
        normalized_state['blacklisted_tools'] = []
    
    # Ensure phase is a string
    if not isinstance(normalized_state.get('phase'), str):
        normalized_state['phase'] = 'reconnaissance'
    
    # Ensure target is a string
    if not isinstance(normalized_state.get('target'), str):
        normalized_state['target'] = ''
    
    # Ensure coverage is a float
    if not isinstance(normalized_state.get('coverage'), (int, float)):
        normalized_state['coverage'] = 0.0
    
    return normalized_state


def update_scan_state_with_result(scan_state: Dict[str, Any], tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update scan state with tool execution results, ensuring schema compliance.
    
    Args:
        scan_state: Current scan state
        tool_name: Name of the tool executed
        result: Tool execution result
        
    Returns:
        Updated scan state with all required fields
    """
    # First ensure the scan state has proper schema
    scan_state = ensure_scan_state(scan_state)
    
    # Add tool execution record
    tool_record = {
        'tool': tool_name,
        'timestamp': datetime.now().isoformat(),
        'success': result.get('success', False),
        'exit_code': result.get('exit_code', -1),
        'execution_time': result.get('execution_time', 0),
        'findings_count': len(result.get('parsed_results', {}).get('vulnerabilities', []))
    }
    
    scan_state['tools_executed'].append(tool_record)
    
    # Add findings if any
    parsed_results = result.get('parsed_results', {})
    new_findings = parsed_results.get('vulnerabilities', [])
    
    for finding in new_findings:
        if 'id' not in finding:
            finding['id'] = str(hash(f"{tool_name}_{datetime.now().isoformat()}_{len(scan_state['findings'])}"))
        if 'timestamp' not in finding:
            finding['timestamp'] = datetime.now().isoformat()
        scan_state['findings'].append(finding)
    
    # Update coverage
    from inference.autonomous_agent import AutonomousPentestAgent
    agent = AutonomousPentestAgent(None)  # Create temporary agent to calculate coverage
    scan_state['coverage'] = agent._calculate_coverage_real(scan_state)
    
    return ensure_scan_state(scan_state)


def validate_scan_state(scan_state: Dict[str, Any]) -> List[str]:
    """
    Validate scan state and return list of validation errors.
    
    Args:
        scan_state: Scan state to validate
        
    Returns:
        List of validation error messages, empty if valid
    """
    errors = []
    
    if scan_state is None:
        errors.append("Scan state cannot be None")
        return errors
    
    # Check required fields exist
    required_fields = ['findings', 'tools_executed', 'phase', 'target']
    for field in required_fields:
        if field not in scan_state:
            errors.append(f"Missing required field: {field}")
    
    # Check field types
    if not isinstance(scan_state.get('findings'), list):
        errors.append("findings must be a list")
    
    if not isinstance(scan_state.get('tools_executed'), list):
        errors.append("tools_executed must be a list")
    
    if not isinstance(scan_state.get('phase'), str):
        errors.append("phase must be a string")
    
    if not isinstance(scan_state.get('target'), str):
        errors.append("target must be a string")
    
    return errors