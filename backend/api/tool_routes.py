"""
Tool API Routes - Integrates with Hybrid Tool System
"""

from flask import Blueprint, jsonify, request
import json
from pathlib import Path

tool_bp = Blueprint('tools', __name__)

# Tool inventory path
INVENTORY_PATH = Path(__file__).parent.parent / 'data' / 'tool_inventory.json'

def load_inventory():
    """Load tool inventory from file."""
    if INVENTORY_PATH.exists():
        with open(INVENTORY_PATH) as f:
            return json.load(f)
    return {'tools': [], 'statistics': {}}

def save_inventory(data):
    """Save tool inventory to file."""
    INVENTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(INVENTORY_PATH, 'w') as f:
        json.dump(data, f, indent=2)

@tool_bp.route('/available')
def get_available_tools():
    """Get available tools."""
    category = request.args.get('category')
    
    try:
        from tools import get_hybrid_tool_system
        system = get_hybrid_tool_system()
        tools = system.get_available_tools()
        
        if category:
            tools = [t for t in tools if t.get('category') == category]
        
        return jsonify({'tools': tools})
    except ImportError:
        # Fallback to inventory file
        inventory = load_inventory()
        tools = inventory.get('tools', [])
        
        if category:
            tools = [t for t in tools if t.get('category') == category]
        
        return jsonify({'tools': tools})

@tool_bp.route('/categories')
def get_categories():
    """Get tool categories."""
    categories = [
        'recon', 'scanning', 'enumeration', 'exploitation',
        'post_exploitation', 'password', 'wireless', 'web',
        'database', 'forensics', 'reverse_engineering',
        'sniffing', 'social_engineering', 'reporting', 'utility'
    ]
    return jsonify({'categories': categories})

@tool_bp.route('/resolve', methods=['POST'])
def resolve_tool():
    """Resolve a tool using the hybrid system."""
    data = request.get_json()
    
    tool_name = data.get('tool_name')
    task = data.get('task', 'general scan')
    target = data.get('target', '')
    context = data.get('context', {})
    
    if not tool_name:
        return jsonify({'error': 'tool_name is required'}), 400
    
    try:
        from tools import get_hybrid_tool_system
        system = get_hybrid_tool_system()
        resolution = system.resolve_tool(tool_name, task, target, context)
        
        # Safely extract attributes with defaults
        return jsonify({
            'tool_name': resolution.tool_name,
            'source': resolution.source.value if hasattr(resolution.source, 'value') else str(resolution.source),
            'status': resolution.status.value if hasattr(resolution.status, 'value') else str(resolution.status),
            'command': resolution.command or '',
            'explanation': resolution.explanation or '',
            'confidence': resolution.confidence or 0.0,
            'examples': resolution.examples or [],
            'warnings': resolution.warnings or [],
            'alternatives': resolution.alternatives or []
        })
    except ImportError:
        # Fallback response
        return jsonify({
            'tool_name': tool_name,
            'source': 'fallback',
            'status': 'partial',
            'command': f'{tool_name} {target}',
            'explanation': 'Hybrid tool system not available',
            'confidence': 0.3,
            'examples': [],
            'warnings': ['Hybrid tool system not loaded'],
            'alternatives': []
        })

@tool_bp.route('/scan', methods=['POST'])
def scan_tools():
    """Scan system for available tools."""
    try:
        # Try to get SSH client from the tool manager if available
        ssh_client = None
        try:
            # Try to get the tool manager directly
            from core.scan_engine import get_tool_manager
            tool_manager = get_tool_manager()
            print(f"[DEBUG] tool_manager: {tool_manager}")
            if tool_manager:
                ssh_client = getattr(tool_manager, 'ssh_client', None)
                print(f"[DEBUG] ssh_client: {ssh_client}")
        except Exception as e:
            print(f"[DEBUG] Error getting tool manager: {e}")
            # If we can't get the SSH client from tool manager, that's fine
            # The tool scanner will fall back to local scanning
            pass
        
        from tools import get_tool_scanner
        # Pass the SSH client to the tool scanner if available
        scanner = get_tool_scanner(ssh_client)
        print(f"[DEBUG] scanner: {scanner}")
        result = scanner.scan_system()
        print(f"[DEBUG] scan result: {result}")
        
        # Process the result to match expected format
        tools_found = len(result) if isinstance(result, list) else 0
        
        # Categorize tools by category for statistics
        by_category = {}
        if isinstance(result, list):
            for tool in result:
                category = tool.get('category', 'unknown')
                if category in by_category:
                    by_category[category] += 1
                else:
                    by_category[category] = 1
        
        return jsonify({
            'tools_found': tools_found,
            'by_category': by_category,
            'tools': result if isinstance(result, list) else []
        })
    except ImportError as e:
        print(f"[DEBUG] ImportError: {e}")
        return jsonify({
            'tools_found': 0,
            'by_category': {},
            'tools': [],
            'message': 'Tool scanner not available'
        })
    except Exception as e:
        print(f"[DEBUG] Exception: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'tools_found': 0,
            'by_category': {},
            'tools': [],
            'error': str(e),
            'message': 'Tool scan failed'
        })

@tool_bp.route('/research/<tool_name>')
def research_tool(tool_name):
    """Research a tool from web sources."""
    try:
        from tools import get_research_engine
        engine = get_research_engine()
        result = engine.research(tool_name)
        
        return jsonify(result)
    except ImportError:
        return jsonify({
            'tool_name': tool_name,
            'description': 'Research engine not available',
            'confidence': 0.0
        })

@tool_bp.route('/inventory')
def get_inventory():
    """Get full tool inventory."""
    try:
        from tools import get_tool_inventory
        inventory = get_tool_inventory()
        tools = inventory.get_all_tools()
        stats = inventory.get_statistics()
        
        return jsonify({
            'tools': tools,
            'statistics': stats
        })
    except ImportError:
        inventory = load_inventory()
        return jsonify(inventory)

@tool_bp.route('/inventory/<tool_name>')
def get_tool_details(tool_name):
    """Get detailed info for a specific tool."""
    try:
        from tools import get_tool_inventory
        inventory = get_tool_inventory()
        tool = inventory.get_tool(tool_name)
        
        if tool:
            return jsonify(tool)
        return jsonify({'error': 'Tool not found'}), 404
    except ImportError:
        inventory = load_inventory()
        for tool in inventory.get('tools', []):
            if tool.get('name') == tool_name:
                return jsonify(tool)
        return jsonify({'error': 'Tool not found'}), 404

@tool_bp.route('/knowledge-base')
def get_knowledge_base():
    """Get knowledge base tools."""
    # Static knowledge base tools
    kb_tools = [
        {
            'name': 'nmap',
            'category': 'scanning',
            'description': 'Network exploration and security auditing tool',
            'source': 'knowledge_base',
            'is_available': True
        },
        {
            'name': 'nuclei',
            'category': 'scanning',
            'description': 'Fast and customizable vulnerability scanner',
            'source': 'knowledge_base',
            'is_available': True
        },
        {
            'name': 'sqlmap',
            'category': 'exploitation',
            'description': 'Automatic SQL injection detection and exploitation',
            'source': 'knowledge_base',
            'is_available': True
        },
        {
            'name': 'gobuster',
            'category': 'enumeration',
            'description': 'Directory/file & DNS busting tool',
            'source': 'knowledge_base',
            'is_available': True
        },
        {
            'name': 'nikto',
            'category': 'web',
            'description': 'Web server scanner',
            'source': 'knowledge_base',
            'is_available': True
        },
        {
            'name': 'wpscan',
            'category': 'web',
            'description': 'WordPress security scanner',
            'source': 'knowledge_base',
            'is_available': True
        },
        {
            'name': 'ffuf',
            'category': 'enumeration',
            'description': 'Fast web fuzzer',
            'source': 'knowledge_base',
            'is_available': True
        },
        {
            'name': 'hydra',
            'category': 'password',
            'description': 'Network login cracker',
            'source': 'knowledge_base',
            'is_available': True
        }
    ]
    return jsonify({'tools': kb_tools})

@tool_bp.route('/statistics')
def get_tool_statistics():
    """Get tool system statistics."""
    try:
        from tools import get_hybrid_tool_system
        system = get_hybrid_tool_system()
        stats = system.get_statistics()
        return jsonify(stats)
    except ImportError:
        return jsonify({
            'total_resolutions': 0,
            'by_source': {},
            'success_rates': {}
        })