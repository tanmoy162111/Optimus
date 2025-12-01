"""
Intelligence Module API Routes
Provides endpoints for memory, learning, chaining, campaigns, and explainability
"""

from flask import Blueprint, request, jsonify
import logging

logger = logging.getLogger(__name__)

intelligence_bp = Blueprint('intelligence', __name__, url_prefix='/api/intelligence')


# === Helper to get intelligence systems ===
def get_optimus_brain():
    """Lazy load OptmusBrain instance"""
    try:
        from intelligence import get_optimus_brain as _get_brain
        return _get_brain()
    except Exception as e:
        logger.warning(f"Failed to load brain: {e}")
        return None


def get_memory_system():
    """Lazy load memory system"""
    try:
        from intelligence import get_memory_system as _get_memory
        return _get_memory()
    except Exception as e:
        logger.warning(f"Failed to load memory: {e}")
        return None


def get_campaign_engine():
    """Lazy load campaign engine"""
    try:
        from intelligence import get_campaign_engine as _get_campaign
        return _get_campaign()
    except Exception as e:
        logger.warning(f"Failed to load campaign engine: {e}")
        return None


def get_explainable_engine():
    """Lazy load explainable AI engine"""
    try:
        from intelligence import get_explainable_engine as _get_explainable
        return _get_explainable()
    except Exception as e:
        logger.warning(f"Failed to load explainable engine: {e}")
        return None


# === Memory & Learning ===
@intelligence_bp.route('/memory/stats', methods=['GET'])
def get_memory_stats():
    """Get memory system statistics"""
    memory = get_memory_system()
    if not memory:
        return jsonify({'error': 'Memory system not available'}), 503
    
    try:
        stats = {
            'scan_stats': memory.get_scan_statistics(),
            'tool_effectiveness': {
                tool: memory.get_tool_effectiveness(tool)
                for tool in ['nmap', 'nuclei', 'nikto', 'sqlmap', 'wpscan']
            }
        }
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/memory/target/<target_hash>', methods=['GET'])
def get_target_profile(target_hash):
    """Get stored profile for a target"""
    memory = get_memory_system()
    if not memory:
        return jsonify({'error': 'Memory system not available'}), 503
    
    try:
        profile = memory.get_target_profile(target_hash)
        if not profile:
            return jsonify({'error': 'Target profile not found'}), 404
        return jsonify(profile), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/memory/patterns', methods=['GET'])
def get_attack_patterns():
    """Get best attack patterns for a target type"""
    memory = get_memory_system()
    if not memory:
        return jsonify({'error': 'Memory system not available'}), 503
    
    try:
        target_type = request.args.get('target_type', 'web')
        limit = request.args.get('limit', 10, type=int)
        
        patterns = memory.get_best_attack_patterns(target_type, limit=limit)
        return jsonify({'patterns': patterns}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# === Vulnerability Chaining ===
@intelligence_bp.route('/chains/analyze', methods=['POST'])
def analyze_vulnerability_chains():
    """Analyze findings for attack chains"""
    brain = get_optimus_brain()
    if not brain:
        return jsonify({'error': 'Intelligence system not available'}), 503
    
    try:
        brain.initialize()
        findings = request.json.get('findings', [])
        
        if not brain.chain_engine:
            return jsonify({'error': 'Chain engine not available'}), 503
        
        analysis = brain.chain_engine.analyze_findings(findings)
        return jsonify(analysis), 200
    except Exception as e:
        logger.error(f"Chain analysis failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/chains/<chain_id>/plan', methods=['GET'])
def get_chain_exploitation_plan(chain_id):
    """Get detailed exploitation plan for a chain"""
    brain = get_optimus_brain()
    if not brain:
        return jsonify({'error': 'Intelligence system not available'}), 503
    
    try:
        brain.initialize()
        
        if not brain.chain_engine:
            return jsonify({'error': 'Chain engine not available'}), 503
        
        plan = brain.chain_engine.get_exploitation_plan(chain_id)
        if not plan:
            return jsonify({'error': 'Chain not found'}), 404
        
        return jsonify(plan), 200
    except Exception as e:
        logger.error(f"Exploitation plan failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# === Campaign Management ===
@intelligence_bp.route('/campaigns', methods=['POST'])
def create_campaign():
    """Create a new multi-target campaign"""
    campaign_engine = get_campaign_engine()
    if not campaign_engine:
        return jsonify({'error': 'Campaign engine not available'}), 503
    
    try:
        data = request.json
        campaign_id = campaign_engine.create_campaign(
            name=data.get('name'),
            targets=data.get('targets', []),
            sector=data.get('sector', 'unknown')
        )
        return jsonify({'campaign_id': campaign_id}), 201
    except Exception as e:
        logger.error(f"Campaign creation failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/campaigns/<campaign_id>', methods=['GET'])
def get_campaign_insights(campaign_id):
    """Get insights for a campaign"""
    campaign_engine = get_campaign_engine()
    if not campaign_engine:
        return jsonify({'error': 'Campaign engine not available'}), 503
    
    try:
        insights = campaign_engine.get_campaign_insights(campaign_id)
        if not insights:
            return jsonify({'error': 'Campaign not found'}), 404
        return jsonify(insights), 200
    except Exception as e:
        logger.error(f"Campaign insights failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/campaigns/<campaign_id>/optimize', methods=['GET'])
def get_optimized_scan_order(campaign_id):
    """Get optimized target scanning order"""
    campaign_engine = get_campaign_engine()
    if not campaign_engine:
        return jsonify({'error': 'Campaign engine not available'}), 503
    
    try:
        order = campaign_engine.get_optimized_scan_order(campaign_id)
        return jsonify({'scan_order': order}), 200
    except Exception as e:
        logger.error(f"Scan order optimization failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/campaigns/<campaign_id>/recommendations/<path:target_url>', methods=['GET'])
def get_target_recommendations(campaign_id, target_url):
    """Get recommendations for a target based on campaign learnings"""
    campaign_engine = get_campaign_engine()
    if not campaign_engine:
        return jsonify({'error': 'Campaign engine not available'}), 503
    
    try:
        recommendations = campaign_engine.get_target_recommendations(campaign_id, target_url)
        return jsonify(recommendations), 200
    except Exception as e:
        logger.error(f"Target recommendations failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# === Explainability ===
@intelligence_bp.route('/decisions/audit', methods=['GET'])
def get_decision_audit_trail():
    """Get AI decision audit trail"""
    explainable = get_explainable_engine()
    if not explainable:
        return jsonify({'error': 'Explainable AI not available'}), 503
    
    try:
        scan_id = request.args.get('scan_id')
        audit = explainable.get_audit_trail(scan_id)
        return jsonify(audit), 200
    except Exception as e:
        logger.error(f"Audit trail failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/decisions/report', methods=['GET'])
def get_audit_report():
    """Get decision audit statistics"""
    explainable = get_explainable_engine()
    if not explainable:
        return jsonify({'error': 'Explainable AI not available'}), 503
    
    try:
        report = explainable.get_audit_report()
        return jsonify(report), 200
    except Exception as e:
        logger.error(f"Audit report failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# === Intelligence Status ===
@intelligence_bp.route('/status', methods=['GET'])
def get_intelligence_status():
    """Get status of all intelligence subsystems"""
    brain = get_optimus_brain()
    if not brain:
        return jsonify({
            'status': 'unavailable',
            'message': 'Intelligence system not initialized'
        }), 503
    
    try:
        brain.initialize()
        status = brain.get_intelligence_status()
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Status check failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# === Zero-Day Discovery ===
@intelligence_bp.route('/zeroday/queue', methods=['GET'])
def get_zeroday_investigation_queue():
    """Get anomalies requiring investigation"""
    brain = get_optimus_brain()
    if not brain:
        return jsonify({'error': 'Intelligence system not available'}), 503
    
    try:
        brain.initialize()
        
        if not brain.zeroday_engine:
            return jsonify({'error': 'Zero-day engine not available'}), 503
        
        queue = brain.zeroday_engine.get_investigation_queue()
        return jsonify({'queue': queue}), 200
    except Exception as e:
        logger.error(f"Zero-day queue failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@intelligence_bp.route('/zeroday/<anomaly_id>/resolve', methods=['POST'])
def resolve_anomaly(anomaly_id):
    """Mark an anomaly as resolved (known vuln or false positive)"""
    brain = get_optimus_brain()
    if not brain:
        return jsonify({'error': 'Intelligence system not available'}), 503
    
    try:
        brain.initialize()
        
        if not brain.zeroday_engine:
            return jsonify({'error': 'Zero-day engine not available'}), 503
        
        vuln_type = request.json.get('vuln_type')
        brain.zeroday_engine.mark_as_known(anomaly_id, vuln_type)
        
        return jsonify({'status': 'resolved'}), 200
    except Exception as e:
        logger.error(f"Anomaly resolution failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
