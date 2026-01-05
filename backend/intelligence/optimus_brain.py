"""
Optimus Brain - Unified Intelligence Engine

This is the main integration module that connects all intelligence components:
- Smart Memory System
- Web Intelligence
- Delegation System
- Real-Time Adaptive Exploitation
- Vulnerability Chaining
- Explainable AI
- Continuous Learning
- Zero-Day Discovery
- Campaign Intelligence

This unified engine provides a single interface for the pentesting agent
to leverage all advanced capabilities.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import threading

logger = logging.getLogger(__name__)


@dataclass
class OptimusConfig:
    """Configuration for Optimus Brain"""
    enable_memory: bool = True
    enable_web_intel: bool = True
    enable_delegation: bool = True
    enable_adaptive: bool = True
    enable_chaining: bool = True
    enable_explainable: bool = True
    enable_learning: bool = True
    enable_zeroday: bool = True
    enable_campaign: bool = True
    llm_client: Any = None
    data_path: str = "data"


class OptimusBrain:
    """
    Unified Intelligence Engine for Autonomous Penetration Testing
    
    This is the brain of the Optimus agent, coordinating all intelligence
    subsystems to provide:
    - Intelligent decision making
    - Cross-scan learning
    - Attack chain optimization
    - Real-time adaptation
    - Explainable actions
    - Campaign-level intelligence
    """
    
    def __init__(self, config: OptimusConfig = None):
        self.config = config or OptimusConfig()
        
        # Initialize components
        self.memory_system = None
        self.web_intel = None
        self.delegation_system = None
        self.adaptive_engine = None
        self.chain_engine = None
        self.explainable_engine = None
        self.learning_engine = None
        self.zeroday_engine = None
        self.campaign_engine = None
        
        self._initialized = False
        self._lock = threading.Lock()
        
        logger.info("Optimus Brain created (not yet initialized)")
    
    def initialize(self):
        """Initialize all intelligence components"""
        with self._lock:
            if self._initialized:
                return
            
            logger.info("Initializing Optimus Brain...")
            
            # Initialize Memory System (foundation for other components)
            if self.config.enable_memory:
                try:
                    from .memory_system import get_memory_system
                    self.memory_system = get_memory_system()
                    logger.info("✓ Memory System initialized")
                except Exception as e:
                    logger.error(f"X Memory System failed: {e}")
            
            # Initialize Web Intelligence
            if self.config.enable_web_intel:
                try:
                    from .web_intelligence import get_web_intelligence
                    self.web_intel = get_web_intelligence()
                    logger.info("✓ Web Intelligence initialized")
                except Exception as e:
                    logger.error(f"X Web Intelligence failed: {e}")
            
            # Initialize Delegation System
            if self.config.enable_delegation:
                try:
                    from .delegation_system import get_agent_coordinator
                    self.delegation_system = get_agent_coordinator(self.config.llm_client)
                    logger.info("✓ Delegation System initialized")
                except Exception as e:
                    logger.error(f"X Delegation System failed: {e}")
            
            # Initialize Adaptive Exploitation Engine
            if self.config.enable_adaptive:
                try:
                    from .adaptive_exploitation import get_adaptive_engine
                    self.adaptive_engine = get_adaptive_engine(self.memory_system)
                    logger.info("✓ Adaptive Exploitation Engine initialized")
                except Exception as e:
                    logger.error(f"X Adaptive Exploitation failed: {e}")
            
            # Initialize Vulnerability Chain Engine
            if self.config.enable_chaining:
                try:
                    from .vulnerability_chaining import get_chain_engine
                    self.chain_engine = get_chain_engine(self.memory_system)
                    logger.info("✓ Vulnerability Chain Engine initialized")
                except Exception as e:
                    logger.error(f"X Vulnerability Chaining failed: {e}")
            
            # Initialize Explainable AI Engine
            if self.config.enable_explainable:
                try:
                    from .explainable_ai import get_explainable_engine
                    self.explainable_engine = get_explainable_engine()
                    logger.info("✓ Explainable AI Engine initialized")
                except Exception as e:
                    logger.error(f"X Explainable AI failed: {e}")
            
            # Initialize Continuous Learning Engine
            if self.config.enable_learning:
                try:
                    from .continuous_learning import get_learning_engine
                    self.learning_engine = get_learning_engine(self.memory_system)
                    logger.info("✓ Continuous Learning Engine initialized")
                except Exception as e:
                    logger.error(f"X Continuous Learning failed: {e}")
            
            # Initialize Zero-Day Discovery Engine
            if self.config.enable_zeroday:
                try:
                    from .continuous_learning import get_zeroday_engine
                    self.zeroday_engine = get_zeroday_engine(self.memory_system)
                    logger.info("✓ Zero-Day Discovery Engine initialized")
                except Exception as e:
                    logger.error(f"✗ Zero-Day Discovery failed: {e}")
            
            # Initialize Campaign Intelligence Engine
            if self.config.enable_campaign:
                try:
                    from .campaign_intelligence import get_campaign_engine
                    self.campaign_engine = get_campaign_engine(self.memory_system)
                    logger.info("✓ Campaign Intelligence Engine initialized")
                except Exception as e:
                    logger.error(f"✗ Campaign Intelligence failed: {e}")
            
            self._initialized = True
            logger.info("Optimus Brain initialization complete")
    
    # ==================== UNIFIED INTERFACES ====================
    
    def start_scan(self, target: str, options: Dict = None) -> Dict:
        """
        Start an intelligent scan with all subsystems engaged
        
        Args:
            target: Target URL or IP
            options: Scan options
            
        Returns:
            Scan context with intelligence data
        """
        self.initialize()
        
        options = options or {}
        scan_context = {
            'target': target,
            'start_time': datetime.now().isoformat(),
            'scan_id': f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'intelligence': {}
        }
        
        # Gather pre-scan intelligence
        if self.web_intel:
            try:
                intel = self.web_intel.gather_target_intelligence(target)
                scan_context['intelligence']['web_intel'] = intel
                logger.info(f"Gathered web intelligence for {target}")
            except Exception as e:
                logger.error(f"Web intelligence gathering failed: {e}")
        
        # Check memory for past scans
        if self.memory_system:
            try:
                profile = self.memory_system.get_target_profile(target)
                if profile:
                    scan_context['intelligence']['past_profile'] = profile
                    logger.info(f"Found past profile for {target}")
                
                # Find similar targets
                if not profile:
                    # Get similar targets for hints
                    pass
            except Exception as e:
                logger.error(f"Memory recall failed: {e}")
        
        # Get recommended approach from learning engine
        if self.learning_engine:
            try:
                stats = self.learning_engine.get_learning_stats()
                scan_context['intelligence']['learning_stats'] = stats
            except Exception as e:
                logger.error(f"Learning stats failed: {e}")
        
        return scan_context
    
    def select_tool(self, tools: List[str], context: Dict) -> Dict:
        """
        Intelligently select the best tool for the current context
        
        Args:
            tools: Available tools
            context: Current scan context
            
        Returns:
            Tool selection with explanation
        """
        self.initialize()
        
        result = {
            'selected_tool': tools[0] if tools else None,
            'confidence': 0.5,
            'reasoning': [],
            'alternatives': []
        }
        
        scores = {}
        factors = []
        
        # Get learning-based recommendation
        if self.learning_engine:
            recommended = self.learning_engine.get_recommended_tool(tools, context)
            if recommended:
                scores[recommended] = scores.get(recommended, 0) + 0.3
                factors.append({
                    'name': 'learning_recommendation',
                    'description': f'Continuous learning recommends {recommended}',
                    'weight': 0.3,
                    'impact': 'positive',
                    'source': 'learning'
                })
        
        # Check memory for tool effectiveness on similar targets
        if self.memory_system:
            try:
                target_type = context.get('target_type', 'web')
                phase = context.get('phase', 'recon')
                
                for tool in tools:
                    effectiveness = self.memory_system.get_tool_effectiveness(
                        tool, target_type, phase
                    )
                    if effectiveness['sample_count'] > 0:
                        scores[tool] = scores.get(tool, 0) + effectiveness['success_rate'] * 0.4
                        factors.append({
                            'name': f'memory_{tool}',
                            'description': f'{tool} has {effectiveness["success_rate"]:.0%} success rate',
                            'weight': effectiveness['success_rate'] * 0.4,
                            'impact': 'positive' if effectiveness['success_rate'] > 0.5 else 'neutral',
                            'source': 'memory'
                        })
            except Exception as e:
                logger.error(f"Memory tool check failed: {e}")
        
        # Get adaptive engine recommendation
        if self.adaptive_engine:
            try:
                recommended = self.adaptive_engine.get_recommended_strategy(
                    tools, context.get('target', ''), context.get('phase', '')
                )
                if recommended:
                    scores[recommended] = scores.get(recommended, 0) + 0.2
                    factors.append({
                        'name': 'adaptive_recommendation',
                        'description': f'Adaptive engine recommends {recommended}',
                        'weight': 0.2,
                        'impact': 'positive',
                        'source': 'adaptive'
                    })
            except Exception as e:
                logger.error(f"Adaptive recommendation failed: {e}")
        
        # Select best tool
        if scores:
            best_tool = max(scores, key=scores.get)
            result['selected_tool'] = best_tool
            result['confidence'] = min(1.0, scores[best_tool])
            result['alternatives'] = [
                {'tool': t, 'score': s}
                for t, s in sorted(scores.items(), key=lambda x: x[1], reverse=True)
                if t != best_tool
            ][:3]
        
        result['reasoning'] = factors
        
        # Record decision for explainability
        if self.explainable_engine:
            self.explainable_engine.record_tool_selection(
                result['selected_tool'],
                context,
                scores,
                factors
            )
        
        return result
    
    def process_tool_result(self, tool: str, context: Dict, 
                           output: str, findings: List[Dict]) -> Dict:
        """
        Process tool execution result through all intelligence systems
        
        Args:
            tool: Tool that was executed
            context: Execution context
            output: Tool output
            findings: Vulnerabilities found
            
        Returns:
            Processing results with recommendations
        """
        self.initialize()
        
        result = {
            'success': len(findings) > 0,
            'findings_count': len(findings),
            'should_retry': False,
            'adapted_params': None,
            'next_actions': [],
            'chains_found': [],
            'anomalies': []
        }
        
        # Update continuous learning
        if self.learning_engine:
            try:
                self.learning_engine.record_tool_result(
                    tool, context, result['success'], len(findings)
                )
            except Exception as e:
                logger.error(f"Learning update failed: {e}")
        
        # Process through adaptive engine
        if self.adaptive_engine:
            try:
                exec_context = self.adaptive_engine.create_execution_context(
                    tool, context.get('target', ''), context, context.get('phase', '')
                )
                
                adaptive_result = self.adaptive_engine.process_execution_result(
                    exec_context, output, None, None, findings
                )
                
                result['should_retry'] = adaptive_result.get('should_retry', False)
                result['adapted_params'] = adaptive_result.get('adapted_params')
                result['defenses_detected'] = adaptive_result.get('defenses_detected', [])
                
            except Exception as e:
                logger.error(f"Adaptive processing failed: {e}")
        
        # Analyze vulnerability chains
        if self.chain_engine and findings:
            try:
                chain_analysis = self.chain_engine.analyze_findings(findings)
                result['chains_found'] = chain_analysis.get('top_chains', [])
                
                if chain_analysis.get('highest_impact_chain'):
                    result['recommended_chain'] = chain_analysis['highest_impact_chain']
                    
            except Exception as e:
                logger.error(f"Chain analysis failed: {e}")
        
        # Check for zero-day indicators
        if self.zeroday_engine:
            try:
                # Analyze response for anomalies
                for finding in findings:
                    anomaly = self.zeroday_engine.analyze_response(
                        finding.get('url', ''),
                        finding.get('payload', ''),
                        {'content': output, 'time': 0}
                    )
                    if anomaly:
                        result['anomalies'].append({
                            'type': anomaly.anomaly_type.value,
                            'description': anomaly.description,
                            'priority': anomaly.investigation_priority
                        })
            except Exception as e:
                logger.error(f"Zero-day analysis failed: {e}")
        
        # Update memory
        if self.memory_system:
            try:
                self.memory_system.record_tool_execution(
                    tool_name=tool,
                    target_type=context.get('target_type', 'web'),
                    phase=context.get('phase', ''),
                    context=context,
                    success=result['success'],
                    vulns_found=len(findings),
                    execution_time=context.get('execution_time', 0)
                )
            except Exception as e:
                logger.error(f"Memory update failed: {e}")
        
        return result
    
    def get_exploitation_plan(self, findings: List[Dict], 
                             context: Dict) -> Dict:
        """
        Get intelligent exploitation plan for discovered vulnerabilities
        
        Args:
            findings: Discovered vulnerabilities
            context: Scan context
            
        Returns:
            Exploitation plan with chains and recommendations
        """
        self.initialize()
        
        plan = {
            'vulnerabilities': len(findings),
            'chains': [],
            'recommended_order': [],
            'tools_needed': [],
            'estimated_time': 0,
            'risk_assessment': {}
        }
        
        # Analyze chains
        if self.chain_engine:
            try:
                chain_analysis = self.chain_engine.analyze_findings(findings)
                plan['chains'] = chain_analysis.get('top_chains', [])
                
                # Get detailed plan for best chain
                if plan['chains']:
                    best_chain = plan['chains'][0]
                    detailed_plan = self.chain_engine.get_exploitation_plan(best_chain['id'])
                    if detailed_plan:
                        plan['detailed_plan'] = detailed_plan
            except Exception as e:
                logger.error(f"Chain planning failed: {e}")
        
        # Get delegation recommendations
        if self.delegation_system:
            try:
                # Create exploitation task
                from .delegation_system import AgentTask, TaskPriority
                
                task = AgentTask(
                    id=f"exploit_plan_{datetime.now().timestamp()}",
                    task_type="plan_exploitation",
                    description="Plan exploitation strategy",
                    priority=TaskPriority.HIGH,
                    payload={
                        'target': context.get('target', ''),
                        'vulnerabilities': findings[:10]  # Limit for processing
                    }
                )
                
                # This would be async in production
                # task_id = self.delegation_system.submit_task(task)
                
            except Exception as e:
                logger.error(f"Delegation failed: {e}")
        
        # Record for explainability
        if self.explainable_engine and plan['chains']:
            try:
                self.explainable_engine.record_attack_chain_selection(
                    plan['chains'][0],
                    plan['chains'][1:] if len(plan['chains']) > 1 else [],
                    [
                        {
                            'name': 'chain_severity',
                            'description': f"Chain has total severity {plan['chains'][0].get('total_severity', 0):.1f}",
                            'weight': 0.5,
                            'impact': 'positive',
                            'source': 'chain_analysis'
                        }
                    ]
                )
            except Exception as e:
                logger.error(f"Explainability recording failed: {e}")
        
        return plan
    
    def generate_report(self, scan_id: str, findings: List[Dict],
                       context: Dict, report_type: str = "technical") -> str:
        """
        Generate comprehensive report with AI explanations
        
        Args:
            scan_id: Scan identifier
            findings: All findings
            context: Scan context
            report_type: Type of report ('technical', 'executive', 'compliance')
            
        Returns:
            Generated report content
        """
        self.initialize()
        
        scan_results = {
            'scan_id': scan_id,
            'target': context.get('target', ''),
            'findings': findings,
            'context': context
        }
        
        # Generate explainable report
        if self.explainable_engine:
            try:
                return self.explainable_engine.generate_report(scan_results, report_type)
            except Exception as e:
                logger.error(f"Report generation failed: {e}")
        
        # Fallback to basic report
        return self._generate_basic_report(scan_results)
    
    def _generate_basic_report(self, scan_results: Dict) -> str:
        """Generate basic report without explainability engine"""
        lines = [
            f"# Penetration Test Report",
            "",
            f"**Target:** {scan_results.get('target', 'Unknown')}",
            f"**Scan ID:** {scan_results.get('scan_id', 'Unknown')}",
            "",
            "## Findings Summary",
            "",
            f"Total Findings: {len(scan_results.get('findings', []))}",
            ""
        ]
        
        for finding in scan_results.get('findings', [])[:20]:
            lines.append(f"- **{finding.get('title', 'Unknown')}** "
                        f"(Severity: {finding.get('severity', 'N/A')})")
        
        return "\n".join(lines)
    
    def get_intelligence_status(self) -> Dict[str, Any]:
        """Get status of all intelligence subsystems"""
        status = {
            'initialized': self._initialized,
            'components': {}
        }
        
        components = [
            ('memory_system', self.memory_system),
            ('web_intel', self.web_intel),
            ('delegation_system', self.delegation_system),
            ('adaptive_engine', self.adaptive_engine),
            ('chain_engine', self.chain_engine),
            ('explainable_engine', self.explainable_engine),
            ('learning_engine', self.learning_engine),
            ('zeroday_engine', self.zeroday_engine),
            ('campaign_engine', self.campaign_engine)
        ]
        
        for name, component in components:
            status['components'][name] = {
                'enabled': getattr(self.config, f'enable_{name.replace("_system", "").replace("_engine", "")}', False),
                'initialized': component is not None
            }
        
        # Get detailed stats from each component
        if self.learning_engine:
            try:
                status['learning_stats'] = self.learning_engine.get_learning_stats()
            except:
                pass
        
        if self.adaptive_engine:
            try:
                status['adaptation_stats'] = self.adaptive_engine.get_adaptation_statistics()
            except:
                pass
        
        if self.zeroday_engine:
            try:
                status['zeroday_stats'] = self.zeroday_engine.get_discovery_stats()
            except:
                pass
        
        if self.memory_system:
            try:
                status['memory_stats'] = self.memory_system.get_scan_statistics()
            except:
                pass
        
        return status
    
    def shutdown(self):
        """Shutdown all components gracefully"""
        logger.info("Shutting down Optimus Brain...")
        
        # Stop delegation agents
        if self.delegation_system:
            try:
                self.delegation_system.stop_all_agents()
            except:
                pass
        
        # Save learning state
        if self.learning_engine:
            try:
                # Export learnings would go here
                pass
            except:
                pass
        
        # Close web intel connections
        if self.web_intel:
            try:
                self.web_intel.close()
            except:
                pass
        
        # Consolidate memory
        if self.memory_system:
            try:
                self.memory_system.consolidate_memories()
            except:
                pass
        
        self._initialized = False
        logger.info("Optimus Brain shutdown complete")


# Singleton instance
_optimus_brain = None

def get_optimus_brain(config: OptimusConfig = None) -> OptimusBrain:
    """Get the singleton Optimus Brain instance"""
    global _optimus_brain
    if _optimus_brain is None:
        _optimus_brain = OptimusBrain(config)
    return _optimus_brain


# Create __init__.py for the intelligence package
INIT_CONTENT = '''"""
Intelligence Package for Optimus Penetration Testing Agent

This package contains advanced AI/ML capabilities:
- memory_system: Persistent cross-scan memory
- web_intelligence: Real-time web intel gathering  
- delegation_system: Multi-agent task delegation
- adaptive_exploitation: Real-time adaptation
- vulnerability_chaining: Attack graph analysis
- explainable_ai: Decision explanations
- continuous_learning: Production learning
- campaign_intelligence: Multi-target campaigns
- optimus_brain: Unified intelligence engine
"""

from .optimus_brain import get_optimus_brain, OptimusBrain, OptimusConfig
from .memory_system import get_memory_system, SmartMemorySystem
from .web_intelligence import get_web_intelligence, WebIntelligenceEngine
from .delegation_system import get_agent_coordinator, AgentCoordinator
from .adaptive_exploitation import get_adaptive_engine, RealTimeAdaptiveEngine
from .vulnerability_chaining import get_chain_engine, VulnerabilityChainEngine
from .explainable_ai import get_explainable_engine, ExplainableAIEngine
from .continuous_learning import get_learning_engine, get_zeroday_engine
from .campaign_intelligence import get_campaign_engine, CampaignIntelligenceEngine

__all__ = [
    'get_optimus_brain',
    'OptimusBrain', 
    'OptimusConfig',
    'get_memory_system',
    'SmartMemorySystem',
    'get_web_intelligence',
    'WebIntelligenceEngine',
    'get_agent_coordinator',
    'AgentCoordinator',
    'get_adaptive_engine',
    'RealTimeAdaptiveEngine',
    'get_chain_engine',
    'VulnerabilityChainEngine',
    'get_explainable_engine',
    'ExplainableAIEngine',
    'get_learning_engine',
    'get_zeroday_engine',
    'get_campaign_engine',
    'CampaignIntelligenceEngine'
]
'''
