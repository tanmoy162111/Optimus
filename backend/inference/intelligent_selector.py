"""
Intelligent Tool Selector for Optimus

This module provides dynamic, adaptive tool selection that:
1. Uses trained Deep RL agent when available
2. Adapts based on discovered findings
3. Considers target type and technology stack
4. Learns from execution results
5. Avoids redundant tool execution

Integrates with robust_orchestrator.py to replace hardcoded tool lists.
"""

import random
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ToolRecommendation:
    """Structured tool recommendation"""
    tool: str
    args: str
    priority: float  # 0-1, higher = more important
    reason: str
    source: str  # 'rl_agent', 'rule_based', 'finding_based', 'fallback'


class IntelligentToolSelector:
    """
    Intelligent tool selection using multiple strategies:
    1. Deep RL Agent (if trained model available)
    2. Finding-based selection (react to discoveries)
    3. Rule-based selection (phase + target type)
    4. Fallback to defaults
    """
    
    def __init__(self):
        self.rl_agent = None
        self.state_encoder = None
        self.execution_history = []
        self.tool_effectiveness = {}  # tool -> {success_rate, avg_findings}
        self.session_tools_executed = set()
        
        # Initialize RL agent if available
        self._init_rl_agent()
        
        # Tool database with metadata
        self.tool_db = self._init_tool_database()
        
        # Current phase and phase sequence
        self.current_phase = "reconnaissance"  # Changed from "training" to proper pentest phase
        self.phase_sequence = [
            "reconnaissance",
            "enumeration", 
            "vulnerability_analysis",
            "exploitation",
            "post_exploitation"
        ]
        
        # Initialize tool availability cache
        self.tool_availability = {}
        
        # Tool-to-phase mapping for validation
        self.tool_phases = {
            "nmap": ["reconnaissance", "enumeration"],
            "whatweb": ["reconnaissance", "enumeration"],
            "wafw00f": ["reconnaissance", "enumeration"],
            "gobuster": ["enumeration"],
            "ffuf": ["enumeration"],
            "nikto": ["enumeration", "vulnerability_analysis"],
            "nuclei": ["vulnerability_analysis", "enumeration"],
            "sqlmap": ["vulnerability_analysis", "exploitation"],
            "dalfox": ["vulnerability_analysis", "exploitation"],
            "commix": ["vulnerability_analysis", "exploitation"],
            "hydra": ["exploitation"],
            "metasploit": ["exploitation"],
            "linpeas": ["post_exploitation"],
            "curl": ["reconnaissance", "enumeration", "post_exploitation"],
        }
        
        # Phase-specific tool pools (not order - just available tools)
        self.phase_pools = self._init_phase_pools()
    
    def _init_rl_agent(self):
        """Initialize Deep RL agent if model exists"""
        try:
            from training.deep_rl_agent import DeepRLAgent
            from training.enhanced_state_encoder import EnhancedStateEncoder
            
            self.rl_agent = DeepRLAgent(
                state_dim=128,
                num_actions=50,
                hidden_dim=256,
                device='cpu'
            )
            
            # Try to load trained model
            self.rl_agent.load()
            self.state_encoder = EnhancedStateEncoder()
            
            logger.info("[IntelligentSelector] ✓ Deep RL Agent loaded successfully")
        except Exception as e:
            logger.warning(f"[IntelligentSelector] RL Agent not available: {e}")
            self.rl_agent = None
    
    def _init_tool_database(self) -> Dict[str, Dict]:
        """Initialize tool database with metadata"""
        return {
            # Reconnaissance tools
            'nmap': {
                'phases': ['reconnaissance', 'enumeration'],
                'target_types': ['all'],
                'finds': ['ports', 'services', 'os'],
                'weight': 0.9,
                'templates': {
                    'quick': '-sn {target}',
                    'standard': '-sV -sC -p- --min-rate=1000 {target}',
                    'stealth': '-sS -T2 {target}',
                    'udp': '-sU --top-ports 100 {target}',
                }
            },
            'whatweb': {
                'phases': ['reconnaissance'],
                'target_types': ['web'],
                'finds': ['technologies', 'cms'],
                'weight': 0.8,
                'templates': {'default': '{target}'}
            },
            'wafw00f': {
                'phases': ['reconnaissance'],
                'target_types': ['web'],
                'finds': ['waf'],
                'weight': 0.7,
                'templates': {'default': '{target}'}
            },
            
            # Enumeration tools
            'gobuster': {
                'phases': ['enumeration'],
                'target_types': ['web'],
                'finds': ['directories', 'files'],
                'weight': 0.85,
                'templates': {
                    'dir': 'dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 50',
                    'vhost': 'vhost -u {target} -w /usr/share/wordlists/subdomains.txt',
                }
            },
            'ffuf': {
                'phases': ['enumeration'],
                'target_types': ['web'],
                'finds': ['directories', 'parameters'],
                'weight': 0.85,
                'templates': {
                    'dir': '-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403',
                    'param': '-u {target}?FUZZ=test -w /usr/share/wordlists/params.txt',
                }
            },
            'nikto': {
                'phases': ['enumeration', 'vulnerability_analysis'],
                'target_types': ['web'],
                'finds': ['vulnerabilities', 'misconfigurations'],
                'weight': 0.8,
                'templates': {'default': '-h {target} -Tuning 123bde'}
            },
            'wpscan': {
                'phases': ['enumeration'],
                'target_types': ['wordpress'],
                'finds': ['plugins', 'themes', 'users', 'vulnerabilities'],
                'weight': 0.9,
                'templates': {'default': '--url {target} --enumerate ap,at,u'}
            },
            'dirsearch': {
                'phases': ['enumeration'],
                'target_types': ['web'],
                'finds': ['directories', 'files'],
                'weight': 0.75,
                'templates': {'default': '-u {target} -e php,asp,aspx,jsp,html,js'}
            },
            
            # Vulnerability scanning tools
            'nuclei': {
                'phases': ['vulnerability_analysis'],
                'target_types': ['web', 'api'],
                'finds': ['cves', 'vulnerabilities', 'exposures'],
                'weight': 0.95,
                'templates': {
                    'cve': '-u {target} -t cves/ -severity critical,high,medium',
                    'vuln': '-u {target} -t vulnerabilities/',
                    'exposure': '-u {target} -t exposures/',
                    'tech': '-u {target} -t technologies/',
                }
            },
            'sqlmap': {
                'phases': ['vulnerability_scan', 'exploitation'],
                'target_types': ['web', 'api'],
                'finds': ['sqli'],
                'triggers': ['sql', 'database', 'query', 'injection'],
                'weight': 0.9,
                'templates': {
                    'crawl': '-u {target} --batch --crawl=2 --level=2 --risk=2',
                    'forms': '-u {target} --batch --forms --level=3',
                    'exploit': '-u {target} --batch --dbs --dump',
                }
            },
            'dalfox': {
                'phases': ['vulnerability_scan', 'exploitation'],
                'target_types': ['web'],
                'finds': ['xss'],
                'triggers': ['xss', 'reflect', 'script', 'cross-site'],
                'weight': 0.85,
                'templates': {'default': "url '{target}' --skip-bav"}
            },
            'commix': {
                'phases': ['vulnerability_scan', 'exploitation'],
                'target_types': ['web', 'api'],
                'finds': ['command_injection', 'rce'],
                'triggers': ['command', 'rce', 'exec', 'shell'],
                'weight': 0.85,
                'templates': {'default': "--url='{target}' --batch --all"}
            },
            'xsstrike': {
                'phases': ['vulnerability_scan'],
                'target_types': ['web'],
                'finds': ['xss'],
                'weight': 0.8,
                'templates': {'default': '-u {target} --crawl'}
            },
            'sslscan': {
                'phases': ['vulnerability_scan'],
                'target_types': ['web', 'api'],
                'finds': ['ssl_issues'],
                'weight': 0.7,
                'templates': {'default': '{target}'}
            },
            
            # Exploitation tools
            'metasploit': {
                'phases': ['exploitation'],
                'target_types': ['all'],
                'finds': ['shells', 'sessions'],
                'weight': 0.9,
                'templates': {}  # Handled specially
            },
            'hydra': {
                'phases': ['exploitation'],
                'target_types': ['all'],
                'finds': ['credentials'],
                'triggers': ['login', 'auth', 'ssh', 'ftp'],
                'weight': 0.8,
                'templates': {
                    'ssh': '-l admin -P /usr/share/wordlists/rockyou.txt {target} ssh',
                    'http': '-l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form',
                }
            },
            
            # Post-exploitation
            'linpeas': {
                'phases': ['post_exploitation'],
                'target_types': ['linux'],
                'finds': ['privesc', 'credentials'],
                'weight': 0.9,
                'templates': {'default': '-a 2>/dev/null'}
            },
            'curl': {
                'phases': ['reconnaissance', 'enumeration', 'post_exploitation'],
                'target_types': ['web', 'api'],
                'finds': ['files', 'endpoints'],
                'weight': 0.6,
                'templates': {
                    'headers': '-I {target}',
                    'robots': '-s {target}/robots.txt',
                    'git': '-s {target}/.git/config',
                    'env': '-s {target}/.env',
                }
            },
        }
    
    def _init_phase_pools(self) -> Dict[str, List[str]]:
        """Initialize tool pools per phase (unordered)"""
        pools = {
            'reconnaissance': [],
            'enumeration': [],
            'vulnerability_analysis': [],
            'exploitation': [],
            'post_exploitation': [],
        }
        
        for tool, meta in self.tool_db.items():
            for phase in meta.get('phases', []):
                if phase in pools:
                    pools[phase].append(tool)
        
        return pools
    
    def select_tools(
        self,
        phase: str,
        scan_state: Dict[str, Any],
        count: int = 5
    ) -> List[ToolRecommendation]:
        """
        Select best tools for current phase and context.
        
        Uses multiple strategies in priority order:
        1. RL Agent selection (if available and confident)
        2. Finding-triggered tools (reactive)
        3. Rule-based selection (target type + phase)
        4. Fallback defaults
        """
        recommendations = []
        target = scan_state.get('target', '')
        target_type = scan_state.get('target_type', 'web')
        findings = scan_state.get('findings', [])
        technologies = scan_state.get('discovered_technologies', [])
        
        # Track which tools already executed
        executed = set()
        for t in scan_state.get('tools_executed', []):
            if isinstance(t, dict):
                executed.add(t.get('tool', ''))
            else:
                executed.add(str(t))
        
        # Also track session-level execution
        executed.update(self.session_tools_executed)
        
        logger.info(f"[IntelligentSelector] Selecting tools for {phase}, "
                   f"executed: {len(executed)}, findings: {len(findings)}")
        
        # Strategy 1: RL Agent
        if self.rl_agent and self.state_encoder:
            rl_tools = self._get_rl_recommendations(scan_state, phase, count)
            recommendations.extend(rl_tools)
        
        # Strategy 2: Finding-triggered tools
        finding_tools = self._get_finding_triggered_tools(findings, phase, executed)
        recommendations.extend(finding_tools)
        
        # Strategy 3: Technology-triggered tools
        tech_tools = self._get_tech_triggered_tools(technologies, phase, executed)
        recommendations.extend(tech_tools)
        
        # Strategy 4: Rule-based for phase
        rule_tools = self._get_rule_based_tools(phase, target_type, executed)
        recommendations.extend(rule_tools)
        
        # Filter out unavailable tools
        available_recommendations = []
        for rec in recommendations:
            if self.is_tool_available(rec.tool):
                available_recommendations.append(rec)
        recommendations = available_recommendations
        
        # Deduplicate and sort by priority
        seen = set()
        unique_recs = []
        for rec in recommendations:
            if rec.tool not in seen and rec.tool not in executed:
                seen.add(rec.tool)
                unique_recs.append(rec)
        
        # Sort by priority (descending)
        unique_recs.sort(key=lambda x: x.priority, reverse=True)
        
        # Add randomization factor (10% shuffle) for exploration
        if len(unique_recs) > 3:
            # Shuffle middle portion slightly
            middle = unique_recs[1:-1]
            if len(middle) > 2 and random.random() < 0.1:
                random.shuffle(middle)
                unique_recs = [unique_recs[0]] + middle + [unique_recs[-1]]
        
        selected = unique_recs[:count]
        
        logger.info(f"[IntelligentSelector] Selected {len(selected)} tools: "
                   f"{[r.tool for r in selected]}")
        
        return selected
    
    def _get_rl_recommendations(
        self,
        scan_state: Dict,
        phase: str,
        count: int
    ) -> List[ToolRecommendation]:
        """Get tool recommendations from RL agent"""
        recommendations = []
        
        try:
            # Encode state
            state_vector = self.state_encoder.encode(scan_state)
            
            # Get action from RL agent
            action, q_values = self.rl_agent.select_action(
                state_vector,
                epsilon=0.1  # Small exploration
            )
            
            # Map action to tool
            tool_list = list(self.tool_db.keys())
            if action < len(tool_list):
                tool = tool_list[action]
                
                # Check if tool is appropriate for phase
                tool_meta = self.tool_db.get(tool, {})
                if phase in tool_meta.get('phases', []):
                    # Get best template for tool
                    templates = tool_meta.get('templates', {})
                    args = templates.get('default', '{target}')
                    
                    recommendations.append(ToolRecommendation(
                        tool=tool,
                        args=args,
                        priority=0.9,  # High priority for RL
                        reason=f"RL agent selection (Q={q_values[action]:.2f})",
                        source='rl_agent'
                    ))
                    
                    logger.info(f"[IntelligentSelector] RL selected: {tool}")
            
            # Get top-k from Q-values
            top_actions = sorted(range(len(q_values)), 
                               key=lambda i: q_values[i], 
                               reverse=True)[:count]
            
            for action_idx in top_actions[1:]:  # Skip first (already added)
                if action_idx < len(tool_list):
                    tool = tool_list[action_idx]
                    tool_meta = self.tool_db.get(tool, {})
                    
                    if phase in tool_meta.get('phases', []):
                        templates = tool_meta.get('templates', {})
                        args = templates.get('default', '{target}')
                        
                        recommendations.append(ToolRecommendation(
                            tool=tool,
                            args=args,
                            priority=0.7 + (q_values[action_idx] * 0.1),
                            reason=f"RL alternative (Q={q_values[action_idx]:.2f})",
                            source='rl_agent'
                        ))
                        
        except Exception as e:
            logger.debug(f"[IntelligentSelector] RL selection failed: {e}")
        
        return recommendations
    
    def _get_finding_triggered_tools(
        self,
        findings: List[Dict],
        phase: str,
        executed: set
    ) -> List[ToolRecommendation]:
        """Select tools based on discovered findings"""
        recommendations = []
        
        for finding in findings:
            vuln_type = str(finding.get('type', '')).lower()
            vuln_name = str(finding.get('name', '')).lower()
            combined = f"{vuln_type} {vuln_name}"
            
            # Check each tool's triggers
            for tool, meta in self.tool_db.items():
                if tool in executed:
                    continue
                
                triggers = meta.get('triggers', [])
                for trigger in triggers:
                    if trigger in combined:
                        templates = meta.get('templates', {})
                        
                        # Select appropriate template
                        if 'exploit' in templates:
                            args = templates['exploit']
                        else:
                            args = templates.get('default', '{target}')
                        
                        recommendations.append(ToolRecommendation(
                            tool=tool,
                            args=args,
                            priority=0.95,  # Very high for finding-triggered
                            reason=f"Triggered by finding: {vuln_type}",
                            source='finding_based'
                        ))
                        break
        
        return recommendations
    
    def _get_tech_triggered_tools(
        self,
        technologies: List[str],
        phase: str,
        executed: set
    ) -> List[ToolRecommendation]:
        """Select tools based on discovered technologies"""
        recommendations = []
        
        tech_lower = [t.lower() if isinstance(t, str) else '' for t in technologies]
        
        # WordPress detection
        if any('wordpress' in t for t in tech_lower):
            if 'wpscan' not in executed:
                recommendations.append(ToolRecommendation(
                    tool='wpscan',
                    args='--url {target} --enumerate ap,at,u',
                    priority=0.95,
                    reason='WordPress detected',
                    source='tech_triggered'
                ))
        
        # Drupal detection
        if any('drupal' in t for t in tech_lower):
            if 'droopescan' not in executed:
                recommendations.append(ToolRecommendation(
                    tool='droopescan',
                    args='scan drupal -u {target}',
                    priority=0.95,
                    reason='Drupal detected',
                    source='tech_triggered'
                ))
        
        # Joomla detection
        if any('joomla' in t for t in tech_lower):
            if 'joomscan' not in executed:
                recommendations.append(ToolRecommendation(
                    tool='joomscan',
                    args='-u {target}',
                    priority=0.95,
                    reason='Joomla detected',
                    source='tech_triggered'
                ))
        
        # PHP detection - focus on PHP-specific vulns
        if any('php' in t for t in tech_lower):
            if 'nuclei' not in executed:
                recommendations.append(ToolRecommendation(
                    tool='nuclei',
                    args='-u {target} -t vulnerabilities/php/',
                    priority=0.85,
                    reason='PHP detected',
                    source='tech_triggered'
                ))
        
        return recommendations
    
    def _get_rule_based_tools(
        self,
        phase: str,
        target_type: str,
        executed: set
    ) -> List[ToolRecommendation]:
        """Get rule-based tool recommendations for phase"""
        recommendations = []
        
        # Get tools for this phase
        phase_tools = self.phase_pools.get(phase, [])
        
        for tool in phase_tools:
            if tool in executed:
                continue
            
            meta = self.tool_db.get(tool, {})
            
            # Check target type compatibility
            tool_targets = meta.get('target_types', ['all'])
            if 'all' not in tool_targets and target_type not in tool_targets:
                continue
            
            # Get template
            templates = meta.get('templates', {})
            args = templates.get('default', '{target}')
            
            # Use phase-specific template if available
            if phase == 'vulnerability_scan' and 'vuln' in templates:
                args = templates['vuln']
            elif phase == 'exploitation' and 'exploit' in templates:
                args = templates['exploit']
            
            # Calculate priority based on weight and effectiveness
            base_weight = meta.get('weight', 0.5)
            effectiveness = self.tool_effectiveness.get(tool, {})
            success_boost = effectiveness.get('success_rate', 0) * 0.2
            
            priority = min(base_weight + success_boost, 0.85)
            
            recommendations.append(ToolRecommendation(
                tool=tool,
                args=args,
                priority=priority,
                reason=f"Rule-based for {phase}",
                source='rule_based'
            ))
        
        return recommendations
    
    def record_execution(
        self,
        tool: str,
        success: bool,
        findings_count: int,
        execution_time: float
    ):
        """Record tool execution results for learning"""
        self.session_tools_executed.add(tool)
        
        # Update effectiveness tracking
        if tool not in self.tool_effectiveness:
            self.tool_effectiveness[tool] = {
                'executions': 0,
                'successes': 0,
                'total_findings': 0,
                'avg_time': 0,
            }
        
        stats = self.tool_effectiveness[tool]
        stats['executions'] += 1
        if success:
            stats['successes'] += 1
        stats['total_findings'] += findings_count
        stats['avg_time'] = (stats['avg_time'] * (stats['executions'] - 1) + 
                           execution_time) / stats['executions']
        stats['success_rate'] = stats['successes'] / stats['executions']
        
        # Record in history
        self.execution_history.append({
            'tool': tool,
            'success': success,
            'findings': findings_count,
            'time': execution_time,
            'timestamp': datetime.now().isoformat()
        })
        
        logger.debug(f"[IntelligentSelector] Recorded: {tool} "
                    f"success={success} findings={findings_count}")
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if tool is available in the system"""
        if tool_name in self.tool_availability:
            return self.tool_availability[tool_name]
        
        # Check if tool exists by attempting to find it in system
        from .tool_availability import is_tool_available
        # Get SSH client from scan_state if available
        ssh_client = getattr(self, 'ssh_client', None)  # Try to get SSH client from selector instance
        if not ssh_client and hasattr(self, 'tool_manager'):
            ssh_client = getattr(self.tool_manager, 'ssh_client', None)
        available = is_tool_available(tool_name, ssh_client=ssh_client)
        self.tool_availability[tool_name] = available
        
        if not available:
            logger.warning(f"[IntelligentSelector] Tool '{tool_name}' is not available in system")
        
        return available
    
    def is_tool_valid_for_phase(self, tool_name: str, phase: str) -> bool:
        """Check if tool is appropriate for current phase"""
        valid_phases = self.tool_phases.get(tool_name, [])
        return phase in valid_phases
    
    def reset_session(self):
        """Reset session-specific tracking"""
        self.session_tools_executed.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get selector statistics"""
        return {
            'rl_available': self.rl_agent is not None,
            'tools_in_db': len(self.tool_db),
            'session_executed': len(self.session_tools_executed),
            'total_executions': len(self.execution_history),
            'effectiveness': dict(self.tool_effectiveness),
        }


# Singleton instance
_selector: Optional[IntelligentToolSelector] = None


def get_intelligent_selector() -> IntelligentToolSelector:
    """Get or create intelligent selector singleton"""
    global _selector
    if _selector is None:
        _selector = IntelligentToolSelector()
    return _selector
