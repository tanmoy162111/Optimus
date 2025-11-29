"""
Phase-Aware Tool Selector - Recommends tools based on context and ML/RL/Phase-Specific Models
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from typing import Dict, List, Any
from config import Config
import logging
from .rule_based_tool_selector import RuleBasedToolSelector

# Import phase-specific models
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'training'))
    from phase_specific_models import PhaseSpecificToolSelector as PSToolSelector
    PHASE_SPECIFIC_MODELS_AVAILABLE = True
except ImportError as e:
    PHASE_SPECIFIC_MODELS_AVAILABLE = False
    logger_import = logging.getLogger(__name__)
    logger_import.warning(f"Phase-specific models not available: {e}")

logger = logging.getLogger(__name__)

class PhaseAwareToolSelector:
    """Intelligent tool selection using ML/RL and phase-specific models"""
    
    def __init__(self):
        self.phase_configs = self._load_phase_configs()
        self.all_tools = self._get_all_tools()
        
        # Placeholders for ML/RL components (loaded separately)
        self.tool_recommender_ml = None
        self.rl_agent = None
        self.rl_state_encoder = None
        
        # Add rule-based fallback
        self.rule_selector = RuleBasedToolSelector()
        self.use_hybrid = True  # Enable hybrid mode
        self.ml_confidence_threshold = 0.5
        
        # Initialize phase-specific models (if available)
        self.phase_specific_selector = None
        self.use_phase_specific = True
        if PHASE_SPECIFIC_MODELS_AVAILABLE:
            try:
                self.phase_specific_selector = PSToolSelector()
                logger.info("✅ Phase-specific models loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load phase-specific models: {e}")
                self.use_phase_specific = False
        else:
            logger.info("Phase-specific models not available, using fallback methods")
        
        # Add tool execution history tracking
        self.tool_execution_history = {}  # Track tool effectiveness

    def recommend_tools(self, scan_state: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced recommendation with execution history and anti-repetition"""
        phase = scan_state.get('phase', 'reconnaissance')
        findings = scan_state.get('findings', [])
        tools_executed = [t['tool'] if isinstance(t, dict) else t 
                          for t in scan_state.get('tools_executed', [])]

        # Extract what we know about the target
        scan_state['target_type'] = scan_state.get('target_type', 'web')
        scan_state['recently_used_tools'] = tools_executed[-3:] if len(tools_executed) > 3 else tools_executed

        # NEW: Enhanced tool repetition prevention
        # Count how many times each tool has been executed
        tool_counts = {}
        for tool in tools_executed:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        # Identify tools that have been executed too many times
        problematic_tools = []
        for tool, count in tool_counts.items():
            # If a tool has been executed 3+ times, consider it problematic
            if count >= 3:
                problematic_tools.append(tool)
                print(f"[ToolSelector] Tool {tool} executed {count} times, marking as problematic")
        
        # Update blacklisted tools in scan state
        blacklisted = scan_state.get('blacklisted_tools', [])
        for tool in problematic_tools:
            if tool not in blacklisted:
                blacklisted.append(tool)
        scan_state['blacklisted_tools'] = blacklisted

        # NEW: Check if last tool was ineffective (no findings)
        if len(tools_executed) > 0:
            last_tool = tools_executed[-1]
            
            # Count how many times this tool was used recently
            recent_tools = tools_executed[-5:] if len(tools_executed) >= 5 else tools_executed
            tool_usage_count = recent_tools.count(last_tool)
            
            # If tool used 3+ times recently with no findings, blacklist it temporarily
            if tool_usage_count >= 3:
                # Check if there were findings from this tool
                last_tool_findings = 0
                for execution in reversed(scan_state.get('tools_executed', [])):
                    if isinstance(execution, dict) and execution.get('tool') == last_tool:
                        # We don't have detailed findings per execution, so we'll assume
                        # if no overall findings, this tool likely didn't find anything
                        if len(findings) == 0:
                            last_tool_findings = 0
                            break
                        else:
                            # If there are findings, we assume this tool contributed
                            last_tool_findings = 1
                            break
                
                if last_tool_findings == 0:
                    print(f"[ToolSelector] Blacklisting {last_tool} - used {tool_usage_count} times with no results")
                    if last_tool not in blacklisted:
                        blacklisted.append(last_tool)
                        scan_state['blacklisted_tools'] = blacklisted
        
        # Get blacklisted tools
        blacklisted = scan_state.get('blacklisted_tools', [])

        # Use phase-specific models first (Tier 1)
        if self.use_phase_specific and self.phase_specific_selector:
            try:
                # Prepare context for phase-specific models (convert unhashable types)
                context = self._prepare_context_for_model(scan_state)
                ps_result = self.phase_specific_selector.recommend_tools(context)
                
                if not ps_result.get('error') and ps_result.get('confidence', 0) >= 0.7:
                    logger.info(f"Using phase-specific model: {ps_result['tools'][:3]}")
                    
                    # Combine with rule-based enhancements
                    rule_tools = self.apply_phase_rules(scan_state, phase)
                    # Filter out blacklisted tools
                    rule_tools = [t for t in rule_tools if t not in blacklisted]
                    
                    final_tools = rule_tools + [t for t in ps_result['tools'] if t not in rule_tools and t not in blacklisted]
                    
                    # Ensure we don't recommend already executed tools
                    final_tools = [t for t in final_tools if t not in tools_executed]
                    
                    if not final_tools:
                        print(f"[ToolSelector] No effective tools left in {phase}, forcing transition")
                        return {
                            'tools': [],  # Empty list signals phase transition needed
                            'phase': phase,
                            'method': 'exhausted',
                            'ml_confidence': 0.0,
                            'reasoning': 'All tools exhausted, need phase transition'
                        }
                    
                    return {
                        'tools': final_tools[:5],
                        'phase': phase,
                        'method': 'phase_specific_ml',
                        'ml_confidence': ps_result.get('confidence', 0.0),
                        'reasoning': f"Phase-specific {phase} model with rule enhancements"
                    }
            except Exception as e:
                logger.warning(f"Phase-specific model failed: {e}")

        # Fall back to rule-based (Tier 3) - ALWAYS RELIABLE
        if self.use_hybrid:
            logger.info(f"Using rule-based selector for {phase}")
            rule_tools = self.rule_selector.recommend_tools(scan_state)
            reasoning = self.rule_selector.get_reasoning(scan_state, rule_tools)
            
            # Filter out blacklisted tools AND already executed tools
            filtered_tools = []
            for tool in rule_tools:
                if tool not in blacklisted and tool not in tools_executed:
                    filtered_tools.append(tool)
            
            # If no rule tools left, force phase transition
            if not filtered_tools:
                print(f"[ToolSelector] No effective tools left in {phase}, forcing transition")
                return {
                    'tools': [],  # Empty list signals phase transition needed
                    'phase': phase,
                    'method': 'exhausted',
                    'ml_confidence': 0.0,
                    'reasoning': 'All tools exhausted, need phase transition'
                }
            
            return {
                'tools': filtered_tools[:5],
                'phase': phase,
                'method': 'rule_based',
                'ml_confidence': 0.8,  # High confidence in rules
                'reasoning': f'Recommended tools excluding {len(blacklisted)} blacklisted and {len(tools_executed)} already executed tools'
            }

    def _prepare_context_for_model(self, scan_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare context for phase-specific models by converting unhashable types
        to hashable equivalents that can be processed by the feature extraction
        """
        # Create a clean copy of the scan state
        context = {}
        
        # Copy simple types directly
        for key, value in scan_state.items():
            if isinstance(value, (str, int, float, bool)):
                context[key] = value
            elif isinstance(value, (list, tuple)):
                # Convert lists/tuples to counts or simple representations
                if key == 'findings':
                    # Extract key information from findings
                    context['vulnerabilities_found'] = len(value)
                    if value:
                        # Get highest severity
                        severities = [f.get('severity', 0) for f in value if isinstance(f, dict)]
                        context['highest_severity'] = max(severities) if severities else 0
                        
                        # Get vulnerability types
                        vuln_types = [f.get('type', 'unknown') for f in value if isinstance(f, dict)]
                        # Convert to boolean flags for common vuln types
                        context['sql_injection_found'] = 'sql_injection' in vuln_types
                        context['xss_found'] = 'xss' in vuln_types
                        context['command_injection_found'] = 'command_injection' in vuln_types
                elif key == 'tools_executed':
                    # Convert to count and tool types
                    context['num_tools_executed'] = len(value)
                    # Get unique tools executed
                    unique_tools = list(set([t['tool'] if isinstance(t, dict) else t for t in value]))
                    context['tools_executed'] = unique_tools
                else:
                    # For other lists, just store the count
                    context[key] = len(value)
            elif isinstance(value, dict):
                # For dictionaries, extract key information
                if key == 'phase_data':
                    # Extract phase-specific data
                    for subkey, subvalue in value.items():
                        context[subkey] = subvalue
                else:
                    # For other dictionaries, convert to string representation or extract key info
                    context[key] = str(value)  # Simple conversion to avoid unhashable issues
            else:
                # For other types, convert to string
                context[key] = str(value)
        
        # Add missing default values that models expect
        expected_features = {
            'target_type': 'web',
            'time_in_phase': 0,
            'subdomains_discovered': 0,
            'emails_discovered': 0,
            'technologies_discovered': 0,
            'employees_discovered': 0,
            'passive_recon_complete': False,
            'active_recon_started': False,
            'stealth_required': False,
            'detection_risk': 0.0,
            'domain_complexity': 0.0,
            'open_ports_found': 0,
            'scan_coverage': 0.0,
            'services_enumerated': 0,
            'wordpress_detected': False,
            'joomla_detected': False,
            'has_ssl_tls': False,
            'has_database': False,
            'has_smb': False,
            'aggressive_mode': False,
            'access_gained': False,
            'exploit_attempts': 0,
            'num_critical_vulns': 0,
            'num_exploitable_vulns': 0,
            'waf_detected': False,
            'authentication_required': False,
            'target_hardening_level': 0.0,
            'current_user_privilege': 'user',
            'os_type': 'linux',
            'privilege_escalated': False,
            'persistence_established': False,
            'credentials_dumped': False,
            'lateral_movement_success': False,
            'domain_joined': False,
            'antivirus_detected': False,
            'edr_detected': False,
            'other_hosts_visible': 0,
            'detection_probability': 0.0,
            'log_entries_present': 0,
            'artifacts_present': 0,
            'backdoors_installed': 0,
            'forensic_evidence_score': 0.0,
            'logs_cleaned': False,
            'timestamps_modified': False,
            'artifacts_removed': False,
            'time_remaining': 0,
            'stealth_critical': False,
            'detection_imminent': False,
            'admin_access': False
        }
        
        # Fill in missing values with defaults
        for key, default_value in expected_features.items():
            if key not in context:
                context[key] = default_value
        
        return context

    def apply_phase_rules(self, state: Dict[str, Any], phase: str) -> List[str]:
        """Apply rule-based tool selection for phase - ENHANCED"""
        rule_tools = []
        tools_executed = [t['tool'] if isinstance(t, dict) else t 
                          for t in state.get('tools_executed', [])]
        
        # Map tool names to available tools on Kali VM
        tool_mapping = {
            'sublist3r': 'amass',  # Use amass instead of sublist3r
            'theHarvester': 'dnsenum',  # Use dnsenum as alternative
            'linpeas.sh': 'linpeas',  # Normalize name
        }
        
        if phase == 'reconnaissance':
            # Start with subdomain enumeration
            actual_tool = tool_mapping.get('sublist3r', 'sublist3r')
            if actual_tool not in tools_executed:
                rule_tools.append(actual_tool)
            
            # If sublist3r already ran, try other recon tools
            if actual_tool in tools_executed:
                if 'whatweb' not in tools_executed:
                    rule_tools.append('whatweb')
                actual_dns_tool = tool_mapping.get('theHarvester', 'theHarvester')
                if actual_dns_tool not in tools_executed:
                    rule_tools.append(actual_dns_tool)
                # Add fierce for DNS enumeration
                if 'fierce' not in tools_executed:
                    rule_tools.append('fierce')
                # Add enum4linux for SMB enumeration
                if 'enum4linux' not in tools_executed:
                    rule_tools.append('enum4linux')
            
            # If all recon tools tried, force nmap to start scanning
            all_recon_tools = [tool_mapping.get('sublist3r', 'sublist3r'), 'whatweb', tool_mapping.get('theHarvester', 'theHarvester'), 'fierce', 'enum4linux']
            if all(t in tools_executed for t in all_recon_tools):
                rule_tools.append('nmap')  # This will trigger phase transition
                
        elif phase == 'scanning':
            # Always start with nmap for port scanning
            if 'nmap' not in tools_executed:
                rule_tools.append('nmap')
            else:
                # After nmap, do web vulnerability scanning
                if 'nikto' not in tools_executed:
                    rule_tools.append('nikto')
                if 'nuclei' not in tools_executed:
                    rule_tools.append('nuclei')
                # Add directory brute forcing tools
                if 'gobuster' not in tools_executed:
                    rule_tools.append('gobuster')
                if 'ffuf' not in tools_executed:
                    rule_tools.append('ffuf')
                # Add SSL/TLS scanning
                if 'sslscan' not in tools_executed:
                    rule_tools.append('sslscan')
                # Add WordPress scanning if WordPress detected
                technologies = state.get('technologies_detected', [])
                if 'wordpress' in technologies and 'wpscan' not in tools_executed:
                    rule_tools.append('wpscan')
                    
        elif phase == 'exploitation':
            # Check what vulnerabilities were found
            findings = state.get('findings', [])
            vuln_types = [f.get('type') for f in findings]
            
            if 'sql_injection' in vuln_types and 'sqlmap' not in tools_executed:
                rule_tools.append('sqlmap')
            elif 'xss' in vuln_types and 'dalfox' not in tools_executed:
                rule_tools.append('dalfox')
            elif 'command_injection' in vuln_types and 'commix' not in tools_executed:
                rule_tools.append('commix')
            else:
                # No specific vulnerabilities, try generic exploitation
                if 'sqlmap' not in tools_executed:
                    rule_tools.append('sqlmap')
                # Add password brute forcing
                if 'hydra' not in tools_executed:
                    rule_tools.append('hydra')
                # Add metasploit for advanced exploitation
                if 'metasploit' not in tools_executed:
                    rule_tools.append('metasploit')
                    
        elif phase == 'post_exploitation':
            # Check for privilege escalation tools
            actual_linpeas = tool_mapping.get('linpeas.sh', 'linpeas.sh')
            if actual_linpeas not in tools_executed:
                rule_tools.append(actual_linpeas)
            # Add winpeas for Windows systems
            if 'winpeas' not in tools_executed:
                rule_tools.append('winpeas')
                
        return rule_tools
    
    def extract_phase_features(self, scan_state: Dict[str, Any]) -> List[float]:
        """Extract features for ML tool recommendation"""
        features = []
        
        # Phase encoding (one-hot)
        phases = ['reconnaissance', 'scanning', 'exploitation', 'post_exploitation', 'covering_tracks']
        for p in phases:
            features.append(1.0 if scan_state.get('phase') == p else 0.0)
        
        # State features
        features.append(len(scan_state.get('findings', [])) / 20.0)  # Normalize
        features.append(self._get_highest_severity(scan_state.get('findings', [])) / 10.0)
        features.append(scan_state.get('time_elapsed', 0) / 3600.0)
        features.append(scan_state.get('coverage', 0.0))
        features.append(scan_state.get('ml_confidence', 0.5))
        
        return features
    
    def merge_ml_rl(self, ml_tools: Dict[str, float], rl_tool: str) -> List[str]:
        """
        Merge ML probabilities with RL selection
        Returns: Ordered list of tools
        """
        # Sort ML tools by probability
        sorted_ml_tools = sorted(ml_tools.items(), key=lambda x: x[1], reverse=True)
        
        # Put RL selected tool first (if present)
        result = []
        if rl_tool and rl_tool in ml_tools:
            result.append(rl_tool)
        
        # Add other ML tools
        for tool, prob in sorted_ml_tools:
            if tool not in result:
                result.append(tool)
        
        return result
    
    def generate_reasoning(self, phase: str, ml_tools: Dict[str, float], 
                          rl_tool: str, rule_tools: List[str]) -> str:
        """Generate human-readable reasoning for tool selection"""
        parts = []
        
        if rule_tools:
            parts.append(f"Rule-based: {', '.join(rule_tools)}")
        
        if ml_tools:
            top_ml = sorted(ml_tools.items(), key=lambda x: x[1], reverse=True)[:2]
            ml_str = ', '.join([f"{t} ({p:.2f})" for t, p in top_ml])
            parts.append(f"ML recommendations: {ml_str}")
        
        if rl_tool:
            parts.append(f"RL selected: {rl_tool}")
        
        return "; ".join(parts) if parts else f"Default tools for {phase}"
    
    def _load_phase_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load phase-specific configurations"""
        return {
            'reconnaissance': {
                'allowed_tools': ['sublist3r', 'theHarvester', 'shodan', 'dnsenum', 
                                'fierce', 'whatweb', 'builtwith', 'amass', 'enum4linux',
                                'cewl', 'crunch', 'arjun', 'bloodhound-python'],
                'default_tools': ['amass', 'whatweb', 'fierce'],
                'ml_confidence_threshold': 0.6,
                'max_tools_per_iteration': 3
            },
            'scanning': {
                'allowed_tools': ['nmap', 'masscan', 'nuclei', 'nikto', 'nessus', 
                                'unicornscan', 'enum4linux', 'metasploit', 'gobuster', 
                                'ffuf', 'sslscan', 'wpscan', 'ike-scan', 'dirb'],
                'default_tools': ['nmap', 'nikto', 'gobuster'],
                'ml_confidence_threshold': 0.7,
                'max_tools_per_iteration': 4
            },
            'exploitation': {
                'allowed_tools': ['sqlmap', 'metasploit', 'dalfox', 'commix', 
                                'xsser', 'hydra', 'medusa', 'hydra', 'john', 'hashcat',
                                'nosqlmap', 'tplmap', 'jwt_tool', 'burpsuite', 'weevely'],
                'default_tools': ['sqlmap', 'hydra', 'metasploit'],
                'ml_confidence_threshold': 0.8,
                'max_tools_per_iteration': 2
            },
            'post_exploitation': {
                'allowed_tools': ['linpeas', 'winpeas', 'mimikatz', 'lazagne', 
                                'crackmapexec', 'psexec', 'linpeas.sh', 'bloodhound-python'],
                'default_tools': ['linpeas', 'winpeas'],
                'ml_confidence_threshold': 0.7,
                'max_tools_per_iteration': 3
            },
            'covering_tracks': {
                'allowed_tools': ['clear_logs', 'wevtutil', 'shred', 'timestomp'],
                'default_tools': ['clear_logs'],
                'ml_confidence_threshold': 0.6,
                'max_tools_per_iteration': 2
            }
        }
    
    def _get_all_tools(self) -> List[str]:
        """Get list of all available tools"""
        all_tools = set()
        for phase_config in self.phase_configs.values():
            all_tools.update(phase_config.get('allowed_tools', []))
        return list(all_tools)
    
    def _get_ml_recommendations(self, features: List[float], phase_config: Dict[str, Any]) -> Dict[str, float]:
        """Get ML tool recommendations (placeholder for actual ML model)"""
        # This would use the trained tool_recommender model
        # For now, return empty dict (will be populated when ML model is integrated)
        return {}
    
    def _get_highest_severity(self, findings: List[Dict[str, Any]]) -> float:
        """Get highest severity from findings"""
        if not findings:
            return 0.0
        return max(f.get('severity', 0.0) for f in findings)
    
    def set_ml_model(self, model):
        """Set ML tool recommender model"""
        self.tool_recommender_ml = model
    
    def set_rl_agent(self, agent, state_encoder):
        """Set RL agent and state encoder"""
        self.rl_agent = agent
        self.rl_state_encoder = state_encoder