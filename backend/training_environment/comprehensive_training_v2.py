#!/usr/bin/env python3
"""
Optimus Comprehensive Training Session v2

A robust training session that integrates ALL new components:
1. Intelligent Tool Selector (RL-based adaptive selection)
2. Evolving Parser (self-learning output parsing)
3. Evolving Commands (adaptive command generation)
4. Exploit Chainer (multi-step attack chains)
5. Web Intelligence (OSINT gathering)
6. Professional Reporting

Training Objectives:
- Discover and learn new tools dynamically
- Build and execute chain attacks
- Adapt parsers for unknown tool outputs
- Learn from web intelligence
- Train exploitation strategies
- Generate professional reports

Target VMs:
- OWASP Juice Shop (Web application vulnerabilities)
- Vulnerable VMs (System-level exploitation)

Usage:
    python comprehensive_training_v2.py --targets juice_shop,vm1,vm2 --episodes 10
    python comprehensive_training_v2.py --config training_config.json
"""

import os
import sys
import json
import time
import random
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('training_session.log')
    ]
)
logger = logging.getLogger('ComprehensiveTraining')


class TrainingPhase(Enum):
    """Training phases"""
    DISCOVERY = "discovery"          # Discover new tools and techniques
    CHAIN_ATTACK = "chain_attack"    # Learn attack chains
    PARSER_EVOLUTION = "parser_evolution"  # Train parsers
    COMMAND_EVOLUTION = "command_evolution"  # Evolve commands
    WEB_INTEL = "web_intel"          # Web intelligence gathering
    EXPLOITATION = "exploitation"    # Exploitation training
    REPORTING = "reporting"          # Report generation


@dataclass
class TrainingConfig:
    """Training session configuration"""
    targets: List[Dict[str, str]]
    episodes_per_target: int = 5
    max_time_per_episode: int = 1800  # 30 minutes
    enable_chain_attacks: bool = True
    enable_parser_evolution: bool = True
    enable_command_evolution: bool = True
    enable_web_intel: bool = True
    enable_new_tool_discovery: bool = True
    exploration_rate: float = 0.3  # 30% exploration
    output_dir: str = "training_output/comprehensive_v2"
    checkpoint_interval: int = 5  # Save every 5 episodes
    
    # Reward weights
    reward_finding: float = 10.0
    reward_chain_success: float = 50.0
    reward_new_tool: float = 20.0
    reward_parser_improvement: float = 15.0
    reward_shell: float = 100.0


@dataclass
class EpisodeResult:
    """Result of a training episode"""
    episode_id: str
    target: str
    start_time: str
    end_time: str
    duration_seconds: float
    
    # Metrics
    tools_executed: List[str] = field(default_factory=list)
    tools_discovered: List[str] = field(default_factory=list)
    findings_count: int = 0
    chains_attempted: int = 0
    chains_successful: int = 0
    parsers_evolved: int = 0
    commands_evolved: int = 0
    
    # Rewards
    total_reward: float = 0.0
    reward_breakdown: Dict[str, float] = field(default_factory=dict)
    
    # Learning
    rl_updates: int = 0
    exploration_actions: int = 0
    exploitation_actions: int = 0
    
    # Errors
    errors: List[str] = field(default_factory=list)


class ComponentManager:
    """Manages all training components"""
    
    def __init__(self):
        self.components = {}
        self.initialized = False
        
    def initialize(self) -> Dict[str, bool]:
        """Initialize all components"""
        status = {}
        
        # 1. Intelligent Tool Selector
        try:
            from inference.intelligent_selector import get_intelligent_selector
            self.components['intelligent_selector'] = get_intelligent_selector()
            status['intelligent_selector'] = True
            logger.info("✓ Intelligent Tool Selector initialized")
        except Exception as e:
            status['intelligent_selector'] = False
            logger.warning(f"X Intelligent Tool Selector failed: {e}")
        
        # 2. Evolving Parser
        try:
            from inference.evolving_parser import get_evolving_parser
            self.components['evolving_parser'] = get_evolving_parser()
            status['evolving_parser'] = True
            logger.info("✓ Evolving Parser initialized")
        except Exception as e:
            status['evolving_parser'] = False
            logger.warning(f"X Evolving Parser failed: {e}")
        
        # 3. Evolving Commands
        try:
            from inference.evolving_commands import get_evolving_command_generator
            self.components['evolving_commands'] = get_evolving_command_generator()
            status['evolving_commands'] = True
            logger.info("✓ Evolving Commands initialized")
        except Exception as e:
            status['evolving_commands'] = False
            logger.warning(f"X Evolving Commands failed: {e}")
        
        # 4. Exploit Chainer
        try:
            from exploitation.exploit_chainer import ExploitChainer
            from exploitation.exploit_executor import ExploitExecutor
            executor = ExploitExecutor()
            self.components['exploit_chainer'] = ExploitChainer(executor)
            status['exploit_chainer'] = True
            logger.info("✓ Exploit Chainer initialized")
        except Exception as e:
            status['exploit_chainer'] = False
            logger.warning(f"X Exploit Chainer failed: {e}")
        
        # 5. Web Intelligence
        try:
            from intelligence.web_intelligence import WebIntelligenceGatherer
            self.components['web_intel'] = WebIntelligenceGatherer()
            status['web_intel'] = True
            logger.info("✓ Web Intelligence initialized")
        except Exception as e:
            status['web_intel'] = False
            logger.warning(f"X Web Intelligence failed: {e}")
        
        # 6. Tool Manager
        try:
            from inference.tool_manager import ToolManager
            self.components['tool_manager'] = ToolManager()
            status['tool_manager'] = True
            logger.info("✓ Tool Manager initialized")
        except Exception as e:
            status['tool_manager'] = False
            logger.warning(f"X Tool Manager failed: {e}")
        
        # 7. Deep RL Agent
        try:
            from training.deep_rl_agent import DeepRLAgent
            from training.enhanced_state_encoder import EnhancedStateEncoder as StateEncoder
            self.components['rl_agent'] = DeepRLAgent(
                state_dim=128,
                num_actions=50,
                learning_rate=1e-4,
                gamma=0.99,
                tau=0.005,
                buffer_size=100000,
                batch_size=64,
                use_per=True,
                use_noisy=True,
                per_alpha=0.6,
                per_beta_start=0.4,
                model_dir=None
            )
            self.components['rl_agent'].load()
            self.components['state_encoder'] = StateEncoder()
            status['rl_agent'] = True
            logger.info("✓ Deep RL Agent initialized")
        except Exception as e:
            status['rl_agent'] = False
            logger.warning(f"X Deep RL Agent failed: {e}")
        
        # 8. Reward Calculator
        try:
            from training.reward_calculator import RewardCalculator
            self.components['reward_calculator'] = RewardCalculator()
            status['reward_calculator'] = True
            logger.info("✓ Reward Calculator initialized")
        except Exception as e:
            status['reward_calculator'] = False
            logger.warning(f"X Reward Calculator failed: {e}")
        
        # 9. Professional Report Generator
        try:
            from reporting.professional_report import get_professional_report_generator
            self.components['report_generator'] = get_professional_report_generator()
            status['report_generator'] = True
            logger.info("✓ Report Generator initialized")
        except Exception as e:
            status['report_generator'] = False
            logger.warning(f"X Report Generator failed: {e}")
        
        self.initialized = True
        return status
    
    def get(self, name: str) -> Optional[Any]:
        """Get component by name"""
        return self.components.get(name)


class ChainAttackTrainer:
    """Trains the agent on multi-step attack chains"""
    
    # Common attack chains to learn
    ATTACK_CHAINS = [
        {
            'name': 'SQLi to Shell',
            'steps': ['sqli_detection', 'sqli_exploitation', 'file_write', 'webshell_upload', 'shell_access'],
            'tools': ['sqlmap', 'curl', 'nc'],
        },
        {
            'name': 'XSS to Session Hijack',
            'steps': ['xss_detection', 'payload_craft', 'session_steal', 'account_takeover'],
            'tools': ['dalfox', 'curl', 'beef'],
        },
        {
            'name': 'LFI to RCE',
            'steps': ['lfi_detection', 'log_poison', 'code_execution'],
            'tools': ['curl', 'ffuf', 'nc'],
        },
        {
            'name': 'Auth Bypass to Privesc',
            'steps': ['auth_bypass', 'user_enum', 'privesc_enum', 'privilege_escalation'],
            'tools': ['hydra', 'curl', 'linpeas'],
        },
        {
            'name': 'SSRF to Cloud Metadata',
            'steps': ['ssrf_detection', 'internal_scan', 'metadata_access', 'credential_extract'],
            'tools': ['curl', 'ffuf', 'nuclei'],
        },
    ]
    
    def __init__(self, components: ComponentManager, config: TrainingConfig):
        self.components = components
        self.config = config
        self.chain_history = []
    
    def train_chain(self, target: str, chain: Dict, scan_state: Dict) -> Dict[str, Any]:
        """Train on a specific attack chain"""
        chain_result = {
            'chain_name': chain['name'],
            'steps_completed': 0,
            'total_steps': len(chain['steps']),
            'success': False,
            'findings': [],
            'reward': 0.0,
        }
        
        logger.info(f"[ChainTraining] Attempting chain: {chain['name']}")
        
        chainer = self.components.get('exploit_chainer')
        tool_manager = self.components.get('tool_manager')
        
        if not chainer or not tool_manager:
            logger.warning("[ChainTraining] Missing components")
            return chain_result
        
        # Execute chain steps
        chain_state = {
            'target': target,
            'credentials': [],
            'sessions': [],
            'data': {},
        }
        
        for i, step in enumerate(chain['steps']):
            logger.info(f"[ChainTraining] Step {i+1}/{len(chain['steps'])}: {step}")
            
            # Get tool for this step
            tool = chain['tools'][min(i, len(chain['tools'])-1)]
            
            # Execute step
            try:
                result = self._execute_chain_step(
                    step, tool, target, chain_state, scan_state
                )
                
                if result.get('success'):
                    chain_result['steps_completed'] += 1
                    chain_result['findings'].extend(result.get('findings', []))
                    
                    # Update chain state
                    if result.get('credentials'):
                        chain_state['credentials'].extend(result['credentials'])
                    if result.get('session'):
                        chain_state['sessions'].append(result['session'])
                    
                    # Check for shell/success
                    if 'shell' in step or result.get('shell_obtained'):
                        chain_result['success'] = True
                        chain_result['reward'] = self.config.reward_chain_success
                        logger.info(f"[ChainTraining] 🎉 Chain SUCCESS: {chain['name']}")
                        break
                else:
                    # Step failed - try adaptation
                    logger.info(f"[ChainTraining] Step failed, attempting adaptation")
                    
            except Exception as e:
                logger.error(f"[ChainTraining] Step error: {e}")
                break
        
        # Calculate partial reward
        if not chain_result['success']:
            progress = chain_result['steps_completed'] / chain_result['total_steps']
            chain_result['reward'] = progress * self.config.reward_chain_success * 0.5
        
        self.chain_history.append(chain_result)
        return chain_result
    
    def _execute_chain_step(
        self, 
        step: str, 
        tool: str, 
        target: str,
        chain_state: Dict,
        scan_state: Dict
    ) -> Dict[str, Any]:
        """Execute a single chain step"""
        tool_manager = self.components.get('tool_manager')
        evolving_commands = self.components.get('evolving_commands')
        
        # Build command - use evolving commands if available
        if evolving_commands:
            context = {
                'phase': 'exploitation',
                'step': step,
                'chain_state': chain_state,
            }
            command, source = evolving_commands.generate_command(tool, target, context)
        else:
            command = f"{tool} {target}"
        
        # Execute
        result = tool_manager.execute_tool(
            tool_name=tool,
            target=target,
            parameters={'args': command.replace(tool, '').strip()},
            scan_id=scan_state.get('scan_id', 'training'),
            phase='exploitation'
        )
        
        # Learn from execution
        if evolving_commands and result:
            evolving_commands.learn_from_execution(
                tool, command, target,
                result.get('exit_code', 1),
                result.get('stdout', ''),
                result.get('stderr', ''),
                len(result.get('findings', [])),
                result.get('execution_time', 0)
            )
        
        return result or {}


class ToolDiscoveryTrainer:
    """Discovers and learns new tools dynamically"""
    
    # Tools to potentially discover
    DISCOVERABLE_TOOLS = [
        {'name': 'feroxbuster', 'phase': 'enumeration', 'similar_to': 'gobuster'},
        {'name': 'httpx', 'phase': 'reconnaissance', 'similar_to': 'whatweb'},
        {'name': 'subfinder', 'phase': 'reconnaissance', 'similar_to': 'amass'},
        {'name': 'gau', 'phase': 'enumeration', 'similar_to': 'waybackurls'},
        {'name': 'katana', 'phase': 'enumeration', 'similar_to': 'gospider'},
        {'name': 'nuclei', 'phase': 'vulnerability_scan', 'similar_to': 'nikto'},
        {'name': 'jaeles', 'phase': 'vulnerability_scan', 'similar_to': 'nuclei'},
        {'name': 'crlfuzz', 'phase': 'vulnerability_scan', 'similar_to': 'curl'},
        {'name': 'arjun', 'phase': 'enumeration', 'similar_to': 'paramspider'},
        {'name': 'kiterunner', 'phase': 'enumeration', 'similar_to': 'ffuf'},
    ]
    
    def __init__(self, components: ComponentManager, config: TrainingConfig):
        self.components = components
        self.config = config
        self.discovered_tools = []
    
    def discover_and_learn(self, target: str, scan_state: Dict) -> List[Dict]:
        """Discover new tools and learn their patterns"""
        discoveries = []
        
        tool_manager = self.components.get('tool_manager')
        evolving_parser = self.components.get('evolving_parser')
        evolving_commands = self.components.get('evolving_commands')
        
        if not tool_manager:
            return discoveries
        
        for tool_info in self.DISCOVERABLE_TOOLS:
            tool_name = tool_info['name']
            
            # Skip if already discovered
            if tool_name in self.discovered_tools:
                continue
            
            # Check if tool exists on system
            if self._check_tool_exists(tool_name):
                logger.info(f"[ToolDiscovery] Found new tool: {tool_name}")
                
                # Try to execute and learn
                discovery = self._learn_tool(
                    tool_name, tool_info, target, scan_state
                )
                
                if discovery.get('success'):
                    self.discovered_tools.append(tool_name)
                    discoveries.append(discovery)
                    
                    # Cross-learn from similar tools
                    if evolving_parser and tool_info.get('similar_to'):
                        evolving_parser.cross_learn(
                            source_tool=tool_info['similar_to'],
                            target_tool=tool_name
                        )
        
        return discoveries
    
    def _check_tool_exists(self, tool_name: str) -> bool:
        """Check if tool exists via SSH"""
        tool_manager = self.components.get('tool_manager')
        if not tool_manager:
            return False
        
        try:
            # Try which command
            result = tool_manager.ssh_client.execute_command(f"which {tool_name}")
            return result.get('exit_code', 1) == 0
        except:
            return False
    
    def _learn_tool(
        self, 
        tool_name: str, 
        tool_info: Dict, 
        target: str,
        scan_state: Dict
    ) -> Dict:
        """Learn a new tool's behavior"""
        discovery = {
            'tool': tool_name,
            'success': False,
            'output_patterns': [],
            'command_templates': [],
        }
        
        tool_manager = self.components.get('tool_manager')
        evolving_parser = self.components.get('evolving_parser')
        evolving_commands = self.components.get('evolving_commands')
        
        # Try basic execution
        try:
            # First try --help to understand options
            help_result = tool_manager.ssh_client.execute_command(f"{tool_name} --help 2>&1 || {tool_name} -h 2>&1")
            
            if help_result.get('stdout'):
                # Parse help output to understand tool
                discovery['help_output'] = help_result['stdout'][:1000]
                
                # Generate command template from help
                if evolving_commands:
                    template = evolving_commands.generate_template_from_help(
                        tool_name, help_result['stdout']
                    )
                    if template:
                        discovery['command_templates'].append(template)
            
            # Try execution on target
            result = tool_manager.execute_tool(
                tool_name=tool_name,
                target=target,
                parameters={},
                scan_id=scan_state.get('scan_id', 'training'),
                phase=tool_info.get('phase', 'enumeration')
            )
            
            if result and result.get('stdout'):
                # Learn output patterns
                if evolving_parser:
                    patterns = evolving_parser.learn_from_output(
                        tool_name, result['stdout'], result.get('stderr', '')
                    )
                    discovery['output_patterns'] = patterns
                
                discovery['success'] = True
                discovery['sample_output'] = result['stdout'][:500]
                
                logger.info(f"[ToolDiscovery] ✓ Learned tool: {tool_name}")
                
        except Exception as e:
            logger.error(f"[ToolDiscovery] Failed to learn {tool_name}: {e}")
        
        return discovery


class WebIntelTrainer:
    """Trains the agent to use web intelligence for exploitation"""
    
    def __init__(self, components: ComponentManager, config: TrainingConfig):
        self.components = components
        self.config = config
    
    def gather_and_apply(self, target: str, findings: List[Dict], scan_state: Dict) -> Dict:
        """Gather web intelligence and apply to exploitation"""
        result = {
            'intel_gathered': [],
            'exploits_found': [],
            'techniques_learned': [],
            'reward': 0.0,
        }
        
        web_intel = self.components.get('web_intel')
        if not web_intel:
            return result
        
        # 1. Search for CVEs related to technologies
        technologies = scan_state.get('discovered_technologies', [])
        for tech in technologies[:5]:  # Limit queries
            try:
                cve_results = web_intel.search_cves(tech)
                if cve_results:
                    result['intel_gathered'].extend(cve_results)
                    logger.info(f"[WebIntel] Found {len(cve_results)} CVEs for {tech}")
            except Exception as e:
                logger.debug(f"[WebIntel] CVE search error: {e}")
        
        # 2. Search for exploits related to findings
        for finding in findings[:5]:
            vuln_type = finding.get('type', '')
            try:
                exploit_results = web_intel.search_exploits(vuln_type)
                if exploit_results:
                    result['exploits_found'].extend(exploit_results)
                    logger.info(f"[WebIntel] Found {len(exploit_results)} exploits for {vuln_type}")
            except Exception as e:
                logger.debug(f"[WebIntel] Exploit search error: {e}")
        
        # 3. Get techniques from MITRE ATT&CK
        try:
            techniques = web_intel.get_attack_techniques(findings)
            result['techniques_learned'] = techniques
        except Exception as e:
            logger.debug(f"[WebIntel] MITRE search error: {e}")
        
        # Calculate reward based on useful intel
        result['reward'] = (
            len(result['intel_gathered']) * 2.0 +
            len(result['exploits_found']) * 5.0 +
            len(result['techniques_learned']) * 3.0
        )
        
        return result


class ComprehensiveTrainer:
    """Main comprehensive training orchestrator"""
    
    def __init__(self, config: TrainingConfig):
        self.config = config
        self.components = ComponentManager()
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Training sub-modules
        self.chain_trainer = None
        self.tool_discovery = None
        self.web_intel_trainer = None
        
        # Metrics
        self.total_episodes = 0
        self.total_reward = 0.0
        self.episode_results = []
        
    def initialize(self) -> bool:
        """Initialize all components"""
        print("\n" + "="*70)
        print("OPTIMUS COMPREHENSIVE TRAINING v2")
        print("="*70 + "\n")
        
        print("Initializing components...")
        status = self.components.initialize()
        
        # Print status
        print("\nComponent Status:")
        for component, available in status.items():
            icon = "✓" if available else "✗"
            print(f"  {icon} {component}")
        
        # Initialize sub-trainers
        self.chain_trainer = ChainAttackTrainer(self.components, self.config)
        self.tool_discovery = ToolDiscoveryTrainer(self.components, self.config)
        self.web_intel_trainer = WebIntelTrainer(self.components, self.config)
        
        # Check minimum requirements
        if not status.get('tool_manager'):
            logger.error("Tool Manager is required!")
            return False
        
        return True
    
    def run_training(self) -> Dict[str, Any]:
        """Run the full training session"""
        training_start = datetime.now()
        
        print("\n" + "="*70)
        print("STARTING TRAINING SESSION")
        print(f"Targets: {len(self.config.targets)}")
        print(f"Episodes per target: {self.config.episodes_per_target}")
        print(f"Total episodes: {len(self.config.targets) * self.config.episodes_per_target}")
        print("="*70 + "\n")
        
        for target_config in self.config.targets:
            target = target_config.get('url') or target_config.get('ip')
            target_name = target_config.get('name', target)
            
            print(f"\n{'='*60}")
            print(f"TARGET: {target_name}")
            print(f"URL/IP: {target}")
            print(f"{'='*60}\n")
            
            for episode in range(self.config.episodes_per_target):
                print(f"\n[Episode {episode + 1}/{self.config.episodes_per_target}]")
                
                result = self._run_episode(target, target_name, episode)
                self.episode_results.append(result)
                self.total_episodes += 1
                self.total_reward += result.total_reward
                
                # Print episode summary
                self._print_episode_summary(result)
                
                # Checkpoint
                if self.total_episodes % self.config.checkpoint_interval == 0:
                    self._save_checkpoint()
        
        # Final summary
        training_end = datetime.now()
        training_duration = (training_end - training_start).total_seconds()
        
        summary = self._generate_summary(training_duration)
        self._save_final_results(summary)
        self._print_final_summary(summary)
        
        return summary
    
    def _run_episode(self, target: str, target_name: str, episode_num: int) -> EpisodeResult:
        """Run a single training episode"""
        episode_id = f"{target_name}_ep{episode_num}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        episode_start = datetime.now()
        
        result = EpisodeResult(
            episode_id=episode_id,
            target=target,
            start_time=episode_start.isoformat(),
            end_time="",
            duration_seconds=0
        )
        
        # Initialize scan state
        scan_state = self._init_scan_state(target, episode_id)
        
        # Reset components for new episode
        intelligent_selector = self.components.get('intelligent_selector')
        if intelligent_selector:
            intelligent_selector.reset_session()
        
        reward_calculator = self.components.get('reward_calculator')
        if reward_calculator:
            reward_calculator.reset_episode()
        
        try:
            # Phase 1: Discovery
            logger.info("[Phase 1] Tool Discovery")
            if self.config.enable_new_tool_discovery:
                discoveries = self.tool_discovery.discover_and_learn(target, scan_state)
                result.tools_discovered = [d['tool'] for d in discoveries if d.get('success')]
                result.reward_breakdown['discovery'] = len(result.tools_discovered) * self.config.reward_new_tool
            
            # Phase 2: Intelligent Reconnaissance & Scanning
            logger.info("[Phase 2] Intelligent Scanning")
            scan_result = self._run_intelligent_scan(target, scan_state, result)
            result.findings_count = len(scan_state.get('findings', []))
            result.reward_breakdown['findings'] = result.findings_count * self.config.reward_finding
            
            # Phase 3: Web Intelligence
            logger.info("[Phase 3] Web Intelligence")
            if self.config.enable_web_intel and result.findings_count > 0:
                intel_result = self.web_intel_trainer.gather_and_apply(
                    target, scan_state.get('findings', []), scan_state
                )
                result.reward_breakdown['web_intel'] = intel_result['reward']
            
            # Phase 4: Chain Attack Training
            logger.info("[Phase 4] Chain Attack Training")
            if self.config.enable_chain_attacks and result.findings_count > 0:
                chain_results = self._run_chain_training(target, scan_state, result)
                result.chains_attempted = len(chain_results)
                result.chains_successful = len([c for c in chain_results if c.get('success')])
                result.reward_breakdown['chains'] = sum(c.get('reward', 0) for c in chain_results)
            
            # Phase 5: Parser Evolution
            logger.info("[Phase 5] Parser Evolution")
            if self.config.enable_parser_evolution:
                result.parsers_evolved = self._evolve_parsers(scan_state)
                result.reward_breakdown['parsers'] = result.parsers_evolved * self.config.reward_parser_improvement
            
            # Phase 6: Command Evolution
            logger.info("[Phase 6] Command Evolution")
            if self.config.enable_command_evolution:
                result.commands_evolved = self._evolve_commands(scan_state)
            
            # Phase 7: RL Update
            logger.info("[Phase 7] RL Agent Update")
            result.rl_updates = self._update_rl_agent(scan_state, result)
            
        except Exception as e:
            logger.error(f"Episode error: {e}")
            result.errors.append(str(e))
        
        # Finalize
        episode_end = datetime.now()
        result.end_time = episode_end.isoformat()
        result.duration_seconds = (episode_end - episode_start).total_seconds()
        result.total_reward = sum(result.reward_breakdown.values())
        
        return result
    
    def _init_scan_state(self, target: str, scan_id: str) -> Dict:
        """Initialize scan state for episode"""
        return {
            'scan_id': scan_id,
            'target': target,
            'phase': 'reconnaissance',
            'findings': [],
            'tools_executed': [],
            'discovered_technologies': [],
            'discovered_endpoints': [],
            'open_ports': [],
            'credentials_found': [],
            'sessions_obtained': [],
            'exploits_attempted': [],
            'start_time': datetime.now().isoformat(),
        }
    
    def _run_intelligent_scan(self, target: str, scan_state: Dict, result: EpisodeResult) -> Dict:
        """Run intelligent scanning with adaptive tool selection"""
        intelligent_selector = self.components.get('intelligent_selector')
        tool_manager = self.components.get('tool_manager')
        evolving_parser = self.components.get('evolving_parser')
        evolving_commands = self.components.get('evolving_commands')
        
        if not tool_manager:
            return {}
        
        phases = ['reconnaissance', 'enumeration', 'vulnerability_scan']
        
        for phase in phases:
            scan_state['phase'] = phase
            logger.info(f"[Scanning] Phase: {phase}")
            
            tools_in_phase = 0
            max_tools_per_phase = 8
            
            while tools_in_phase < max_tools_per_phase:
                # Get tool recommendation
                if intelligent_selector:
                    recommendations = intelligent_selector.select_tools(
                        phase=phase,
                        scan_state=scan_state,
                        count=3
                    )
                    
                    if not recommendations:
                        break
                    
                    # Exploration vs Exploitation
                    if random.random() < self.config.exploration_rate:
                        # Explore: pick random from recommendations
                        rec = random.choice(recommendations)
                        result.exploration_actions += 1
                    else:
                        # Exploit: pick best
                        rec = recommendations[0]
                        result.exploitation_actions += 1
                    
                    tool_name = rec.tool
                    args = rec.args
                else:
                    # Fallback to default tools
                    break
                
                # Generate evolved command if available
                if evolving_commands:
                    command, source = evolving_commands.generate_command(
                        tool_name, target, {'phase': phase}
                    )
                    if command:
                        args = command.replace(tool_name, '').strip()
                
                # Execute tool
                logger.info(f"[Scanning] Executing: {tool_name}")
                exec_result = tool_manager.execute_tool(
                    tool_name=tool_name,
                    target=target,
                    parameters={'args': args},
                    scan_id=scan_state['scan_id'],
                    phase=phase
                )
                
                if exec_result:
                    result.tools_executed.append(tool_name)
                    tools_in_phase += 1
                    
                    # Parse with evolving parser
                    if evolving_parser and exec_result.get('stdout'):
                        parsed = evolving_parser.parse(
                            tool_name,
                            exec_result['stdout'],
                            exec_result.get('stderr', '')
                        )
                        
                        if parsed and parsed.get('findings'):
                            scan_state['findings'].extend(parsed['findings'])
                    
                    # Record execution for selector
                    if intelligent_selector:
                        intelligent_selector.record_execution(
                            tool=tool_name,
                            success=exec_result.get('success', False),
                            findings_count=len(exec_result.get('findings', [])),
                            execution_time=exec_result.get('execution_time', 0)
                        )
                    
                    # Learn command effectiveness
                    if evolving_commands:
                        evolving_commands.learn_from_execution(
                            tool_name, f"{tool_name} {args}", target,
                            exec_result.get('exit_code', 1),
                            exec_result.get('stdout', ''),
                            exec_result.get('stderr', ''),
                            len(exec_result.get('findings', [])),
                            exec_result.get('execution_time', 0)
                        )
                
                time.sleep(0.5)
        
        return scan_state
    
    def _run_chain_training(self, target: str, scan_state: Dict, result: EpisodeResult) -> List[Dict]:
        """Run chain attack training"""
        chain_results = []
        
        # Select relevant chains based on findings
        findings = scan_state.get('findings', [])
        finding_types = set(f.get('type', '').lower() for f in findings)
        
        for chain in ChainAttackTrainer.ATTACK_CHAINS:
            # Check if chain is relevant
            chain_name_lower = chain['name'].lower()
            relevant = any(
                ft in chain_name_lower or chain_name_lower in ft
                for ft in finding_types
            )
            
            if relevant or random.random() < 0.2:  # 20% chance to try anyway
                chain_result = self.chain_trainer.train_chain(target, chain, scan_state)
                chain_results.append(chain_result)
                
                # Stop if we got a shell
                if chain_result.get('success'):
                    break
        
        return chain_results
    
    def _evolve_parsers(self, scan_state: Dict) -> int:
        """Evolve parsers based on scan results"""
        evolving_parser = self.components.get('evolving_parser')
        if not evolving_parser:
            return 0
        
        evolved = 0
        
        for tool_exec in scan_state.get('tools_executed', []):
            tool_name = tool_exec if isinstance(tool_exec, str) else tool_exec.get('tool', '')
            
            # Trigger evolution analysis
            try:
                if evolving_parser.analyze_and_evolve(tool_name):
                    evolved += 1
            except Exception as e:
                logger.debug(f"Parser evolution error: {e}")
        
        return evolved
    
    def _evolve_commands(self, scan_state: Dict) -> int:
        """Evolve commands based on execution results"""
        evolving_commands = self.components.get('evolving_commands')
        if not evolving_commands:
            return 0
        
        evolved = 0
        
        # Analyze failed commands and create adaptations
        for tool_exec in scan_state.get('tools_executed', []):
            if isinstance(tool_exec, dict) and not tool_exec.get('success'):
                tool_name = tool_exec.get('tool', '')
                try:
                    if evolving_commands.adapt_from_failure(tool_name, tool_exec):
                        evolved += 1
                except Exception as e:
                    logger.debug(f"Command evolution error: {e}")
        
        return evolved
    
    def _update_rl_agent(self, scan_state: Dict, result: EpisodeResult) -> int:
        """Update RL agent with episode experience"""
        rl_agent = self.components.get('rl_agent')
        state_encoder = self.components.get('state_encoder')
        reward_calculator = self.components.get('reward_calculator')
        
        if not all([rl_agent, state_encoder, reward_calculator]):
            return 0
        
        updates = 0
        
        # Create experience from episode
        state = state_encoder.encode(scan_state)
        reward = result.total_reward
        
        # Store experience
        try:
            rl_agent.store_experience(
                state=state,
                action=0,  # Placeholder
                reward=reward,
                next_state=state,
                done=True
            )
            
            # Train on batch
            if rl_agent.memory_size() >= 32:
                loss = rl_agent.train_step(batch_size=32)
                updates = 1
                logger.info(f"[RL] Training step completed, loss: {loss:.4f}")
        except Exception as e:
            logger.debug(f"RL update error: {e}")
        
        return updates
    
    def _print_episode_summary(self, result: EpisodeResult):
        """Print episode summary"""
        print(f"\n  Episode Summary:")
        print(f"    Duration: {result.duration_seconds:.1f}s")
        print(f"    Tools: {len(result.tools_executed)} executed, {len(result.tools_discovered)} discovered")
        print(f"    Findings: {result.findings_count}")
        print(f"    Chains: {result.chains_successful}/{result.chains_attempted} successful")
        print(f"    Parsers evolved: {result.parsers_evolved}")
        print(f"    Total Reward: {result.total_reward:.2f}")
        if result.errors:
            print(f"    Errors: {len(result.errors)}")
    
    def _save_checkpoint(self):
        """Save training checkpoint"""
        checkpoint = {
            'timestamp': datetime.now().isoformat(),
            'total_episodes': self.total_episodes,
            'total_reward': self.total_reward,
            'recent_results': [asdict(r) for r in self.episode_results[-10:]],
        }
        
        checkpoint_path = self.output_dir / f"checkpoint_{self.total_episodes}.json"
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint, f, indent=2)
        
        logger.info(f"[Checkpoint] Saved to {checkpoint_path}")
        
        # Also save RL model
        rl_agent = self.components.get('rl_agent')
        if rl_agent:
            try:
                rl_agent.save()
                logger.info("[Checkpoint] RL model saved")
            except Exception as e:
                logger.debug(f"RL save error: {e}")
    
    def _generate_summary(self, duration: float) -> Dict[str, Any]:
        """Generate training summary"""
        return {
            'training_completed': datetime.now().isoformat(),
            'total_duration_seconds': duration,
            'total_episodes': self.total_episodes,
            'total_reward': self.total_reward,
            'average_reward': self.total_reward / max(self.total_episodes, 1),
            
            'metrics': {
                'total_tools_executed': sum(len(r.tools_executed) for r in self.episode_results),
                'unique_tools_discovered': len(set(
                    t for r in self.episode_results for t in r.tools_discovered
                )),
                'total_findings': sum(r.findings_count for r in self.episode_results),
                'chains_attempted': sum(r.chains_attempted for r in self.episode_results),
                'chains_successful': sum(r.chains_successful for r in self.episode_results),
                'parsers_evolved': sum(r.parsers_evolved for r in self.episode_results),
                'commands_evolved': sum(r.commands_evolved for r in self.episode_results),
                'rl_updates': sum(r.rl_updates for r in self.episode_results),
                'exploration_ratio': sum(r.exploration_actions for r in self.episode_results) / 
                                    max(sum(r.exploration_actions + r.exploitation_actions for r in self.episode_results), 1),
            },
            
            'episode_results': [asdict(r) for r in self.episode_results],
        }
    
    def _save_final_results(self, summary: Dict):
        """Save final training results"""
        # Save summary
        summary_path = self.output_dir / f"training_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"[Results] Saved to {summary_path}")
        
        # Save final RL model
        rl_agent = self.components.get('rl_agent')
        if rl_agent:
            try:
                rl_agent.save()
            except:
                pass
    
    def _print_final_summary(self, summary: Dict):
        """Print final training summary"""
        print("\n" + "="*70)
        print("TRAINING COMPLETE")
        print("="*70)
        print(f"\nDuration: {summary['total_duration_seconds']/60:.1f} minutes")
        print(f"Episodes: {summary['total_episodes']}")
        print(f"Total Reward: {summary['total_reward']:.2f}")
        print(f"Average Reward: {summary['average_reward']:.2f}")
        
        metrics = summary['metrics']
        print(f"\nMetrics:")
        print(f"  Tools executed: {metrics['total_tools_executed']}")
        print(f"  Tools discovered: {metrics['unique_tools_discovered']}")
        print(f"  Findings: {metrics['total_findings']}")
        print(f"  Chain attacks: {metrics['chains_successful']}/{metrics['chains_attempted']} successful")
        print(f"  Parsers evolved: {metrics['parsers_evolved']}")
        print(f"  Commands evolved: {metrics['commands_evolved']}")
        print(f"  RL updates: {metrics['rl_updates']}")
        print(f"  Exploration ratio: {metrics['exploration_ratio']:.2%}")
        print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(description='Optimus Comprehensive Training v2')
    parser.add_argument('--config', type=str, help='Path to config JSON file')
    parser.add_argument('--targets', type=str, help='Comma-separated targets (url or ip)')
    parser.add_argument('--episodes', type=int, default=5, help='Episodes per target')
    parser.add_argument('--max-time', type=int, default=1800, help='Max time per episode (seconds)')
    parser.add_argument('--output', type=str, default='training_output/comprehensive_v2', help='Output directory')
    parser.add_argument('--exploration', type=float, default=0.3, help='Exploration rate (0-1)')
    
    args = parser.parse_args()
    
    # Build config
    if args.config:
        with open(args.config) as f:
            config_dict = json.load(f)
    else:
        # Default targets
        if args.targets:
            targets = [{'url': t.strip(), 'name': f'target_{i}'} 
                      for i, t in enumerate(args.targets.split(','))]
        else:
            targets = [
                {'url': 'http://192.168.56.101:3000', 'name': 'OWASP_Juice_Shop'},
                {'url': '192.168.56.102', 'name': 'Vulnerable_VM_1'},
                {'url': '192.168.56.103', 'name': 'Vulnerable_VM_2'},
            ]
        
        config_dict = {
            'targets': targets,
            'episodes_per_target': args.episodes,
            'max_time_per_episode': args.max_time,
            'output_dir': args.output,
            'exploration_rate': args.exploration,
            'enable_chain_attacks': True,
            'enable_parser_evolution': True,
            'enable_command_evolution': True,
            'enable_web_intel': True,
            'enable_new_tool_discovery': True,
        }
    
    config = TrainingConfig(**config_dict)
    
    # Run training
    trainer = ComprehensiveTrainer(config)
    
    if not trainer.initialize():
        print("Failed to initialize trainer!")
        sys.exit(1)
    
    try:
        summary = trainer.run_training()
        print("\nTraining completed successfully!")
    except KeyboardInterrupt:
        print("\nTraining interrupted by user")
        trainer._save_checkpoint()
    except Exception as e:
        print(f"\nTraining failed: {e}")
        raise


if __name__ == '__main__':
    main()
