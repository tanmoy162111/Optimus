#!/usr/bin/env python3
"""
Simple OWASP VM Trainer - Runs all tools on OWASP VMs and learns from outputs
Focuses on tool execution, output collection, and pattern recognition
"""

import sys
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from inference.tool_manager import ToolManager
from training.production_data_collector import ProductionDataCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class SimpleOWASPTrainer:
    """Simple trainer that runs all tools and learns from their outputs"""
    
    def __init__(self, targets: List[str], output_dir: str = "data/simple_owasp_training"):
        self.targets = targets
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        # Create a dummy socketio object for training environment
        class DummySocketIO:
            def emit(self, event, data):
                pass
        
        self.tool_manager = ToolManager(DummySocketIO())
        self.data_collector = ProductionDataCollector(str(self.output_dir / "logs"))
        
        # Available tools
        self.tools = [
            'nmap', 'nikto', 'nuclei', 'sqlmap', 'gobuster', 'ffuf',
            'hydra', 'dalfox', 'commix', 'wpscan', 'sslscan', 'enum4linux',
            'whatweb', 'dnsenum', 'amass'
        ]
        
        logger.info(f"Simple OWASP Trainer initialized for targets: {targets}")
    
    def run_all_tools_on_target(self, target: str) -> Dict[str, Any]:
        """
        Run ALL available tools on a single target and collect outputs
        
        Args:
            target: Target URL/IP
            
        Returns:
            Dictionary with all tool results
        """
        logger.info(f"Running all tools on target: {target}")
        
        results = {
            'target': target,
            'scan_id': f"simple_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'start_time': datetime.now().isoformat(),
            'tool_results': {},
            'vulnerabilities_found': [],
            'patterns_identified': [],
            'end_time': None
        }
        
        # Run each tool
        for tool_name in self.tools:
            try:
                logger.info(f"Executing {tool_name} on {target}")
                
                # Execute tool with generous timeout
                tool_result = self.tool_manager.execute_tool(
                    tool_name=tool_name,
                    target=target,
                    parameters={
                        'timeout': 1800,  # 30 minutes per tool
                        'aggressive': True
                    },
                    scan_id=results['scan_id'],
                    phase='comprehensive_analysis'
                )
                
                results['tool_results'][tool_name] = tool_result
                
                # Extract vulnerabilities
                parsed_results = tool_result.get('parsed_results', {})
                vulnerabilities = parsed_results.get('vulnerabilities', [])
                
                # Add tool info to vulnerabilities
                for vuln in vulnerabilities:
                    vuln['tool'] = tool_name
                    vuln['target'] = target
                    results['vulnerabilities_found'].append(vuln)
                
                # Log execution for training data
                self.data_collector.log_tool_execution({
                    'scan_id': results['scan_id'],
                    'phase': 'comprehensive_analysis',
                    'tool': tool_name,
                    'target': target,
                    'context': {
                        'target_type': 'owasp_vm',
                        'aggressive_mode': True
                    },
                    'result': tool_result,
                    'success': tool_result.get('success', False),
                    'vulns_found': len(vulnerabilities),
                    'execution_time': tool_result.get('execution_time', 0)
                })
                
                logger.info(f"✓ {tool_name}: {len(vulnerabilities)} vulnerabilities found")
                
            except Exception as e:
                logger.error(f"✗ Error executing {tool_name}: {e}")
                results['tool_results'][tool_name] = {
                    'success': False,
                    'error': str(e),
                    'tool_name': tool_name,
                    'target': target
                }
                # Continue with the next tool instead of stopping the entire process
                continue
        
        # Identify patterns in the results
        results['patterns_identified'] = self._identify_patterns(results)
        results['end_time'] = datetime.now().isoformat()
        
        return results
    
    def _identify_patterns(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify patterns in tool outputs and vulnerabilities
        
        Args:
            results: Scan results dictionary
            
        Returns:
            List of identified patterns
        """
        patterns = []
        vulnerabilities = results.get('vulnerabilities_found', [])
        tool_results = results.get('tool_results', {})
        
        # Pattern 1: Tool effectiveness
        tool_effectiveness = {}
        for tool_name, tool_result in tool_results.items():
            vulns_found = len([v for v in vulnerabilities if v.get('tool') == tool_name])
            success = tool_result.get('success', False)
            execution_time = tool_result.get('execution_time', 0)
            
            tool_effectiveness[tool_name] = {
                'vulns_found': vulns_found,
                'success': success,
                'execution_time': execution_time,
                'effectiveness_score': vulns_found / max(execution_time, 1) if success else 0
            }
        
        patterns.append({
            'type': 'tool_effectiveness',
            'description': 'Effectiveness scores for each tool',
            'data': tool_effectiveness
        })
        
        # Pattern 2: Vulnerability clustering
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Find common vulnerability types
        common_types = {k: len(v) for k, v in vuln_types.items() if len(v) > 1}
        if common_types:
            patterns.append({
                'type': 'common_vulnerabilities',
                'description': 'Common vulnerability types found',
                'data': common_types
            })
        
        # Pattern 3: Severity distribution
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 0)
            severity_bucket = int(severity)  # Group by integer severity
            if severity_bucket not in severity_counts:
                severity_counts[severity_bucket] = 0
            severity_counts[severity_bucket] += 1
        
        if severity_counts:
            patterns.append({
                'type': 'severity_distribution',
                'description': 'Distribution of vulnerabilities by severity',
                'data': severity_counts
            })
        
        # Pattern 4: Tool combinations that find related vulnerabilities
        tool_combinations = {}
        for i, vuln1 in enumerate(vulnerabilities):
            for j, vuln2 in enumerate(vulnerabilities[i+1:], i+1):
                tool1 = vuln1.get('tool')
                tool2 = vuln2.get('tool')
                loc1 = vuln1.get('location', '')
                loc2 = vuln2.get('location', '')
                
                # If same location, tools found related issues
                if loc1 and loc2 and loc1 == loc2 and tool1 != tool2:
                    combo_key = tuple(sorted([tool1, tool2]))
                    if combo_key not in tool_combinations:
                        tool_combinations[combo_key] = 0
                    tool_combinations[combo_key] += 1
        
        if tool_combinations:
            patterns.append({
                'type': 'tool_synergy',
                'description': 'Tool combinations that find related vulnerabilities',
                'data': {f"{k[0]}+{k[1]}": v for k, v in tool_combinations.items()}
            })
        
        return patterns
    
    def run_training_session(self) -> Dict[str, Any]:
        """
        Run complete training session on all targets
        
        Returns:
            Complete training session results
        """
        session_results = {
            'session_id': f"simple_owasp_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'targets': self.targets,
            'start_time': datetime.now().isoformat(),
            'target_results': {},
            'overall_patterns': {},
            'end_time': None
        }
        
        logger.info("Starting simple OWASP training session")
        
        # Run all tools on each target
        for target in self.targets:
            try:
                target_result = self.run_all_tools_on_target(target)
                session_results['target_results'][target] = target_result
            except Exception as e:
                logger.error(f"Failed to scan target {target}: {e}")
                session_results['target_results'][target] = {
                    'error': str(e),
                    'target': target,
                    'scan_id': f"error_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    'tool_results': {},
                    'vulnerabilities_found': []
                }
        
        # Identify overall patterns across all targets
        session_results['overall_patterns'] = self._identify_overall_patterns(session_results)
        session_results['end_time'] = datetime.now().isoformat()
        
        # Save results
        self._save_results(session_results)
        
        # Flush data collector
        self.data_collector.flush_all()
        
        return session_results
    
    def _identify_overall_patterns(self, session_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identify patterns across all targets
        
        Args:
            session_results: Complete session results
            
        Returns:
            Overall patterns dictionary
        """
        overall_patterns = {}
        all_vulnerabilities = []
        
        # Collect all vulnerabilities
        for target_result in session_results['target_results'].values():
            all_vulnerabilities.extend(target_result.get('vulnerabilities_found', []))
        
        # Overall vulnerability types
        vuln_types = {}
        for vuln in all_vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        overall_patterns['vulnerability_types'] = vuln_types
        
        # Overall severity distribution
        severity_dist = {}
        for vuln in all_vulnerabilities:
            severity = int(vuln.get('severity', 0))
            if severity not in severity_dist:
                severity_dist[severity] = 0
            severity_dist[severity] += 1
        
        overall_patterns['severity_distribution'] = severity_dist
        
        return overall_patterns
    
    def _save_results(self, results: Dict[str, Any]):
        """Save training results to file"""
        results_file = self.output_dir / f"simple_training_results_{results['session_id']}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {results_file}")

def main():
    """Main function to run the simple OWASP trainer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Simple OWASP VM Trainer')
    parser.add_argument('--targets', nargs='+', required=True,
                       help='Target URLs/IPs of OWASP VMs')
    parser.add_argument('--output-dir', default='data/simple_owasp_training',
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    # Initialize trainer
    trainer = SimpleOWASPTrainer(args.targets, args.output_dir)
    
    # Run training session
    results = trainer.run_training_session()
    
    # Print summary
    print_summary(results)

def print_summary(results):
    """Print training session summary"""
    print("\n" + "="*60)
    print("SIMPLE OWASP VM TRAINING SUMMARY")
    print("="*60)
    
    print(f"Session ID: {results['session_id']}")
    print(f"Targets: {len(results['targets'])}")
    print(f"Start time: {results['start_time']}")
    print(f"End time: {results['end_time']}")
    
    total_vulns = 0
    total_tools = 0
    
    for target, target_result in results['target_results'].items():
        vulns = len(target_result.get('vulnerabilities_found', []))
        tools = len([t for t in target_result.get('tool_results', {}).values() if t.get('success', False)])
        total_vulns += vulns
        total_tools += tools
        
        print(f"\nTarget: {target}")
        print(f"  Vulnerabilities found: {vulns}")
        print(f"  Successful tools: {tools}/{len(target_result.get('tool_results', {}))}")
    
    print(f"\nOverall Statistics:")
    print(f"  Total vulnerabilities: {total_vulns}")
    print(f"  Total successful tool executions: {total_tools}")
    
    # Show vulnerability types
    vuln_types = results['overall_patterns'].get('vulnerability_types', {})
    if vuln_types:
        print(f"\nVulnerability Types Found:")
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {vuln_type}: {count}")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main()