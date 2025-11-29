"""
Comprehensive Training Session - Runs all available tools on targets
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from training.production_data_collector import get_collector
from inference.autonomous_agent import AutonomousPentestAgent
from inference.dynamic_tool_database import DynamicToolDatabase
import json

def comprehensive_training_session():
    """Comprehensive training session with all tools"""
    
    # Enable production logging
    collector = get_collector()
    
    # Load targets with absolute path
    targets_file = os.path.join(os.path.dirname(__file__), 'data', 'training_targets.json')
    with open(targets_file) as f:
        targets = json.load(f)['targets']
    
    agent = AutonomousPentestAgent()
    
    # Get all available tools
    tool_db = DynamicToolDatabase()
    all_tools = list(tool_db.tools.keys())
    print(f"Available tools: {len(all_tools)}")
    print(f"Tools: {', '.join(sorted(all_tools))}")
    
    for target in targets[:2]:  # Start with first 2 targets
        print(f"\n{'='*80}")
        print(f"Comprehensive Training Session: {target['name']}")
        print(f"Target: {target['url']}")
        print(f"{'='*80}\n")
        
        config = {
            'max_time': 7200,  # 2 hours per target
            'depth': 'deep',
            'stealth': False,
            'aggressive': True,  # Use all available tools
            'target_type': target['type'],
            'learning_mode': True  # Enable enhanced learning
            # No stop_at_phase - go through all phases
        }
        
        try:
            result = agent.run_autonomous_scan(target['url'], config)
            
            # Analyze results
            print(f"\n{'='*80}")
            print(f"Results: {target['name']}")
            print(f"{'='*80}")
            print(f"Tools executed: {len(result.get('tools_executed', []))}")
            print(f"Findings: {len(result.get('findings', []))}")
            print(f"Coverage: {result.get('coverage', 0):.1%}")
            print(f"Phase reached: {result.get('phase', 'unknown')}")
            print(f"Strategy changes: {result.get('strategy_changes', 0)}")
            
            # Show tools executed
            tools_executed = [t['tool'] if isinstance(t, dict) else t 
                             for t in result.get('tools_executed', [])]
            unique_tools = list(set(tools_executed))
            print(f"Unique tools used: {len(unique_tools)}")
            print(f"Tools: {', '.join(sorted(unique_tools))}")
            
            # Show unused tools
            unused_tools = [tool for tool in all_tools if tool not in unique_tools]
            print(f"Unused tools: {len(unused_tools)}")
            if unused_tools:
                print(f"Unused: {', '.join(sorted(unused_tools))}")
            
            # Show findings summary
            findings = result.get('findings', [])
            if findings:
                vuln_types = list(set(f.get('type', 'unknown') for f in findings))
                print(f"Vulnerability types found: {', '.join(vuln_types)}")
                
                # Show high severity findings
                high_sev_findings = [f for f in findings if f.get('severity', 0) >= 7.0]
                if high_sev_findings:
                    print(f"High severity findings: {len(high_sev_findings)}")
            
            # Save detailed log
            filename = os.path.join(os.path.dirname(__file__), 'data', f"comprehensive_session_{target['name'].replace(' ', '_')}.json")
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
                
            print(f"\n✅ Results saved to {filename}")
                
        except Exception as e:
            print(f"❌ Error scanning {target['name']}: {e}")
            import traceback
            traceback.print_exc()
            # Save error result
            error_result = {
                'error': str(e),
                'target': target['url'],
                'tools_executed': [],
                'findings': [],
                'coverage': 0
            }
            filename = os.path.join(os.path.dirname(__file__), 'data', f"comprehensive_session_{target['name'].replace(' ', '_')}_error.json")
            with open(filename, 'w') as f:
                json.dump(error_result, f, indent=2)
            print(f"Error details saved to {filename}")
    
    # Flush production data
    collector.flush_all()
    
    print("\n✅ Comprehensive Training Session Complete")
    print("📊 Check: data/production_logs/ for logged executions")

if __name__ == '__main__':
    comprehensive_training_session()