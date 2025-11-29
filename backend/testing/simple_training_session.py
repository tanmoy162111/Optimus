"""
Simple Training Session - Runs basic scanning tools on targets
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from training.production_data_collector import get_collector
from inference.tool_manager import ToolManager
import json
import time

def simple_training_session():
    """Simple training session with basic tools"""
    
    # Enable production logging
    collector = get_collector()
    
    # Load targets with absolute path
    targets_file = os.path.join(os.path.dirname(__file__), 'data', 'training_targets.json')
    with open(targets_file) as f:
        targets = json.load(f)['targets']
    
    class DummySocketIO:
        def emit(self, event, data):
            pass
    
    tool_manager = ToolManager(DummySocketIO())
    
    # Basic tools for training
    basic_tools = ['nmap', 'whatweb']
    
    for target in targets[:1]:  # Start with first target
        print(f"\n{'='*80}")
        print(f"Simple Training Session: {target['name']}")
        print(f"Target: {target['url']}")
        print(f"{'='*80}\n")
        
        results = {
            'target': target['url'],
            'tools_executed': [],
            'findings': [],
            'tool_results': {}
        }
        
        for tool_name in basic_tools:
            try:
                print(f"Executing {tool_name}...")
                
                # Execute tool with reasonable timeout
                tool_result = tool_manager.execute_tool(
                    tool_name=tool_name,
                    target=target['url'],
                    parameters={
                        'timeout': 300,  # 5 minutes per tool
                    },
                    scan_id=f"simple_{tool_name}_{int(time.time())}",
                    phase='reconnaissance'
                )
                
                results['tool_results'][tool_name] = tool_result
                results['tools_executed'].append(tool_name)
                
                # Extract findings
                parsed_results = tool_result.get('parsed_results', {})
                vulnerabilities = parsed_results.get('vulnerabilities', [])
                results['findings'].extend(vulnerabilities)
                
                print(f"  ✅ {tool_name}: {len(vulnerabilities)} findings")
                
                # Log execution for training data
                collector.log_tool_execution({
                    'scan_id': f"simple_{tool_name}",
                    'phase': 'reconnaissance',
                    'tool': tool_name,
                    'target': target['url'],
                    'context': {
                        'phase': 'reconnaissance',
                        'tools_executed': results['tools_executed'],
                    },
                    'result': tool_result,
                    'success': tool_result.get('success', False),
                    'vulns_found': len(vulnerabilities),
                    'execution_time': tool_result.get('execution_time', 0)
                })
                
            except Exception as e:
                print(f"  ❌ {tool_name}: Error - {e}")
                results['tool_results'][tool_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        # Save results
        filename = os.path.join(os.path.dirname(__file__), 'data', f"simple_session_{target['name'].replace(' ', '_')}.json")
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"\nSummary for {target['name']}:")
        print(f"  Tools executed: {len(results['tools_executed'])}")
        print(f"  Findings: {len(results['findings'])}")
        print(f"  Results saved to: {filename}")
    
    # Flush production data
    collector.flush_all()
    
    print("\n✅ Simple Training Session Complete")

if __name__ == '__main__':
    simple_training_session()