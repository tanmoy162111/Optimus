"""Test rule-based tool selector accuracy"""
import sys
sys.path.append('..')
from inference.rule_based_tool_selector import RuleBasedToolSelector

def test_rule_based_accuracy():
    """
    Test rule-based selector on known scenarios
    """
    print("="*80)
    print("TESTING: Rule-Based Tool Selector")
    print("="*80)
    
    selector = RuleBasedToolSelector()
    
    test_cases = [
        # Reconnaissance
        {
            'name': 'Reconnaissance Phase',
            'context': {
                'phase': 'reconnaissance',
                'target': 'example.com',
                'tools_executed': []
            },
            'expected_first': 'sublist3r'
        },
        # Scanning after recon
        {
            'name': 'Scanning Phase',
            'context': {
                'phase': 'scanning',
                'target': 'http://example.com',
                'tools_executed': []
            },
            'expected_first': 'nmap'
        },
        # Exploitation with SQL injection found
        {
            'name': 'Exploitation - SQL Injection',
            'context': {
                'phase': 'exploitation',
                'findings': [
                    {'type': 'sql_injection', 'severity': 9.8}
                ],
                'tools_executed': []
            },
            'expected_first': 'sqlmap'
        },
        # WordPress detected
        {
            'name': 'WordPress Site Scanning',
            'context': {
                'phase': 'scanning',
                'target': 'http://wordpress-site.com',
                'technologies_detected': ['wordpress'],
                'tools_executed': ['nmap']
            },
            'expected_first': 'wpscan'
        },
        # XSS found
        {
            'name': 'Exploitation - XSS',
            'context': {
                'phase': 'exploitation',
                'findings': [
                    {'type': 'xss', 'severity': 7.5}
                ],
                'tools_executed': []
            },
            'expected_first': 'dalfox'
        },
        # Post-exploitation Linux
        {
            'name': 'Post-Exploitation - Linux',
            'context': {
                'phase': 'post_exploitation',
                'os_type': 'linux',
                'tools_executed': []
            },
            'expected_first': 'linpeas'
        },
        # Covering tracks
        {
            'name': 'Covering Tracks',
            'context': {
                'phase': 'covering_tracks',
                'tools_executed': []
            },
            'expected_first': 'clear_logs'
        }
    ]
    
    correct = 0
    total = len(test_cases)
    
    print(f"\nRunning {total} test cases...\n")
    
    for i, test in enumerate(test_cases, 1):
        tools = selector.recommend_tools(test['context'])
        predicted_first = tools[0] if tools else None
        expected_first = test['expected_first']
        
        if predicted_first == expected_first:
            correct += 1
            print(f"✅ Test {i} ({test['name']}): {predicted_first} == {expected_first}")
        else:
            print(f"❌ Test {i} ({test['name']}): {predicted_first} != {expected_first}")
            print(f"   Recommended: {tools}")
    
    accuracy = correct / total
    print(f"\n" + "="*80)
    print(f"Rule-based accuracy: {accuracy:.1%} ({correct}/{total})")
    print("="*80)
    
    assert accuracy >= 0.70, f"❌ Accuracy {accuracy:.1%} < 70%"
    print("\n✅ RULE-BASED SELECTOR TEST PASSED")
    
    # Test reasoning generation
    print("\n" + "="*80)
    print("Testing Reasoning Generation")
    print("="*80)
    
    test_context = {
        'phase': 'exploitation',
        'findings': [
            {'type': 'sql_injection', 'severity': 9.8},
            {'type': 'xss', 'severity': 7.5}
        ],
        'tools_executed': []
    }
    
    tools = selector.recommend_tools(test_context)
    reasoning = selector.get_reasoning(test_context, tools)
    print(f"\nContext: {test_context['phase']}")
    print(f"Recommended: {tools}")
    print(f"Reasoning: {reasoning}")
    print("\n✅ Reasoning generation working")

if __name__ == '__main__':
    test_rule_based_accuracy()
