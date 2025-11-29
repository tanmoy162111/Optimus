#!/usr/bin/env python3
"""
Training System Demonstration

This script demonstrates the training system capabilities without requiring actual VM access
"""
import sys
import os
import json
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from inference.learning_module import RealTimeLearningModule
from inference.strategy_selector import StrategySelector

def demonstrate_training_system():
    """Demonstrate the training system capabilities"""
    print("🤖 Autonomous Pentest Agent Training System Demo")
    print("=" * 60)
    
    # Initialize components
    learning_module = RealTimeLearningModule()
    strategy_selector = StrategySelector()
    
    print("\n📊 1. Learning Module Demonstration")
    print("-" * 40)
    
    # Simulate tool executions
    sample_executions = [
        {
            'tool': 'nmap',
            'context': {'phase': 'reconnaissance', 'target_type': 'web'},
            'result': {
                'execution_time': 12.5,
                'success': True,
                'parsed_results': {
                    'vulnerabilities': [
                        {'type': 'open_port', 'port': 80, 'service': 'http'},
                        {'type': 'open_port', 'port': 443, 'service': 'https'}
                    ]
                }
            }
        },
        {
            'tool': 'nikto',
            'context': {'phase': 'scanning', 'target_type': 'web'},
            'result': {
                'execution_time': 45.2,
                'success': True,
                'parsed_results': {
                    'vulnerabilities': [
                        {'type': 'outdated_software', 'software': 'Apache 2.2'},
                        {'type': 'missing_headers', 'headers': ['X-Frame-Options']}
                    ]
                }
            }
        },
        {
            'tool': 'sqlmap',
            'context': {'phase': 'exploitation', 'target_type': 'web'},
            'result': {
                'execution_time': 120.8,
                'success': False,  # SQL injection test failed
                'parsed_results': {
                    'vulnerabilities': []
                }
            }
        }
    ]
    
    # Process executions through learning module
    for execution in sample_executions:
        print(f"\n🔧 Tool: {execution['tool']}")
        print(f"   Phase: {execution['context']['phase']}")
        print(f"   Success: {execution['result']['success']}")
        print(f"   Execution Time: {execution['result']['execution_time']}s")
        print(f"   Findings: {len(execution['result']['parsed_results']['vulnerabilities'])}")
        
        # Learn from execution
        insights = learning_module.learn_from_live_execution(
            execution['tool'],
            execution['context'],
            execution['result']
        )
        
        print(f"   Effectiveness Score: {insights['effectiveness_score']:.2f}")
        if insights['recommendations']:
            print(f"   Recommendations: {', '.join(insights['recommendations'])}")
    
    print("\n🎯 2. Context-Aware Tool Recommendations")
    print("-" * 40)
    
    # Get best tools for different contexts
    contexts = [
        {'phase': 'reconnaissance', 'target_type': 'web'},
        {'phase': 'scanning', 'target_type': 'web'},
        {'phase': 'exploitation', 'target_type': 'web'}
    ]
    
    for context in contexts:
        best_tools = learning_module.get_best_tools_for_context(context, top_n=3)
        print(f"\nContext: {context['phase']} ({context['target_type']})")
        print(f"Best Tools: {', '.join(best_tools) if best_tools else 'No data yet'}")
    
    print("\n🧭 3. Strategy Selector Demonstration")
    print("-" * 40)
    
    # Simulate strategy performance updates
    strategy_results = [
        {
            'strategy': 'adaptive',
            'results': {
                'findings_count': 8,
                'tools_used': ['nmap', 'nikto', 'whatweb'],
                'success_rate': 1.0,
                'coverage': 0.65
            }
        },
        {
            'strategy': 'aggressive',
            'results': {
                'findings_count': 12,
                'tools_used': ['nmap', 'nikto', 'sqlmap', 'gobuster', 'ffuf', 'nuclei'],
                'success_rate': 0.85,
                'coverage': 0.85
            }
        }
    ]
    
    # Update strategy performance
    for strategy_result in strategy_results:
        strategy_selector.update_strategy_performance(
            strategy_result['strategy'],
            strategy_result['results']
        )
        print(f"\n📈 Strategy: {strategy_result['strategy']}")
        print(f"   Findings: {strategy_result['results']['findings_count']}")
        print(f"   Tools Used: {len(strategy_result['results']['tools_used'])}")
        print(f"   Success Rate: {strategy_result['results']['success_rate']:.2f}")
        print(f"   Coverage: {strategy_result['results']['coverage']:.2f}")
    
    # Generate strategy report
    print("\n📋 Strategy Performance Report")
    print("-" * 30)
    report = strategy_selector.get_strategy_report()
    
    if report['strategies']:
        for name, data in report['strategies'].items():
            print(f"\n{name.capitalize()} Strategy:")
            print(f"  Executions: {data['executions']}")
            print(f"  Avg Findings: {data['avg_findings']:.2f}")
            print(f"  Success Rate: {data['success_rate']:.2f}")
            print(f"  Effectiveness: {data['effectiveness_score']:.2f}")
    
    if report['best_overall']:
        print(f"\n🏆 Best Overall Strategy: {report['best_overall'].capitalize()}")
    
    if report['recommendations']:
        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")
    
    print("\n🎉 Demo completed successfully!")

if __name__ == '__main__':
    demonstrate_training_system()