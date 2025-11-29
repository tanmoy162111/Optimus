#!/usr/bin/env python3
"""
Simple Training Test Script

This script tests the training infrastructure with a minimal example
"""
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from training_environment.session_manager import TrainingSessionManager

def test_training_session():
    """Test the training session with minimal configuration"""
    print("Testing Training Session Manager...")
    
    # Simple test configuration
    target_vms = ['http://192.168.131.128']
    session_config = {
        'num_episodes': 1,
        'learning_mode': 'exploration',
        'output_dir': 'training_output/test_session',
        'feedback_frequency': 1
    }
    
    print(f"Target VMs: {target_vms}")
    print(f"Episodes: {session_config['num_episodes']}")
    
    try:
        # Initialize session manager
        session_manager = TrainingSessionManager(target_vms, session_config)
        print("✅ Session manager initialized successfully")
        
        # Test single episode execution
        print("\nExecuting test episode...")
        episode_result = session_manager.execute_training_episode(
            target='http://192.168.131.128',
            episode_num=0
        )
        
        print(f"Episode result: {episode_result}")
        print("✅ Episode execution completed")
        
        # Test data collection
        test_tool_result = {
            'tool_name': 'nmap',
            'execution_time': 10.5,
            'success': True,
            'parsed_results': {
                'vulnerabilities': [
                    {'type': 'open_port', 'port': 80, 'service': 'http'},
                    {'type': 'open_port', 'port': 443, 'service': 'https'}
                ]
            }
        }
        
        execution_data = session_manager.collect_execution_data(test_tool_result)
        print(f"Collected execution data: {execution_data}")
        print("✅ Data collection completed")
        
        # Test learning update
        test_episode_data = {
            'episode_num': 0,
            'target': 'http://192.168.131.128',
            'duration': 15.2,
            'tools_used': [
                {
                    'tool': 'nmap',
                    'success': True,
                    'execution_time': 10.5,
                    'phase': 'reconnaissance'
                }
            ],
            'findings': [
                {'type': 'open_port', 'port': 80, 'service': 'http', 'tool': 'nmap'},
                {'type': 'open_port', 'port': 443, 'service': 'https', 'tool': 'nmap'}
            ],
            'coverage': 0.2,
            'strategy_used': 'adaptive',
            'success': True,
            'timestamp': '2025-11-29T08:00:00'
        }
        
        session_manager.update_agent_learning(test_episode_data)
        print("✅ Learning update completed")
        
        print("\n🎉 All tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_training_session()
    sys.exit(0 if success else 1)