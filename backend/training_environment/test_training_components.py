"""
Unit Tests for Training Components

This module tests the training infrastructure components in isolation
"""
import unittest
import sys
import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from training_environment.session_manager import TrainingSessionManager
from inference.learning_module import RealTimeLearningModule
from inference.strategy_selector import StrategySelector

class TestTrainingComponents(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.test_targets = ['http://192.168.131.128']
        self.test_config = {
            'num_episodes': 1,
            'learning_mode': 'exploration',
            'output_dir': 'training_output/unit_test',
            'feedback_frequency': 1
        }
    
    def test_session_manager_initialization(self):
        """Test that TrainingSessionManager initializes correctly"""
        with patch('inference.autonomous_agent.AutonomousPentestAgent') as mock_agent:
            session_manager = TrainingSessionManager(self.test_targets, self.test_config)
            
            # Verify initialization
            self.assertEqual(session_manager.target_vms, self.test_targets)
            self.assertEqual(session_manager.num_episodes, 1)
            self.assertEqual(session_manager.learning_mode, 'exploration')
            
            # Verify components are initialized
            self.assertIsNotNone(session_manager.agent)
            self.assertIsNotNone(session_manager.learning_module)
            self.assertIsNotNone(session_manager.strategy_selector)
    
    def test_collect_execution_data(self):
        """Test collecting execution data from tool results"""
        with patch('inference.autonomous_agent.AutonomousPentestAgent'):
            session_manager = TrainingSessionManager(self.test_targets, self.test_config)
            
            # Test data
            tool_result = {
                'tool_name': 'nmap',
                'execution_time': 15.5,
                'success': True,
                'exit_code': 0,
                'parsed_results': {
                    'vulnerabilities': [
                        {'type': 'open_port', 'port': 80},
                        {'type': 'open_port', 'port': 443}
                    ]
                },
                'stdout': 'Nmap scan report...',
                'stderr': '',
                'parameters': {'-sV': True, '-T4': True},
                'phase': 'reconnaissance'
            }
            
            # Collect execution data
            execution_data = session_manager.collect_execution_data(tool_result)
            
            # Verify collected data
            self.assertEqual(execution_data['tool_name'], 'nmap')
            self.assertEqual(execution_data['execution_time'], 15.5)
            self.assertTrue(execution_data['success'])
            self.assertEqual(execution_data['findings_count'], 2)
            self.assertEqual(execution_data['stdout_length'], 19)  # Corrected length
            self.assertEqual(execution_data['stderr_length'], 0)
            self.assertEqual(execution_data['phase'], 'reconnaissance')
    
    def test_learning_module_enhancements(self):
        """Test enhanced learning module with live execution feedback"""
        learning_module = RealTimeLearningModule()
        
        # Test context creation
        context = {
            'phase': 'reconnaissance',
            'target_type': 'web'
        }
        context_key = learning_module._create_context_key(context)
        self.assertEqual(context_key, 'reconnaissance_web')
        
        # Test effectiveness calculation
        stats = {
            'executions': 10,
            'successes': 8,
            'total_findings': 15,
            'avg_time': 12.5
        }
        effectiveness = learning_module._calculate_contextual_effectiveness(stats)
        self.assertIsInstance(effectiveness, float)
        self.assertGreaterEqual(effectiveness, 0.0)
        self.assertLessEqual(effectiveness, 1.0)
        
        # Test recommendations generation
        recommendations = learning_module._generate_recommendations(
            'nmap', context, 0.8, [{'type': 'open_port'}]
        )
        self.assertIsInstance(recommendations, list)
        
        # Test alternative suggestions
        alternatives = learning_module._suggest_alternatives(context, 0.8)
        self.assertIsInstance(alternatives, list)
        self.assertLessEqual(len(alternatives), 3)
    
    def test_strategy_selector_enhancements(self):
        """Test enhanced strategy selector with performance tracking"""
        strategy_selector = StrategySelector()
        
        # Test strategy performance update
        scan_results = {
            'findings_count': 5,
            'tools_used': ['nmap', 'nikto'],
            'success_rate': 1.0,
            'coverage': 0.75
        }
        
        # Update strategy performance
        strategy_selector.update_strategy_performance('adaptive', scan_results)
        
        # Verify update
        strategy = strategy_selector.strategies['adaptive']
        self.assertEqual(strategy['executions'], 1)
        self.assertEqual(strategy['avg_findings'], 5.0)
        self.assertEqual(strategy['success_rate'], 1.0)
        
        # Test strategy report generation
        report = strategy_selector.get_strategy_report()
        self.assertIsInstance(report, dict)
        self.assertIn('strategies', report)
        self.assertIn('best_overall', report)
    
    def test_make_serializable(self):
        """Test making objects serializable for JSON storage"""
        with patch('inference.autonomous_agent.AutonomousPentestAgent'):
            session_manager = TrainingSessionManager(self.test_targets, self.test_config)
            
            # Test data with non-serializable objects
            test_data = {
                'path': Path('/tmp/test'),
                'nested': {
                    'list': [Path('/tmp/a'), Path('/tmp/b')],
                    'number': 42
                }
            }
            
            # Make serializable
            serializable_data = session_manager._make_serializable(test_data)
            
            # Verify conversion
            self.assertIsInstance(serializable_data['path'], str)
            self.assertIsInstance(serializable_data['nested']['list'][0], str)
            self.assertIsInstance(serializable_data['nested']['list'][1], str)
            self.assertEqual(serializable_data['nested']['number'], 42)

if __name__ == '__main__':
    unittest.main()