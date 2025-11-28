"""
Test for the autonomous agent and reporting functionality
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from inference.autonomous_agent import AutonomousPentestAgent
from reporting.report_generator import VulnerabilityReportGenerator


class TestAgentAndReporting(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.agent = AutonomousPentestAgent()
        self.report_generator = VulnerabilityReportGenerator()
        
    def test_agent_initialization(self):
        """Test that the autonomous agent initializes correctly."""
        self.assertIsNotNone(self.agent.tool_db)
        self.assertIsNotNone(self.agent.knowledge_base)
        self.assertIsNotNone(self.agent.decision_engine)
        self.assertIsNotNone(self.agent.learning_module)
        
    def test_agent_conduct_scan(self):
        """Test that the agent can conduct a scan."""
        # Mock the target and config
        target = "http://test.example.com"
        scan_config = {
            'max_time': 3600,
            'depth': 'normal',
            'stealth': False,
            'target_type': 'http_service'
        }
        
        # Conduct a scan
        result = self.agent.conduct_scan(target, scan_config)
        
        # Verify the result structure
        self.assertIn('scan_id', result)
        self.assertIn('target', result)
        self.assertIn('findings', result)
        self.assertIn('tools_executed', result)
        self.assertIn('coverage', result)
        
    def test_report_generator_initialization(self):
        """Test that the report generator initializes correctly."""
        self.assertIsNotNone(self.report_generator)
        
    def test_generate_detailed_report(self):
        """Test that the report generator can create a detailed report."""
        # Create a mock scan state
        scan_state = {
            'scan_id': 'test-scan-123',
            'target': 'http://test.example.com',
            'findings': [
                {
                    'id': 'vuln-1',
                    'type': 'sql_injection',
                    'name': 'SQL Injection',
                    'severity': 9.5,
                    'location': 'http://test.example.com/login',
                    'parameter': 'username',
                    'evidence': "' OR '1'='1",
                    'tool': 'sqlmap'
                }
            ],
            'tools_executed': ['nmap', 'nikto', 'sqlmap'],
            'coverage': 0.75,
            'time_elapsed': 300
        }
        
        # Generate a report
        report = self.report_generator.generate_detailed_report(scan_state)
        
        # Verify the report structure
        self.assertIn('metadata', report)
        self.assertIn('executive_summary', report)
        self.assertIn('vulnerabilities', report)
        self.assertIn('attack_chain', report)
        self.assertIn('recommendations', report)
        
        # Verify metadata
        self.assertEqual(report['metadata']['scan_id'], 'test-scan-123')
        self.assertEqual(report['metadata']['target'], 'http://test.example.com')
        
        # Verify vulnerabilities
        self.assertEqual(len(report['vulnerabilities']), 1)
        self.assertEqual(report['vulnerabilities'][0]['title'], 'SQL Injection')
        
    def test_calculate_severity_rating(self):
        """Test severity rating calculation."""
        # Test critical severity
        critical_finding = {'severity': 9.5}
        self.assertEqual(
            self.report_generator._calculate_severity_rating(critical_finding), 
            'Critical'
        )
        
        # Test high severity
        high_finding = {'severity': 7.5}
        self.assertEqual(
            self.report_generator._calculate_severity_rating(high_finding), 
            'High'
        )
        
        # Test medium severity
        medium_finding = {'severity': 5.5}
        self.assertEqual(
            self.report_generator._calculate_severity_rating(medium_finding), 
            'Medium'
        )
        
        # Test low severity
        low_finding = {'severity': 2.5}
        self.assertEqual(
            self.report_generator._calculate_severity_rating(low_finding), 
            'Low'
        )


if __name__ == '__main__':
    unittest.main()