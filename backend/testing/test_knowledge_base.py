"""
Test for the vulnerability knowledge base
"""

import sys
import os
import unittest

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from knowledge.vulnerability_kb import VulnerabilityKnowledgeBase


class TestVulnerabilityKnowledgeBase(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.kb = VulnerabilityKnowledgeBase()
        
    def test_kb_initialization(self):
        """Test that the knowledge base initializes correctly."""
        self.assertIsNotNone(self.kb.knowledge_base)
        self.assertIsInstance(self.kb.knowledge_base, dict)
        
    def test_get_exploitation_technique(self):
        """Test retrieving exploitation techniques."""
        # Test SQL injection technique
        sql_technique = self.kb.get_exploitation_technique('sql_injection')
        self.assertIsNotNone(sql_technique)
        self.assertIn('variants', sql_technique)
        self.assertIn('techniques', sql_technique)
        
        # Test non-existent technique
        empty_technique = self.kb.get_exploitation_technique('non_existent')
        self.assertEqual(empty_technique, {})
        
    def test_get_reproduction_template(self):
        """Test retrieving reproduction templates."""
        # Test SQL injection template
        sql_template = self.kb.get_reproduction_template('sql_injection')
        self.assertIsNotNone(sql_template)
        self.assertIn('steps', sql_template)
        self.assertIn('manual_testing', sql_template)
        
        # Test non-existent template
        empty_template = self.kb.get_reproduction_template('non_existent')
        self.assertEqual(empty_template, {})
        
    def test_get_remediation_knowledge(self):
        """Test retrieving remediation knowledge."""
        # Test SQL injection remediation
        sql_remediation = self.kb.get_remediation_knowledge('sql_injection')
        self.assertIsNotNone(sql_remediation)
        self.assertIn('immediate_fix', sql_remediation)
        self.assertIn('long_term_solution', sql_remediation)
        
        # Test non-existent remediation
        empty_remediation = self.kb.get_remediation_knowledge('non_existent')
        self.assertEqual(empty_remediation, {})
        
    def test_map_to_cwe(self):
        """Test mapping findings to CWE identifiers."""
        # Test SQL injection mapping
        sql_finding = {'type': 'sql_injection'}
        cwe_id = self.kb.map_to_cwe(sql_finding)
        self.assertEqual(cwe_id, 'CWE-89')
        
        # Test XSS mapping
        xss_finding = {'type': 'xss'}
        cwe_id = self.kb.map_to_cwe(xss_finding)
        self.assertEqual(cwe_id, 'CWE-79')
        
        # Test unknown mapping
        unknown_finding = {'type': 'unknown_type'}
        cwe_id = self.kb.map_to_cwe(unknown_finding)
        self.assertEqual(cwe_id, 'CWE-NVD-CWE-Other')
        
    def test_map_to_owasp(self):
        """Test mapping findings to OWASP categories."""
        # Test SQL injection mapping
        sql_finding = {'type': 'sql_injection'}
        owasp_cat = self.kb.map_to_owasp(sql_finding)
        self.assertEqual(owasp_cat, 'A03:2021-Injection')
        
        # Test XSS mapping
        xss_finding = {'type': 'xss'}
        owasp_cat = self.kb.map_to_owasp(xss_finding)
        self.assertEqual(owasp_cat, 'A03:2021-Injection')
        
        # Test unknown mapping
        unknown_finding = {'type': 'unknown_type'}
        owasp_cat = self.kb.map_to_owasp(unknown_finding)
        self.assertEqual(owasp_cat, 'A00:2021-Other')
        
    def test_adapt_reproduction_steps(self):
        """Test adapting reproduction steps for technology stack."""
        # Test with PHP stack
        php_steps = self.kb.adapt_reproduction_steps('sql_injection', ['php'])
        self.assertIsInstance(php_steps, list)
        self.assertGreater(len(php_steps), 0)
        
        # Test with unknown vulnerability type
        unknown_steps = self.kb.adapt_reproduction_steps('unknown_type', ['php'])
        self.assertEqual(unknown_steps, [])
        
    def test_get_language_specific_remediation(self):
        """Test getting language-specific remediation."""
        # Test Python remediation for SQL injection
        python_remediation = self.kb.get_language_specific_remediation('sql_injection', 'python')
        self.assertIsInstance(python_remediation, str)
        self.assertNotEqual(python_remediation, 'No language-specific guidance available')
        
        # Test unknown language
        unknown_remediation = self.kb.get_language_specific_remediation('sql_injection', 'unknown_lang')
        self.assertEqual(unknown_remediation, 'No language-specific guidance available')
        
    def test_get_framework_specific_remediation(self):
        """Test getting framework-specific remediation."""
        # Test Django remediation for SQL injection
        django_remediation = self.kb.get_framework_specific_remediation('sql_injection', 'django')
        self.assertIsInstance(django_remediation, str)
        self.assertNotEqual(django_remediation, 'No framework-specific guidance available')
        
        # Test unknown framework
        unknown_remediation = self.kb.get_framework_specific_remediation('sql_injection', 'unknown_framework')
        self.assertEqual(unknown_remediation, 'No framework-specific guidance available')


if __name__ == '__main__':
    unittest.main()