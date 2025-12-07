#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from inference.output_parser import OutputParser

def test_findings_storage():
    """Test if findings with different severities are properly handled"""
    
    # Test with low severity findings
    low_severity_output = "+ Server: Apache/2.4.52\n+ /: Missing security headers"
    
    # Test with high severity findings
    high_severity_output = "+ /login: SQL injection possible\n+ Server vulnerable to XSS"
    
    parser = OutputParser()
    
    print("Testing low severity findings:")
    low_result = parser.parse_tool_output('nikto', low_severity_output, '')
    print(f"  Found {len(low_result['vulnerabilities'])} vulnerabilities")
    for v in low_result['vulnerabilities']:
        print(f"    - {v['name']} (Severity: {v['severity']})")
    
    print("\nTesting high severity findings:")
    high_result = parser.parse_tool_output('nikto', high_severity_output, '')
    print(f"  Found {len(high_result['vulnerabilities'])} vulnerabilities")
    for v in high_result['vulnerabilities']:
        print(f"    - {v['name']} (Severity: {v['severity']})")

if __name__ == '__main__':
    test_findings_storage()