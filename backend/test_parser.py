#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')

from inference.output_parser import OutputParser

def test_nikto_parser():
    parser = OutputParser()
    
    # Test with high severity findings
    nikto_output = '''\
+ /login: SQL injection may be possible.
+ Server may be vulnerable to cross-site scripting.
+ /upload: Remote code execution possible.
+ /admin: Authentication bypass detected.
'''
    
    result = parser.parse_tool_output('nikto', nikto_output, '')
    print('Vulnerabilities found:', len(result['vulnerabilities']))
    for v in result['vulnerabilities']:
        print(f'  - {v["name"]} (Severity: {v["severity"]}, Type: {v["type"]})')

if __name__ == '__main__':
    test_nikto_parser()