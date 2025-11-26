"""Parse PortSwigger Research Labs to extract training data"""
import os
import json
import re
from typing import Dict, List, Any
from collections import defaultdict
import random

class PortSwiggerLabParser:
    """
    Parse PortSwigger Research Labs dataset
    """
    
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.vulnerability_patterns = {
            'command_injection': ['command', 'injection', 'exec', 'shell'],
            'sql_injection': ['sql', 'database', 'query', 'select', 'union'],
            'xss': ['xss', 'cross-site', 'script', 'html', 'dom'],
            'jwt': ['jwt', 'token', 'signature', 'auth'],
            'xxe': ['xml', 'external', 'entity', 'xxe'],
            'ssrf': ['ssrf', 'server-side', 'request', 'forge'],
            'path_traversal': ['path', 'traversal', 'directory', '../'],
            'deserialization': ['deserialize', 'pickle', 'unserialize'],
            'csrf': ['csrf', 'cross-site', 'request', 'forge'],
            'file_upload': ['upload', 'file', 'multipart']
        }
    
    def parse_labs(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse all labs and generate phase-specific training data
        """
        print("="*80)
        print("PARSING PORTSWIGGER RESEARCH LABS DATASET")
        print("="*80)
        print(f"Dataset path: {self.dataset_path}\n")
        
        # Scan for lab directories
        labs = self._discover_labs()
        print(f"Found {len(labs)} labs\n")
        
        # Extract vulnerability information from each lab
        training_data = {
            'reconnaissance': [],
            'scanning': [],
            'exploitation': [],
            'post_exploitation': [],
            'covering_tracks': []
        }
        
        for lab in labs:
            lab_data = self._parse_lab(lab)
            if lab_data:
                # Generate training samples for each phase
                self._generate_training_samples(lab_data, training_data)
        
        # Print statistics
        print("\n" + "="*80)
        print("DATASET PARSING COMPLETE")
        print("="*80)
        for phase, samples in training_data.items():
            print(f"{phase:20s}: {len(samples):4d} samples")
        
        return training_data
    
    def _discover_labs(self) -> List[str]:
        """Find all lab directories"""
        labs = []
        for item in os.listdir(self.dataset_path):
            item_path = os.path.join(self.dataset_path, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                labs.append(item_path)
        return labs
    
    def _parse_lab(self, lab_path: str) -> Dict[str, Any]:
        """Parse a single lab directory"""
        lab_name = os.path.basename(lab_path)
        print(f"Parsing: {lab_name}")
        
        # Detect vulnerability type from name and content
        vuln_type = self._detect_vulnerability_type(lab_name, lab_path)
        
        # Scan for technologies
        technologies = self._detect_technologies(lab_path)
        
        # Scan for vulnerable code patterns
        vulnerable_files = self._scan_vulnerable_files(lab_path, vuln_type)
        
        # Calculate severity
        severity = self._estimate_severity(vuln_type, vulnerable_files)
        
        return {
            'lab_name': lab_name,
            'vulnerability_type': vuln_type,
            'technologies': technologies,
            'vulnerable_files': vulnerable_files,
            'severity': severity,
            'path': lab_path
        }
    
    def _detect_vulnerability_type(self, lab_name: str, lab_path: str) -> str:
        """Detect vulnerability type from lab name and content"""
        lab_name_lower = lab_name.lower()
        
        # Check name patterns
        for vuln_type, patterns in self.vulnerability_patterns.items():
            if any(pattern in lab_name_lower for pattern in patterns):
                return vuln_type
        
        # Check README or documentation
        readme_files = ['README.md', 'readme.md', 'README.txt']
        for readme in readme_files:
            readme_path = os.path.join(lab_path, readme)
            if os.path.exists(readme_path):
                try:
                    with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        for vuln_type, patterns in self.vulnerability_patterns.items():
                            if any(pattern in content for pattern in patterns):
                                return vuln_type
                except:
                    pass
        
        return 'unknown'
    
    def _detect_technologies(self, lab_path: str) -> List[str]:
        """Detect technologies used in the lab"""
        technologies = []
        
        # Check for common technology indicators
        tech_indicators = {
            'nodejs': ['package.json', 'node_modules', '.js'],
            'python': ['requirements.txt', '.py', 'flask', 'django'],
            'php': ['.php', 'composer.json'],
            'java': ['.java', 'pom.xml', 'build.gradle'],
            'docker': ['Dockerfile', 'docker-compose.yml'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx'],
            'react': ['react', 'package.json'],
            'express': ['express', 'server.js'],
            'flask': ['flask', 'application.py'],
        }
        
        for tech, indicators in tech_indicators.items():
            for root, dirs, files in os.walk(lab_path):
                for file in files:
                    if any(ind in file.lower() for ind in indicators):
                        if tech not in technologies:
                            technologies.append(tech)
                        break
                if tech in technologies:
                    break
        
        return technologies
    
    def _scan_vulnerable_files(self, lab_path: str, vuln_type: str) -> List[str]:
        """Scan for files containing vulnerable code"""
        vulnerable_files = []
        
        # Patterns to look for based on vulnerability type
        vuln_code_patterns = {
            'command_injection': [r'exec\(', r'system\(', r'shell_exec', r'subprocess'],
            'sql_injection': [r'SELECT.*FROM', r'\.execute\(', r'query\(', r'mysql_query'],
            'xss': [r'innerHTML', r'document\.write', r'eval\(', r'<script>'],
            'jwt': [r'jwt\.', r'token', r'verify', r'sign'],
            'xxe': [r'xml', r'parseXML', r'XMLParser', r'<!ENTITY'],
            'ssrf': [r'requests\.get', r'urllib', r'fetch\(', r'http\.request'],
        }
        
        patterns = vuln_code_patterns.get(vuln_type, [])
        if not patterns:
            return vulnerable_files
        
        for root, dirs, files in os.walk(lab_path):
            for file in files:
                if file.endswith(('.py', '.js', '.php', '.java', '.ts', '.jsx', '.tsx')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern in patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    vulnerable_files.append(file)
                                    break
                    except:
                        pass
        
        return vulnerable_files
    
    def _estimate_severity(self, vuln_type: str, vulnerable_files: List[str]) -> float:
        """Estimate CVSS severity score"""
        base_severity = {
            'command_injection': 9.5,
            'sql_injection': 9.0,
            'xss': 7.0,
            'jwt': 8.0,
            'xxe': 8.5,
            'ssrf': 8.0,
            'path_traversal': 7.5,
            'deserialization': 9.0,
            'csrf': 6.5,
            'file_upload': 8.5,
            'unknown': 5.0
        }
        
        severity = base_severity.get(vuln_type, 5.0)
        
        # Adjust based on number of vulnerable files
        if len(vulnerable_files) > 3:
            severity = min(10.0, severity + 0.5)
        
        return severity
    
    def _generate_training_samples(self, lab_data: Dict[str, Any], 
                                   training_data: Dict[str, List[Dict]]):
        """Generate phase-specific training samples from lab data"""
        vuln_type = lab_data['vulnerability_type']
        technologies = lab_data['technologies']
        severity = lab_data['severity']
        
        # Reconnaissance phase samples
        for _ in range(3):  # Generate 3 samples per lab
            training_data['reconnaissance'].append({
                'context': {
                    'target_type': 'web' if any(t in technologies for t in ['nodejs', 'flask', 'php']) else 'api',
                    'domain_complexity': random.uniform(0.4, 0.8),
                    'passive_recon_complete': random.choice([True, False]),
                    'active_recon_started': random.choice([True, False]),
                    'subdomains_discovered': random.randint(0, 20),
                    'emails_discovered': random.randint(0, 10),
                    'technologies_discovered': len(technologies),
                    'employees_discovered': random.randint(0, 15),
                    'time_in_phase': random.randint(60, 900),
                    'stealth_required': random.choice([True, False]),
                    'detection_risk': random.uniform(0.2, 0.6),
                    'num_tools_executed': random.randint(0, 5),
                    'passive_tools_ratio': random.uniform(0.4, 0.9)
                },
                'tool': random.choice(['sublist3r', 'theHarvester', 'whatweb', 'shodan', 'dnsenum']),
                'success': True,
                'vulns_found': 0,
                'execution_time': random.uniform(20, 300)
            })
        
        # Scanning phase samples
        has_nodejs = 'nodejs' in technologies or 'javascript' in technologies
        has_python = 'python' in technologies or 'flask' in technologies
        has_php = 'php' in technologies
        
        for _ in range(4):  # More scanning samples
            training_data['scanning'].append({
                'context': {
                    'target_type': 'web',
                    'technologies_known': len(technologies),
                    'subdomains_count': random.randint(1, 15),
                    'open_ports_found': random.randint(1, 10),
                    'scan_coverage': random.uniform(0.4, 0.9),
                    'vulnerabilities_found': random.randint(0, 5),
                    'services_enumerated': random.randint(1, 8),
                    'wordpress_detected': False,
                    'joomla_detected': False,
                    'has_ssl_tls': random.choice([True, False]),
                    'has_database': 'sql' in vuln_type or random.choice([True, False]),
                    'has_smb': False,
                    'time_in_phase': random.randint(120, 1800),
                    'num_tools_executed': random.randint(1, 4),
                    'aggressive_mode': random.choice([True, False])
                },
                'tool': random.choice(['nmap', 'nuclei', 'nikto', 'sslscan']),
                'success': True,
                'vulns_found': random.randint(1, 5),
                'execution_time': random.uniform(60, 600)
            })
        
        # Exploitation phase samples (key phase!)
        for _ in range(5):  # Most samples for exploitation
            # Map vuln type to tool
            tool_mapping = {
                'command_injection': 'commix',
                'sql_injection': 'sqlmap',
                'xss': 'dalfox',
                'jwt': 'jwt_tool',
                'xxe': 'xxeinjector',
                'ssrf': 'ssrfmap',
                'deserialization': 'ysoserial',
                'path_traversal': 'dotdotpwn',
                'csrf': 'burp',
                'file_upload': 'weevely'
            }
            
            training_data['exploitation'].append({
                'context': {
                    'sql_injection_found': vuln_type == 'sql_injection',
                    'xss_found': vuln_type == 'xss',
                    'command_injection_found': vuln_type == 'command_injection',
                    'xxe_found': vuln_type == 'xxe',
                    'ssrf_found': vuln_type == 'ssrf',
                    'file_upload_found': vuln_type == 'file_upload',
                    'auth_bypass_found': vuln_type == 'jwt',
                    'highest_severity': severity,
                    'num_critical_vulns': 1 if severity >= 9.0 else 0,
                    'num_exploitable_vulns': random.randint(1, 3),
                    'waf_detected': random.choice([True, False]),
                    'authentication_required': 'jwt' in vuln_type or random.choice([True, False]),
                    'target_hardening_level': random.uniform(0.2, 0.7),
                    'access_gained': random.choice([True, False]),
                    'exploit_attempts': random.randint(1, 5),
                    'time_in_phase': random.randint(180, 2400)
                },
                'tool': tool_mapping.get(vuln_type, 'metasploit'),
                'success': random.choice([True, True, False]),  # 66% success
                'vulns_found': random.randint(0, 2),
                'execution_time': random.uniform(120, 1800)
            })
        
        # Post-exploitation samples
        os_type = 'linux' if has_python or has_nodejs or has_php else random.choice(['linux', 'windows'])
        
        for _ in range(3):
            training_data['post_exploitation'].append({
                'context': {
                    'current_user_privilege': random.choice(['user', 'admin', 'root']),
                    'os_type': os_type,
                    'os_version': 'Ubuntu 20.04' if os_type == 'linux' else 'Windows Server 2019',
                    'privilege_escalated': random.choice([True, False]),
                    'persistence_established': random.choice([True, False]),
                    'credentials_dumped': random.choice([True, False]),
                    'lateral_movement_success': random.choice([True, False]),
                    'domain_joined': random.choice([True, False]),
                    'antivirus_detected': random.choice([True, False]),
                    'edr_detected': random.choice([True, False]),
                    'other_hosts_visible': random.randint(0, 15),
                    'time_in_phase': random.randint(240, 1800),
                    'num_tools_executed': random.randint(0, 5),
                    'detection_probability': random.uniform(0.2, 0.7)
                },
                'tool': 'linpeas' if os_type == 'linux' else random.choice(['winpeas', 'mimikatz']),
                'success': random.choice([True, False]),
                'vulns_found': 0,
                'execution_time': random.uniform(60, 600)
            })
        
        # Covering tracks samples
        for _ in range(2):
            training_data['covering_tracks'].append({
                'context': {
                    'log_entries_present': random.randint(50, 300),
                    'artifacts_present': random.randint(1, 10),
                    'backdoors_installed': random.randint(0, 2),
                    'forensic_evidence_score': random.uniform(4.0, 9.0),
                    'logs_cleaned': random.choice([True, False]),
                    'timestamps_modified': random.choice([True, False]),
                    'artifacts_removed': random.choice([True, False]),
                    'time_remaining': random.randint(120, 600),
                    'stealth_critical': random.choice([True, True, False]),
                    'detection_imminent': random.choice([True, False]),
                    'os_type': os_type,
                    'admin_access': random.choice([True, False])
                },
                'tool': random.choice(['clear_logs', 'timestomp', 'shred', 'wevtutil']),
                'success': random.choice([True, True, False]),
                'vulns_found': 0,
                'execution_time': random.uniform(10, 180)
            })


def main():
    """Parse PortSwigger labs and save training data"""
    dataset_path = r"D:\Work\Ai Engineering\Git\data\datasets\PortSwigger Research Lab Data\research-labs-main"
    
    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found at: {dataset_path}")
        return
    
    parser = PortSwiggerLabParser(dataset_path)
    training_data = parser.parse_labs()
    
    # Save to JSON files
    output_dir = 'data/phase_training_logs'
    os.makedirs(output_dir, exist_ok=True)
    
    for phase, logs in training_data.items():
        output_path = f'{output_dir}/{phase}_training_logs.json'
        with open(output_path, 'w') as f:
            json.dump(logs, f, indent=2)
        print(f"✅ Saved {len(logs)} samples to: {output_path}")
    
    print(f"\n{'='*80}")
    print("READY FOR TRAINING")
    print(f"{'='*80}")
    print("Run: python train_phase_models.py")

if __name__ == '__main__':
    main()
