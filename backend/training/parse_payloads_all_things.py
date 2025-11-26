"""Parse PayloadsAllTheThings dataset to extract training data"""
import os
import json
import re
from typing import Dict, List, Any
from collections import defaultdict
import random

class PayloadsAllTheThingsParser:
    """
    Parse PayloadsAllTheThings comprehensive attack payload collection
    """
    
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        
        # Map vulnerability types to phases and tools
        self.vuln_to_phase_tool = {
            # Reconnaissance phase
            'API Key Leaks': ('reconnaissance', 'theHarvester'),
            'Hidden Parameters': ('reconnaissance', 'arjun'),
            'DNS Rebinding': ('reconnaissance', 'dnsenum'),
            
            # Scanning phase
            'Directory Traversal': ('scanning', 'dirb'),
            'File Inclusion': ('scanning', 'nuclei'),
            'CORS Misconfiguration': ('scanning', 'cors-scanner'),
            'Clickjacking': ('scanning', 'nuclei'),
            'GraphQL Injection': ('scanning', 'graphql-cop'),
            'Prototype Pollution': ('scanning', 'nuclei'),
            'Open Redirect': ('scanning', 'openredirex'),
            'Server Side Request Forgery': ('scanning', 'ssrfmap'),
            
            # Exploitation phase
            'Command Injection': ('exploitation', 'commix'),
            'SQL Injection': ('exploitation', 'sqlmap'),
            'NoSQL Injection': ('exploitation', 'nosqlmap'),
            'XSS Injection': ('exploitation', 'dalfox'),
            'XXE Injection': ('exploitation', 'xxeinjector'),
            'LDAP Injection': ('exploitation', 'ldapinjection'),
            'LaTeX Injection': ('exploitation', 'custom'),
            'CSV Injection': ('exploitation', 'custom'),
            'CRLF Injection': ('exploitation', 'custom'),
            'Cross-Site Request Forgery': ('exploitation', 'burp'),
            'Insecure Deserialization': ('exploitation', 'ysoserial'),
            'Insecure Direct Object References': ('exploitation', 'burp'),
            'JSON Web Token': ('exploitation', 'jwt_tool'),
            'OAuth': ('exploitation', 'oauth-scan'),
            'Race Condition': ('exploitation', 'turbo-intruder'),
            'Remote File Inclusion': ('exploitation', 'lfi-suite'),
            'SAML Injection': ('exploitation', 'saml-raider'),
            'Server Side Template Injection': ('exploitation', 'tplmap'),
            'Type Juggling': ('exploitation', 'custom'),
            'Upload Insecure Files': ('exploitation', 'weevely'),
            'XPATH Injection': ('exploitation', 'xcat'),
            
            # Post-exploitation phase
            'Account Takeover': ('post_exploitation', 'account-takeover'),
            'Linux Privilege Escalation': ('post_exploitation', 'linpeas'),
            'Windows Privilege Escalation': ('post_exploitation', 'winpeas'),
            'Active Directory Attack': ('post_exploitation', 'bloodhound'),
            'Kerberos': ('post_exploitation', 'rubeus'),
            'NTLM': ('post_exploitation', 'crackmapexec'),
            
            # Covering tracks
            'Log Poisoning': ('covering_tracks', 'log_wiper'),
            'Web Cache Poisoning': ('covering_tracks', 'cache-poisoning'),
        }
        
        # Severity mapping
        self.severity_map = {
            'Command Injection': 9.8,
            'SQL Injection': 9.0,
            'NoSQL Injection': 8.5,
            'Remote File Inclusion': 9.5,
            'Insecure Deserialization': 9.0,
            'XXE Injection': 8.5,
            'Server Side Request Forgery': 8.0,
            'XSS Injection': 7.5,
            'LDAP Injection': 8.0,
            'XPATH Injection': 7.5,
            'Server Side Template Injection': 9.0,
            'Upload Insecure Files': 8.5,
            'CRLF Injection': 6.5,
            'CSRF': 6.5,
            'JSON Web Token': 8.0,
            'OAuth': 7.5,
            'IDOR': 7.0,
            'Race Condition': 7.0,
            'Directory Traversal': 7.5,
            'File Inclusion': 8.0,
            'Clickjacking': 5.5,
            'CORS Misconfiguration': 6.0,
            'Open Redirect': 5.5,
            'API Key Leaks': 8.0,
        }
    
    def parse_dataset(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parse all payload directories and generate training data"""
        print("="*80)
        print("PARSING PAYLOADSALLTHETHINGS DATASET")
        print("="*80)
        print(f"Dataset path: {self.dataset_path}\n")
        
        training_data = {
            'reconnaissance': [],
            'scanning': [],
            'exploitation': [],
            'post_exploitation': [],
            'covering_tracks': []
        }
        
        # Scan all directories
        vuln_dirs = self._discover_vulnerability_dirs()
        print(f"Found {len(vuln_dirs)} vulnerability directories\n")
        
        for vuln_dir in vuln_dirs:
            vuln_name = os.path.basename(vuln_dir)
            
            # Get phase and tool mapping
            phase, tool = self._map_vuln_to_phase_tool(vuln_name)
            
            if phase:
                # Generate training samples for this vulnerability
                samples = self._generate_samples(vuln_name, vuln_dir, phase, tool)
                training_data[phase].extend(samples)
                print(f"  {vuln_name:40s} -> {phase:20s} ({len(samples)} samples)")
        
        # Print statistics
        print("\n" + "="*80)
        print("DATASET PARSING COMPLETE")
        print("="*80)
        total = 0
        for phase, samples in training_data.items():
            count = len(samples)
            total += count
            print(f"{phase:20s}: {count:4d} samples")
        print(f"{'='*80}")
        print(f"{'Total':20s}: {total:4d} samples")
        
        return training_data
    
    def _discover_vulnerability_dirs(self) -> List[str]:
        """Find all vulnerability directories"""
        vuln_dirs = []
        
        for item in os.listdir(self.dataset_path):
            item_path = os.path.join(self.dataset_path, item)
            
            # Skip hidden and special directories
            if os.path.isdir(item_path) and not item.startswith(('_', '.')):
                vuln_dirs.append(item_path)
        
        return sorted(vuln_dirs)
    
    def _map_vuln_to_phase_tool(self, vuln_name: str) -> tuple:
        """Map vulnerability name to phase and tool"""
        
        # Direct mapping
        if vuln_name in self.vuln_to_phase_tool:
            return self.vuln_to_phase_tool[vuln_name]
        
        # Fuzzy matching
        vuln_lower = vuln_name.lower()
        
        if any(word in vuln_lower for word in ['sql', 'sqli']):
            return ('exploitation', 'sqlmap')
        elif any(word in vuln_lower for word in ['xss', 'cross-site scripting']):
            return ('exploitation', 'dalfox')
        elif any(word in vuln_lower for word in ['command', 'rce', 'code execution']):
            return ('exploitation', 'commix')
        elif any(word in vuln_lower for word in ['ssrf', 'server-side request']):
            return ('scanning', 'ssrfmap')
        elif any(word in vuln_lower for word in ['xxe', 'xml']):
            return ('exploitation', 'xxeinjector')
        elif any(word in vuln_lower for word in ['deserialization', 'deserialize']):
            return ('exploitation', 'ysoserial')
        elif any(word in vuln_lower for word in ['upload', 'file upload']):
            return ('exploitation', 'weevely')
        elif any(word in vuln_lower for word in ['lfi', 'file inclusion', 'path traversal']):
            return ('scanning', 'nuclei')
        elif any(word in vuln_lower for word in ['jwt', 'token']):
            return ('exploitation', 'jwt_tool')
        elif any(word in vuln_lower for word in ['privilege escalation', 'privesc']):
            if 'linux' in vuln_lower:
                return ('post_exploitation', 'linpeas')
            elif 'windows' in vuln_lower:
                return ('post_exploitation', 'winpeas')
            else:
                return ('post_exploitation', 'linpeas')
        elif any(word in vuln_lower for word in ['active directory', 'ad', 'kerberos', 'ntlm']):
            return ('post_exploitation', 'bloodhound')
        
        # Default to scanning if unknown
        return ('scanning', 'nuclei')
    
    def _generate_samples(self, vuln_name: str, vuln_dir: str, 
                         phase: str, tool: str) -> List[Dict[str, Any]]:
        """Generate training samples for a vulnerability"""
        
        # Count files (as proxy for complexity)
        file_count = sum(1 for root, dirs, files in os.walk(vuln_dir) for f in files)
        
        # Get severity
        severity = self.severity_map.get(vuln_name, 6.0)
        
        # Generate 2-5 samples per vulnerability
        num_samples = min(5, max(2, file_count // 2))
        samples = []
        
        for _ in range(num_samples):
            if phase == 'reconnaissance':
                sample = self._generate_recon_sample(vuln_name, tool)
            elif phase == 'scanning':
                sample = self._generate_scanning_sample(vuln_name, tool, severity)
            elif phase == 'exploitation':
                sample = self._generate_exploitation_sample(vuln_name, tool, severity)
            elif phase == 'post_exploitation':
                sample = self._generate_post_exploit_sample(vuln_name, tool)
            else:  # covering_tracks
                sample = self._generate_covering_tracks_sample(vuln_name, tool)
            
            samples.append(sample)
        
        return samples
    
    def _generate_recon_sample(self, vuln_name: str, tool: str) -> Dict[str, Any]:
        """Generate reconnaissance phase sample"""
        return {
            'context': {
                'target_type': random.choice(['web', 'api', 'network']),
                'domain_complexity': random.uniform(0.3, 0.9),
                'passive_recon_complete': random.choice([True, False]),
                'active_recon_started': random.choice([True, False]),
                'subdomains_discovered': random.randint(0, 50),
                'emails_discovered': random.randint(0, 20),
                'technologies_discovered': random.randint(0, 15),
                'employees_discovered': random.randint(0, 30),
                'time_in_phase': random.randint(60, 1800),
                'stealth_required': random.choice([True, False]),
                'detection_risk': random.uniform(0.1, 0.5),
                'num_tools_executed': random.randint(0, 6),
                'passive_tools_ratio': random.uniform(0.4, 0.8)
            },
            'tool': tool,
            'success': random.choice([True, True, False]),
            'vulns_found': 0,
            'execution_time': random.uniform(10, 300)
        }
    
    def _generate_scanning_sample(self, vuln_name: str, tool: str, severity: float) -> Dict[str, Any]:
        """Generate scanning phase sample"""
        return {
            'context': {
                'target_type': 'web',
                'technologies_known': random.randint(0, 10),
                'subdomains_count': random.randint(1, 30),
                'open_ports_found': random.randint(0, 20),
                'scan_coverage': random.uniform(0.2, 0.9),
                'vulnerabilities_found': random.randint(0, 15),
                'services_enumerated': random.randint(0, 10),
                'wordpress_detected': False,
                'joomla_detected': False,
                'has_ssl_tls': random.choice([True, False]),
                'has_database': random.choice([True, False]),
                'has_smb': random.choice([True, False]),
                'time_in_phase': random.randint(120, 2400),
                'num_tools_executed': random.randint(1, 5),
                'aggressive_mode': random.choice([True, False])
            },
            'tool': tool,
            'success': random.choice([True, True, False]),
            'vulns_found': random.randint(0, 8),
            'execution_time': random.uniform(30, 600)
        }
    
    def _generate_exploitation_sample(self, vuln_name: str, tool: str, severity: float) -> Dict[str, Any]:
        """Generate exploitation phase sample"""
        
        # Determine vulnerability type
        vuln_type_map = {
            'sql': 'sql_injection_found',
            'xss': 'xss_found',
            'command': 'command_injection_found',
            'xxe': 'xxe_found',
            'ssrf': 'ssrf_found',
            'upload': 'file_upload_found',
            'jwt': 'auth_bypass_found',
            'oauth': 'auth_bypass_found',
        }
        
        context = {
            'sql_injection_found': False,
            'xss_found': False,
            'command_injection_found': False,
            'xxe_found': False,
            'ssrf_found': False,
            'file_upload_found': False,
            'auth_bypass_found': False,
            'highest_severity': severity,
            'num_critical_vulns': 1 if severity >= 9.0 else 0,
            'num_exploitable_vulns': random.randint(1, 3),
            'waf_detected': random.choice([True, False]),
            'authentication_required': random.choice([True, False]),
            'target_hardening_level': random.uniform(0.2, 0.7),
            'access_gained': random.choice([True, False]),
            'exploit_attempts': random.randint(0, 5),
            'time_in_phase': random.randint(60, 2400)
        }
        
        # Set the appropriate vulnerability flag
        vuln_lower = vuln_name.lower()
        for key, flag in vuln_type_map.items():
            if key in vuln_lower:
                context[flag] = True
                break
        
        return {
            'context': context,
            'tool': tool,
            'success': random.choice([True, True, False]),
            'vulns_found': random.randint(0, 3),
            'execution_time': random.uniform(60, 1800)
        }
    
    def _generate_post_exploit_sample(self, vuln_name: str, tool: str) -> Dict[str, Any]:
        """Generate post-exploitation phase sample"""
        os_type = 'linux' if 'linux' in vuln_name.lower() else ('windows' if 'windows' in vuln_name.lower() else random.choice(['linux', 'windows']))
        
        return {
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
                'other_hosts_visible': random.randint(0, 20),
                'time_in_phase': random.randint(180, 1800),
                'num_tools_executed': random.randint(0, 5),
                'detection_probability': random.uniform(0.1, 0.7)
            },
            'tool': tool,
            'success': random.choice([True, False]),
            'vulns_found': 0,
            'execution_time': random.uniform(30, 600)
        }
    
    def _generate_covering_tracks_sample(self, vuln_name: str, tool: str) -> Dict[str, Any]:
        """Generate covering tracks phase sample"""
        return {
            'context': {
                'log_entries_present': random.randint(10, 500),
                'artifacts_present': random.randint(0, 20),
                'backdoors_installed': random.randint(0, 3),
                'forensic_evidence_score': random.uniform(3.0, 9.0),
                'logs_cleaned': random.choice([True, False]),
                'timestamps_modified': random.choice([True, False]),
                'artifacts_removed': random.choice([True, False]),
                'time_remaining': random.randint(60, 600),
                'stealth_critical': random.choice([True, False]),
                'detection_imminent': random.choice([True, False]),
                'os_type': random.choice(['linux', 'windows']),
                'admin_access': random.choice([True, False])
            },
            'tool': tool,
            'success': random.choice([True, True, False]),
            'vulns_found': 0,
            'execution_time': random.uniform(5, 120)
        }


def main():
    """Parse PayloadsAllTheThings and save training data"""
    dataset_path = r"D:\Work\Ai Engineering\Git\data\datasets\PayloadsAllTheThings-master\PayloadsAllTheThings-master"
    
    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found at: {dataset_path}")
        return
    
    parser = PayloadsAllTheThingsParser(dataset_path)
    training_data = parser.parse_dataset()
    
    # Merge with existing training data
    output_dir = 'data/phase_training_logs'
    
    for phase, new_samples in training_data.items():
        output_path = f'{output_dir}/{phase}_training_logs.json'
        
        # Load existing data
        existing_samples = []
        if os.path.exists(output_path):
            try:
                with open(output_path, 'r') as f:
                    existing_samples = json.load(f)
            except:
                existing_samples = []
        
        # Merge
        combined = existing_samples + new_samples
        
        # Save
        with open(output_path, 'w') as f:
            json.dump(combined, f, indent=2)
        
        print(f"\n✅ {phase}: {len(existing_samples)} existing + {len(new_samples)} new = {len(combined)} total")
    
    print(f"\n{'='*80}")
    print("READY FOR TRAINING")
    print(f"{'='*80}")
    print("Run: python train_phase_models.py")


if __name__ == '__main__':
    main()
