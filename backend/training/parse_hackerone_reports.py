"""Parse HackerOne bug bounty reports dataset"""
import os
import csv
import json
import random
from typing import Dict, List, Any
from collections import defaultdict

class HackerOneReportsParser:
    """Parse HackerOne bug bounty reports CSV dataset"""
    
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        
        # Map vulnerability types to phases and tools
        self.vuln_to_phase_tool = {
            'SQL Injection': ('exploitation', 'sqlmap'),
            'Cross-site Scripting (XSS)': ('exploitation', 'dalfox'),
            'XSS': ('exploitation', 'dalfox'),
            'Command Injection': ('exploitation', 'commix'),
            'Server-Side Request Forgery (SSRF)': ('scanning', 'ssrfmap'),
            'SSRF': ('scanning', 'ssrfmap'),
            'XML External Entities (XXE)': ('exploitation', 'xxeinjector'),
            'XXE': ('exploitation', 'xxeinjector'),
            'Insecure Deserialization': ('exploitation', 'ysoserial'),
            'Remote Code Execution': ('exploitation', 'metasploit'),
            'RCE': ('exploitation', 'metasploit'),
            'CSRF': ('exploitation', 'burp'),
            'Open Redirect': ('scanning', 'openredirex'),
            'Authentication Bypass': ('exploitation', 'hydra'),
            'Improper Authorization': ('exploitation', 'burp'),
            'Access Control': ('scanning', 'nuclei'),
            'Privilege Escalation': ('post_exploitation', 'linpeas'),
            'Information Disclosure': ('scanning', 'nuclei'),
            'Path Traversal': ('scanning', 'dirb'),
            'File Upload': ('exploitation', 'weevely'),
            'Business Logic': ('scanning', 'burp'),
            'Race Condition': ('exploitation', 'turbo-intruder'),
            'Denial of Service': ('scanning', 'nuclei'),
            'Code Injection': ('exploitation', 'commix'),
            'Cryptographic Issues': ('scanning', 'sslscan'),
            'Memory Corruption': ('exploitation', 'metasploit'),
            'Improper Certificate Validation': ('scanning', 'sslscan'),
        }
        
        # Severity estimation
        self.severity_map = {
            'SQL Injection': 9.0,
            'Remote Code Execution': 10.0,
            'Command Injection': 9.5,
            'XXE': 8.5,
            'SSRF': 8.0,
            'Deserialization': 9.0,
            'XSS': 7.0,
            'CSRF': 6.5,
            'Authentication Bypass': 8.5,
            'Privilege Escalation': 8.0,
            'Path Traversal': 7.5,
            'File Upload': 8.5,
            'Open Redirect': 5.5,
            'Information Disclosure': 6.0,
        }
    
    def parse_dataset(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parse CSV file and generate training data"""
        print("="*80)
        print("PARSING HACKERONE BUG BOUNTY REPORTS DATASET")
        print("="*80)
        print(f"Dataset: {self.csv_path}\n")
        
        training_data = {
            'reconnaissance': [],
            'scanning': [],
            'exploitation': [],
            'post_exploitation': [],
            'covering_tracks': []
        }
        
        vuln_counts = defaultdict(int)
        
        # Read CSV
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                vuln_type = row.get('vuln_type', '').strip()
                title = row.get('title', '').strip()
                bounty = row.get('bounty', '0.0')
                
                if not vuln_type and not title:
                    continue
                
                # Get phase and tool mapping
                phase, tool = self._map_vuln_to_phase_tool(vuln_type, title)
                
                if phase:
                    # Generate training sample
                    severity = self._estimate_severity(vuln_type, title, bounty)
                    sample = self._generate_sample(vuln_type, title, phase, tool, severity)
                    training_data[phase].append(sample)
                    vuln_counts[vuln_type] += 1
        
        # Print statistics
        print("\nTop 20 Vulnerability Types:")
        for vuln_type, count in sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            if vuln_type:
                print(f"  {vuln_type:50s}: {count:4d} reports")
        
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
    
    def _map_vuln_to_phase_tool(self, vuln_type: str, title: str) -> tuple:
        """Map vulnerability to phase and tool"""
        
        # Direct mapping
        if vuln_type in self.vuln_to_phase_tool:
            return self.vuln_to_phase_tool[vuln_type]
        
        # Fuzzy matching on vuln_type and title
        combined = (vuln_type + ' ' + title).lower()
        
        if any(word in combined for word in ['sql', 'sqli', 'sql injection']):
            return ('exploitation', 'sqlmap')
        elif any(word in combined for word in ['xss', 'cross-site scripting', 'script injection']):
            return ('exploitation', 'dalfox')
        elif any(word in combined for word in ['command injection', 'rce', 'remote code', 'code execution']):
            return ('exploitation', 'commix')
        elif any(word in combined for word in ['ssrf', 'server-side request']):
            return ('scanning', 'ssrfmap')
        elif any(word in combined for word in ['xxe', 'xml external']):
            return ('exploitation', 'xxeinjector')
        elif any(word in combined for word in ['deserialize', 'deserialization']):
            return ('exploitation', 'ysoserial')
        elif any(word in combined for word in ['file upload', 'upload']):
            return ('exploitation', 'weevely')
        elif any(word in combined for word in ['path traversal', 'directory traversal', 'lfi']):
            return ('scanning', 'nuclei')
        elif any(word in combined for word in ['authentication', 'auth bypass', 'broken auth']):
            return ('exploitation', 'hydra')
        elif any(word in combined for word in ['privilege escalation', 'privesc']):
            return ('post_exploitation', 'linpeas')
        elif any(word in combined for word in ['csrf', 'cross-site request']):
            return ('exploitation', 'burp')
        elif any(word in combined for word in ['open redirect', 'url redirect']):
            return ('scanning', 'openredirex')
        elif any(word in combined for word in ['information disclosure', 'sensitive data']):
            return ('scanning', 'nuclei')
        
        # Default to scanning
        return ('scanning', 'nuclei')
    
    def _estimate_severity(self, vuln_type: str, title: str, bounty: str) -> float:
        """Estimate vulnerability severity"""
        
        # Base severity from type
        for key, severity in self.severity_map.items():
            if key.lower() in vuln_type.lower() or key.lower() in title.lower():
                # Adjust based on bounty
                try:
                    bounty_val = float(bounty)
                    if bounty_val > 5000:
                        severity = min(10.0, severity + 1.0)
                    elif bounty_val > 1000:
                        severity = min(10.0, severity + 0.5)
                except:
                    pass
                
                return severity
        
        # Default severity
        return 6.0
    
    def _generate_sample(self, vuln_type: str, title: str, phase: str, 
                        tool: str, severity: float) -> Dict[str, Any]:
        """Generate training sample"""
        
        if phase == 'reconnaissance':
            return self._generate_recon_sample(tool)
        elif phase == 'scanning':
            return self._generate_scanning_sample(tool, severity)
        elif phase == 'exploitation':
            return self._generate_exploitation_sample(vuln_type, title, tool, severity)
        elif phase == 'post_exploitation':
            return self._generate_post_exploit_sample(tool)
        else:  # covering_tracks
            return self._generate_covering_tracks_sample(tool)
    
    def _generate_recon_sample(self, tool: str) -> Dict[str, Any]:
        """Generate reconnaissance sample"""
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
    
    def _generate_scanning_sample(self, tool: str, severity: float) -> Dict[str, Any]:
        """Generate scanning sample"""
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
    
    def _generate_exploitation_sample(self, vuln_type: str, title: str,
                                     tool: str, severity: float) -> Dict[str, Any]:
        """Generate exploitation sample"""
        
        vuln_lower = (vuln_type + ' ' + title).lower()
        
        context = {
            'sql_injection_found': 'sql' in vuln_lower,
            'xss_found': 'xss' in vuln_lower or 'cross-site scripting' in vuln_lower,
            'command_injection_found': 'command' in vuln_lower or 'rce' in vuln_lower,
            'xxe_found': 'xxe' in vuln_lower or 'xml' in vuln_lower,
            'ssrf_found': 'ssrf' in vuln_lower,
            'file_upload_found': 'upload' in vuln_lower,
            'auth_bypass_found': 'auth' in vuln_lower or 'bypass' in vuln_lower,
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
        
        return {
            'context': context,
            'tool': tool,
            'success': random.choice([True, True, False]),
            'vulns_found': random.randint(0, 3),
            'execution_time': random.uniform(60, 1800)
        }
    
    def _generate_post_exploit_sample(self, tool: str) -> Dict[str, Any]:
        """Generate post-exploitation sample"""
        return {
            'context': {
                'current_user_privilege': random.choice(['user', 'admin', 'root']),
                'os_type': random.choice(['linux', 'windows']),
                'os_version': 'Ubuntu 20.04',
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
    
    def _generate_covering_tracks_sample(self, tool: str) -> Dict[str, Any]:
        """Generate covering tracks sample"""
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
    """Parse HackerOne reports and merge with existing training data"""
    csv_path = r"D:\Work\Ai Engineering\Git\data\datasets\hackerone-reports-master\hackerone-reports-master\data.csv"
    
    if not os.path.exists(csv_path):
        print(f"❌ Dataset not found at: {csv_path}")
        return
    
    parser = HackerOneReportsParser(csv_path)
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
