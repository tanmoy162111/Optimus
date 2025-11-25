"""
Train ML/RL Models with Real Security Datasets
Uses CSIC, UNSW_NB15, NSL-KDD, and MITRE ATT&CK datasets
"""
import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
import json
from datetime import datetime

# Import our training modules
from training.feature_extractor import DatasetFeatureExtractor
from training.pattern_extractor import PatternExtractor
from training.model_trainer import SecurityMLTrainer
from training.rl_trainer import EnhancedRLAgent
from training.rl_state import RLStateEncoder

DATASET_BASE = r"D:\Work\Ai Engineering\Git\data\datasets"

class RealDataTrainer:
    def __init__(self):
        self.feature_extractor = DatasetFeatureExtractor()
        self.pattern_extractor = PatternExtractor()
        self.ml_trainer = SecurityMLTrainer()
        self.rl_state_encoder = RLStateEncoder()
        self.seclists_base = os.path.join(DATASET_BASE, "SecLists-master")
        
    def load_csic_http_attacks(self):
        """Load CSIC HTTP attack dataset (SQL injection, XSS, etc.)"""
        print("\n[1/4] Loading CSIC HTTP Attack Dataset...")
        
        csic_path = os.path.join(DATASET_BASE, "archive", "csic_database.csv")
        
        try:
            df = pd.read_csv(csic_path, low_memory=False)
            print(f"  [OK] Loaded {len(df)} HTTP requests")
            
            # Process samples
            vuln_examples = []
            attack_examples = []
            
            for idx, row in df.iterrows():
                if idx >= 5000:  # Limit for faster training
                    break
                
                # Construct HTTP request string
                url = str(row.get('URL', ''))
                method = str(row.get('Method', 'GET'))
                content = str(row.get('content', ''))
                label = row.get('classification', 0)
                
                request_str = f"{method} {url} {content}"
                
                # Extract features
                features = self.feature_extractor.extract_http_features(request_str)
                patterns = self.pattern_extractor.match_patterns(request_str)
                
                # Determine attack type
                attack_type = 'normal'
                if label == 1:  # Anomalous
                    if any(p in request_str.lower() for p in ['select', 'union', 'sql']):
                        attack_type = 'sql_injection'
                    elif any(p in request_str.lower() for p in ['script', 'alert', 'onerror']):
                        attack_type = 'xss'
                    elif any(p in request_str.lower() for p in ['../', '..\\', 'etc/passwd']):
                        attack_type = 'path_traversal'
                    else:
                        attack_type = 'injection'
                
                # Determine severity
                severity = 0.0 if attack_type == 'normal' else np.random.uniform(4.0, 9.5)
                
                vuln_example = {
                    'features': features,
                    'patterns': patterns,
                    'label': 1 if label == 1 else 0,  # Binary label for vuln detector
                    'is_vulnerable': 1 if label == 1 else 0,
                    'severity': severity,
                    'attack_type': attack_type,
                    'evidence': request_str[:200]
                }
                
                vuln_examples.append(vuln_example)
                
                if label == 1:
                    attack_examples.append({
                        'features': features,
                        'attack_type': attack_type
                    })
            
            print(f"  [OK] Processed {len(vuln_examples)} HTTP requests")
            print(f"  [OK] Found {len(attack_examples)} attack samples")
            
            return vuln_examples, attack_examples
            
        except Exception as e:
            print(f"  [ERROR] Error loading CSIC: {e}")
            return [], []
    
    def load_seclists_payloads(self):
        """Load SecLists attack payloads (XSS, SQLi, LFI, Command Injection)"""
        print("\n[2/4] Loading SecLists Attack Payloads...")
        
        vuln_examples = []
        attack_examples = []
        
        # Define payload files to load
        payload_files = [
            ('Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt', 'xss'),
            ('Fuzzing/XSS/robot-friendly/XSS-Somdev.txt', 'xss'),
            ('Fuzzing/Databases/SQLi/Generic-SQLi.txt', 'sql_injection'),
            ('Fuzzing/Databases/SQLi/quick-SQLi.txt', 'sql_injection'),
            ('Fuzzing/LFI/LFI-Jhaddix.txt', 'path_traversal'),
            ('Fuzzing/command-injection-commix.txt', 'rce'),
            ('Discovery/Web-Content/common.txt', 'reconnaissance'),
            ('Fuzzing/XXE-Fuzzing.txt', 'xxe'),
            ('Fuzzing/big-list-of-naughty-strings.txt', 'injection')
        ]
        
        total_loaded = 0
        
        for file_path, attack_type in payload_files:
            full_path = os.path.join(self.seclists_base, file_path)
            
            if not os.path.exists(full_path):
                print(f"  [SKIP] {file_path} not found")
                continue
            
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                # Limit samples per file
                payloads = payloads[:500]
                
                for payload in payloads:
                    # Create HTTP request context
                    request_str = f"GET /?param={payload} HTTP/1.1"
                    
                    # Extract features
                    features = self.feature_extractor.extract_http_features(request_str)
                    patterns = self.pattern_extractor.match_patterns(request_str)
                    
                    # Determine severity
                    severity_map = {
                        'xss': 7.5,
                        'sql_injection': 9.0,
                        'rce': 9.8,
                        'path_traversal': 7.0,
                        'reconnaissance': 3.0,
                        'xxe': 8.0
                    }
                    severity = severity_map.get(attack_type, 6.0)
                    
                    vuln_example = {
                        'features': features,
                        'patterns': patterns,
                        'label': 1,  # All payloads are malicious
                        'is_vulnerable': 1,
                        'severity': severity,
                        'attack_type': attack_type,
                        'evidence': payload[:200]
                    }
                    
                    vuln_examples.append(vuln_example)
                    attack_examples.append({
                        'features': features,
                        'attack_type': attack_type
                    })
                    
                    total_loaded += 1
                
                print(f"  [OK] Loaded {len(payloads)} {attack_type} payloads from {os.path.basename(file_path)}")
                
            except Exception as e:
                print(f"  [ERROR] Failed to load {file_path}: {e}")
        
        print(f"  [OK] Total SecLists payloads processed: {total_loaded}")
        return vuln_examples, attack_examples
    
    def load_exploitdb_vulnerabilities(self):
        """Load ExploitDB database of real-world exploits"""
        print("\n[3/4] Loading ExploitDB Vulnerability Database...")
        
        exploitdb_path = os.path.join(DATASET_BASE, "exploitdb-master", "files_exploits.csv")
        
        try:
            df = pd.read_csv(exploitdb_path, low_memory=False, encoding='utf-8', on_bad_lines='skip')
            print(f"  [OK] Loaded {len(df)} exploit records")
            
            vuln_examples = []
            attack_examples = []
            
            # Sample subset for training
            df_sample = df.sample(n=min(3000, len(df)), random_state=42)
            
            # Attack type mapping from exploit types
            type_mapping = {
                'webapps': 'webapp_exploit',
                'remote': 'rce',
                'local': 'privilege_escalation',
                'dos': 'dos',
                'shellcode': 'rce',
                'exploit': 'exploit'
            }
            
            # Platform severity mapping
            platform_severity = {
                'windows': 8.0,
                'linux': 8.0,
                'php': 7.5,
                'multiple': 8.5,
                'hardware': 9.0,
                'android': 7.0,
                'ios': 7.5
            }
            
            for idx, row in df_sample.iterrows():
                description = str(row.get('description', ''))
                exploit_type = str(row.get('type', 'exploit')).lower()
                platform = str(row.get('platform', 'unknown')).lower()
                codes = str(row.get('codes', ''))
                
                # Skip if no description
                if not description or description == 'nan':
                    continue
                
                # Create request context from description
                request_str = f"Exploit: {description[:200]}"
                
                # Extract features
                features = self.feature_extractor.extract_http_features(request_str)
                patterns = self.pattern_extractor.match_patterns(description)
                
                # Determine attack type
                attack_type = type_mapping.get(exploit_type, 'exploit')
                
                # Check for specific vulnerability types in description
                desc_lower = description.lower()
                if 'sql injection' in desc_lower or 'sqli' in desc_lower:
                    attack_type = 'sql_injection'
                elif 'xss' in desc_lower or 'cross-site scripting' in desc_lower:
                    attack_type = 'xss'
                elif 'remote code' in desc_lower or 'rce' in desc_lower:
                    attack_type = 'rce'
                elif 'buffer overflow' in desc_lower:
                    attack_type = 'buffer_overflow'
                elif 'csrf' in desc_lower or 'cross-site request' in desc_lower:
                    attack_type = 'csrf'
                elif 'path traversal' in desc_lower or 'directory traversal' in desc_lower:
                    attack_type = 'path_traversal'
                
                # Determine severity
                base_severity = platform_severity.get(platform, 7.0)
                
                # Increase severity if CVE codes present
                if 'cve' in codes.lower():
                    base_severity = min(base_severity + 1.0, 10.0)
                
                # Adjust by exploit type
                if exploit_type == 'remote' or exploit_type == 'shellcode':
                    base_severity = min(base_severity + 0.5, 10.0)
                elif exploit_type == 'dos':
                    base_severity = min(base_severity - 1.0, 10.0)
                
                severity = max(4.0, min(base_severity, 10.0))
                
                vuln_example = {
                    'features': features,
                    'patterns': patterns,
                    'label': 1,  # All exploits are vulnerabilities
                    'is_vulnerable': 1,
                    'severity': severity,
                    'attack_type': attack_type,
                    'evidence': description[:200]
                }
                
                vuln_examples.append(vuln_example)
                attack_examples.append({
                    'features': features,
                    'attack_type': attack_type
                })
            
            print(f"  [OK] Processed {len(vuln_examples)} exploit records")
            print(f"  [OK] Found {len(attack_examples)} attack patterns")
            
            return vuln_examples, attack_examples
            
        except Exception as e:
            print(f"  [ERROR] Error loading ExploitDB: {e}")
            import traceback
            traceback.print_exc()
            return [], []
    
    def load_cve_database(self):
        """Load CVE/CWE database with CVSS scores"""
        print("\n[4/5] Loading CVE/CWE Vulnerability Database...")
        
        cve_path = os.path.join(DATASET_BASE, "CVE", "CVE_CWE_2025.csv")
        
        try:
            df = pd.read_csv(cve_path, low_memory=False, encoding='utf-8', on_bad_lines='skip')
            print(f"  [OK] Loaded {len(df)} CVE records")
            
            vuln_examples = []
            attack_examples = []
            
            # Sample subset for training
            df_sample = df.sample(n=min(5000, len(df)), random_state=42)
            
            # CWE to attack type mapping (Common Weakness Enumeration)
            cwe_mapping = {
                'CWE-79': 'xss',  # Cross-site Scripting
                'CWE-89': 'sql_injection',  # SQL Injection
                'CWE-78': 'rce',  # OS Command Injection
                'CWE-94': 'rce',  # Code Injection
                'CWE-22': 'path_traversal',  # Path Traversal
                'CWE-352': 'csrf',  # Cross-Site Request Forgery
                'CWE-434': 'file_upload',  # Unrestricted File Upload
                'CWE-120': 'buffer_overflow',  # Buffer Overflow
                'CWE-119': 'buffer_overflow',  # Memory Corruption
                'CWE-200': 'info_disclosure',  # Information Exposure
                'CWE-287': 'auth_bypass',  # Improper Authentication
                'CWE-306': 'auth_bypass',  # Missing Authentication
                'CWE-862': 'privilege_escalation',  # Missing Authorization
                'CWE-798': 'hardcoded_credentials',  # Use of Hard-coded Credentials
                'CWE-502': 'deserialization',  # Deserialization of Untrusted Data
                'CWE-611': 'xxe',  # XML External Entity
                'CWE-918': 'ssrf',  # Server-Side Request Forgery
                'CWE-601': 'open_redirect',  # URL Redirection
            }
            
            for idx, row in df_sample.iterrows():
                cve_id = str(row.get('CVE-ID', ''))
                description = str(row.get('DESCRIPTION', ''))
                cwe_id = str(row.get('CWE-ID', ''))
                severity_str = str(row.get('SEVERITY', 'MEDIUM')).upper()
                
                # Get CVSS scores (prefer V3, then V2)
                cvss_v3 = row.get('CVSS-V3', None)
                cvss_v2 = row.get('CVSS-V2', None)
                cvss_v4 = row.get('CVSS-V4', None)
                
                # Skip if no description
                if not description or description == 'nan' or len(description) < 10:
                    continue
                
                # Parse CVSS score
                cvss_score = None
                if pd.notna(cvss_v4):
                    try:
                        cvss_score = float(cvss_v4)
                    except:
                        pass
                if cvss_score is None and pd.notna(cvss_v3):
                    try:
                        cvss_score = float(cvss_v3)
                    except:
                        pass
                if cvss_score is None and pd.notna(cvss_v2):
                    try:
                        cvss_score = float(cvss_v2)
                    except:
                        pass
                
                # Map severity to score if CVSS not available
                if cvss_score is None:
                    severity_scores = {
                        'CRITICAL': 9.5,
                        'HIGH': 8.0,
                        'MEDIUM': 6.0,
                        'LOW': 3.0,
                        'NONE': 0.0
                    }
                    cvss_score = severity_scores.get(severity_str, 5.0)
                
                # Ensure score is in valid range
                cvss_score = max(0.0, min(cvss_score, 10.0))
                
                # Determine attack type from CWE
                attack_type = cwe_mapping.get(cwe_id, None)
                
                # If no CWE mapping, try to infer from description
                if attack_type is None:
                    desc_lower = description.lower()
                    if 'sql injection' in desc_lower or 'sqli' in desc_lower:
                        attack_type = 'sql_injection'
                    elif 'cross-site scripting' in desc_lower or 'xss' in desc_lower:
                        attack_type = 'xss'
                    elif 'remote code' in desc_lower or 'rce' in desc_lower:
                        attack_type = 'rce'
                    elif 'buffer overflow' in desc_lower:
                        attack_type = 'buffer_overflow'
                    elif 'csrf' in desc_lower:
                        attack_type = 'csrf'
                    elif 'path traversal' in desc_lower or 'directory traversal' in desc_lower:
                        attack_type = 'path_traversal'
                    elif 'denial of service' in desc_lower or 'dos' in desc_lower:
                        attack_type = 'dos'
                    elif 'authentication' in desc_lower:
                        attack_type = 'auth_bypass'
                    elif 'privilege' in desc_lower:
                        attack_type = 'privilege_escalation'
                    else:
                        attack_type = 'exploit'
                
                # Create request context from CVE description
                request_str = f"CVE {cve_id}: {description[:200]}"
                
                # Extract features
                features = self.feature_extractor.extract_http_features(request_str)
                patterns = self.pattern_extractor.match_patterns(description)
                
                vuln_example = {
                    'features': features,
                    'patterns': patterns,
                    'label': 1,  # All CVEs are vulnerabilities
                    'is_vulnerable': 1,
                    'severity': cvss_score,
                    'attack_type': attack_type,
                    'evidence': f"{cve_id}: {description[:150]}"
                }
                
                vuln_examples.append(vuln_example)
                attack_examples.append({
                    'features': features,
                    'attack_type': attack_type
                })
            
            print(f"  [OK] Processed {len(vuln_examples)} CVE records")
            print(f"  [OK] Found {len(attack_examples)} vulnerability patterns")
            
            return vuln_examples, attack_examples
            
        except Exception as e:
            print(f"  [ERROR] Error loading CVE database: {e}")
            import traceback
            traceback.print_exc()
            return [], []
    
    def load_unsw_nb15_network_attacks(self):
        """Load UNSW-NB15 network attack dataset"""
        print("\n[5/5] Loading UNSW-NB15 Network Attack Dataset...")
        
        train_path = os.path.join(DATASET_BASE, "UNSW_NB15", "UNSW_NB15_training-set.csv")
        
        try:
            df = pd.read_csv(train_path, low_memory=False)
            print(f"  [OK] Loaded {len(df)} network flows")
            
            vuln_examples = []
            attack_examples = []
            
            # Sample subset
            df_sample = df.sample(n=min(3000, len(df)), random_state=42)
            
            for idx, row in df_sample.iterrows():
                attack_cat = str(row.get('attack_cat', 'Normal'))
                label = int(row.get('label', 0))
                
                # Create pseudo-HTTP request for feature extraction
                proto = row.get('proto', 'tcp')
                service = row.get('service', '-')
                sbytes = row.get('sbytes', 0)
                dbytes = row.get('dbytes', 0)
                
                request_str = f"{proto.upper()} /{service} bytes={sbytes},{dbytes}"
                
                features = self.feature_extractor.extract_http_features(request_str)
                
                # Map attack categories
                attack_type_map = {
                    'Normal': 'normal',
                    'Fuzzers': 'fuzzing',
                    'Analysis': 'reconnaissance',
                    'Backdoor': 'backdoor',
                    'DoS': 'dos',
                    'Exploits': 'exploit',
                    'Generic': 'generic_attack',
                    'Reconnaissance': 'reconnaissance',
                    'Shellcode': 'rce',
                    'Worms': 'worm'
                }
                
                attack_type = attack_type_map.get(attack_cat, 'generic_attack')
                
                # Calculate severity based on attack type
                severity_map = {
                    'normal': 0.0,
                    'reconnaissance': 3.5,
                    'dos': 7.0,
                    'exploit': 8.5,
                    'rce': 9.5,
                    'backdoor': 9.0,
                    'worm': 8.0
                }
                severity = severity_map.get(attack_type, 5.0)
                
                vuln_example = {
                    'features': features,
                    'patterns': {},
                    'label': label,  # Binary label for vuln detector
                    'is_vulnerable': label,
                    'severity': severity,
                    'attack_type': attack_type,
                    'evidence': f"Network flow: {proto}/{service}"
                }
                
                vuln_examples.append(vuln_example)
                
                if label == 1:
                    attack_examples.append({
                        'features': features,
                        'attack_type': attack_type
                    })
            
            print(f"  [OK] Processed {len(vuln_examples)} network flows")
            print(f"  [OK] Found {len(attack_examples)} attack flows")
            
            return vuln_examples, attack_examples
            
        except Exception as e:
            print(f"  [ERROR] Error loading UNSW-NB15: {e}")
            return [], []
    
    def train_ml_models(self, vuln_examples, attack_examples):
        """Train all ML models"""
        print("\n[6/7] Training Machine Learning Models...")
        
        # Train vulnerability detector
        print("  Training Vulnerability Detector...")
        vuln_result = self.ml_trainer.train_vulnerability_detector(vuln_examples)
        print(f"    F1 Score: {vuln_result['metrics']['f1']:.4f}")
        print(f"    Accuracy: {vuln_result['metrics']['accuracy']:.4f}")
        
        # Train attack classifier
        print("  Training Attack Classifier...")
        attack_result = self.ml_trainer.train_attack_classifier(attack_examples)
        print(f"    F1 Score: {attack_result['metrics']['f1']:.4f}")
        print(f"    Accuracy: {attack_result['metrics']['accuracy']:.4f}")
        
        # Train severity predictor
        print("  Training Severity Predictor...")
        severity_result = self.ml_trainer.train_severity_predictor(vuln_examples)
        print(f"    R² Score: {severity_result['metrics']['r2']:.4f}")
        print(f"    MAE: {severity_result['metrics']['mae']:.4f}")
        
        # Create tool execution logs for tool recommender
        print("  Creating tool execution logs...")
        tool_logs = []
        tool_names = ['nmap', 'nikto', 'sqlmap', 'metasploit', 'burpsuite', 'wpscan', 'dirb', 'hydra']
        
        for idx, vuln in enumerate(vuln_examples[:1000]):  # Sample subset
            attack_type = vuln.get('attack_type', 'normal')
            severity = vuln.get('severity', 0.0)
            
            # Map attack types to appropriate tools with some variation
            tool_map = {
                'sql_injection': ['sqlmap', 'burpsuite', 'sqlmap'],
                'xss': ['burpsuite', 'dalfox', 'burpsuite'],
                'reconnaissance': ['nmap', 'nikto', 'wpscan'],
                'dos': ['nmap', 'nikto', 'nmap'],
                'exploit': ['metasploit', 'burpsuite', 'metasploit'],
                'rce': ['metasploit', 'commix', 'metasploit'],
                'backdoor': ['metasploit', 'nmap', 'metasploit'],
                'normal': ['nikto', 'nmap', 'dirb', 'wpscan'],
                'fuzzing': ['burpsuite', 'dirb', 'nikto'],
                'worm': ['nmap', 'metasploit', 'nmap'],
                'generic_attack': ['nmap', 'nikto', 'metasploit']
            }
            
            # Add variety by rotating through tool options
            tools_for_type = tool_map.get(attack_type, ['nikto', 'nmap'])
            tool_name = tools_for_type[idx % len(tools_for_type)]
            
            tool_log = {
                'context': {
                    'attack_type': attack_type,
                    'severity': severity,
                    'phase': 'exploitation' if severity >= 7.0 else 'scanning'
                },
                'tool_name': tool_name
            }
            tool_logs.append(tool_log)
        
        # Train tool recommender
        print("  Training Tool Recommender...")
        tool_result = self.ml_trainer.train_tool_recommender(tool_logs)
        print(f"    Score: {tool_result['metrics']['accuracy']:.4f}")
        
        # Save models
        print("  Saving models...")
        self.ml_trainer.save_model(vuln_result, 'vuln_detector')
        self.ml_trainer.save_model(attack_result, 'attack_classifier')
        self.ml_trainer.save_model(severity_result, 'severity_predictor')
        self.ml_trainer.save_model(tool_result, 'tool_recommender')
        print("  [OK] All ML models saved to ./models/")
        
        return {
            'vuln_detector': vuln_result['metrics'],
            'attack_classifier': attack_result['metrics'],
            'severity_predictor': severity_result['metrics'],
            'tool_recommender': tool_result['metrics']
        }
    
    def train_rl_agent(self, vuln_examples):
        """Train RL agent for tool selection"""
        print("\n[7/7] Training Reinforcement Learning Agent...")
        
        # Initialize RL agent
        rl_agent = EnhancedRLAgent(
            state_dim=23,
            num_actions=20,
            learning_rate=0.001
        )
        
        # Create episodes from vulnerability examples
        episodes = []
        tool_options = ['nmap', 'nikto', 'sqlmap', 'metasploit', 'burpsuite', 'dirb', 'hydra', 'wpscan']
        
        for episode_idx in range(50):  # Create 50 episodes
            episode_data = np.random.choice(vuln_examples, size=min(10, len(vuln_examples)), replace=False)
            
            episode = {
                'scan_id': f'training_{episode_idx}',
                'transitions': []
            }
            
            for vuln in episode_data:
                # Create state
                state = {
                    'target_type': 'web',
                    'target_complexity': 0.5,
                    'current_phase': 'exploitation',
                    'num_vulns_found': 1 if vuln['label'] else 0,
                    'highest_severity': vuln['severity'],
                    'avg_severity': vuln['severity'],
                    'total_exploitable': 1 if vuln['label'] else 0,
                    'critical_count': 1 if vuln['severity'] >= 9.0 else 0,
                    'high_count': 1 if 7.0 <= vuln['severity'] < 9.0 else 0,
                    'medium_count': 1 if 4.0 <= vuln['severity'] < 7.0 else 0,
                    'time_elapsed': 0.3,
                    'time_remaining': 0.7,
                    'num_tools_used': 2,
                    'ml_confidence': 0.8,
                    'scan_coverage': 0.6,
                    'sql_detected': vuln['attack_type'] == 'sql_injection',
                    'xss_detected': vuln['attack_type'] == 'xss',
                    'rce_detected': vuln['attack_type'] == 'rce'
                }
                
                # Map attack type to appropriate tool
                tool_map = {
                    'sql_injection': 'sqlmap',
                    'xss': 'burpsuite',
                    'rce': 'metasploit',
                    'normal': 'nikto'
                }
                tool_used = tool_map.get(vuln['attack_type'], 'nmap')
                
                # Create action result
                action_result = {
                    'vulns_found': [{'severity': vuln['severity'], 'exploitable': vuln['label']}] if vuln['label'] else [],
                    'time_taken': 0.1,
                    'detected': False
                }
                
                # Calculate reward
                reward = rl_agent.calculate_reward(action_result)
                
                # Next state (slightly progressed)
                next_state = state.copy()
                next_state['num_tools_used'] += 1
                next_state['scan_coverage'] += 0.1
                
                episode['transitions'].append({
                    'state': state,
                    'tool_used': tool_used,
                    'reward': reward,
                    'next_state': next_state
                })
            
            episodes.append(episode)
        
        # Train from episodes
        print(f"  Training on {len(episodes)} episodes...")
        rl_metrics = rl_agent.train_from_episodes(episodes)
        
        # Save RL agent
        rl_agent.save_model('./models/rl_agent.weights.h5')
        print("  [OK] RL agent saved to ./models/rl_agent.weights.h5")
        
        return rl_metrics
    
    def save_training_state(self, ml_metrics, rl_metrics):
        """Save training state to JSON"""
        state = {
            'timestamp': datetime.now().isoformat(),
            'ml_metrics': ml_metrics,
            'rl_metrics': rl_metrics,
            'datasets_used': ['CSIC', 'SecLists', 'ExploitDB', 'CVE/CWE', 'UNSW-NB15']
        }
        
        os.makedirs('data', exist_ok=True)
        with open('data/ml_training_state.json', 'w') as f:
            json.dump(state, f, indent=2)
        
        print("\n[OK] Training state saved to data/ml_training_state.json")

def main():
    print("=" * 80)
    print("Optimus - Real Dataset Training")
    print("CSIC + SecLists + ExploitDB + CVE/CWE + UNSW-NB15")
    print("=" * 80)
    
    trainer = RealDataTrainer()
    
    # Load datasets
    csic_vuln, csic_attack = trainer.load_csic_http_attacks()
    seclists_vuln, seclists_attack = trainer.load_seclists_payloads()
    exploitdb_vuln, exploitdb_attack = trainer.load_exploitdb_vulnerabilities()
    cve_vuln, cve_attack = trainer.load_cve_database()
    unsw_vuln, unsw_attack = trainer.load_unsw_nb15_network_attacks()
    
    # Combine datasets
    all_vuln_examples = csic_vuln + seclists_vuln + exploitdb_vuln + cve_vuln + unsw_vuln
    all_attack_examples = csic_attack + seclists_attack + exploitdb_attack + cve_attack + unsw_attack
    
    print(f"\nTotal vulnerability examples: {len(all_vuln_examples)}")
    print(f"Total attack examples: {len(all_attack_examples)}")
    
    if len(all_vuln_examples) == 0:
        print("\n[ERROR] No data loaded. Check dataset paths.")
        return 1
    
    # Train ML models
    ml_metrics = trainer.train_ml_models(all_vuln_examples, all_attack_examples)
    
    # Train RL agent
    rl_metrics = trainer.train_rl_agent(all_vuln_examples)
    
    # Save state
    trainer.save_training_state(ml_metrics, rl_metrics)
    
    print("\n" + "=" * 70)
    print("[SUCCESS] Training Complete!")
    print("=" * 70)
    print("\nModel Performance Summary:")
    print(f"  Vulnerability Detector F1: {ml_metrics['vuln_detector']['f1']:.4f}")
    print(f"  Attack Classifier F1: {ml_metrics['attack_classifier']['f1']:.4f}")
    print(f"  Severity Predictor R²: {ml_metrics['severity_predictor']['r2']:.4f}")
    print(f"  RL Agent Episodes: {rl_metrics.get('episodes_trained', 50)}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
