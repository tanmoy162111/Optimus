"""Train all phase-specific models"""
import sys
sys.path.append('..')
from training.phase_specific_models import PhaseSpecificModelTrainer
import json
import random
from collections import Counter

def generate_synthetic_training_data():
    """
    Generate synthetic training logs for each phase
    (In production, this would come from real scan data)
    """
    print("Generating synthetic training data...")
    
    training_data = {
        'reconnaissance': [],
        'scanning': [],
        'exploitation': [],
        'post_exploitation': [],
        'covering_tracks': []
    }
    
    # Reconnaissance tools and their typical contexts
    recon_tools = ['sublist3r', 'theHarvester', 'whatweb', 'shodan', 'dnsenum', 'fierce', 'builtwith', 'amass']
    for _ in range(80):
        passive_complete = random.choice([True, False])
        tool = random.choice(recon_tools[:4] if not passive_complete else recon_tools)
        
        training_data['reconnaissance'].append({
            'context': {
                'target_type': random.choice(['web', 'api', 'network']),
                'domain_complexity': random.uniform(0.3, 0.9),
                'passive_recon_complete': passive_complete,
                'active_recon_started': passive_complete,
                'subdomains_discovered': random.randint(0, 50) if passive_complete else 0,
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
            'success': random.choice([True, True, True, False]),
            'vulns_found': 0,
            'execution_time': random.uniform(10, 300)
        })
    
    # Scanning tools
    scan_tools = ['nmap', 'nuclei', 'nikto', 'wpscan', 'sslscan', 'enum4linux']
    for _ in range(70):
        has_wordpress = random.choice([True, False])
        tool = 'wpscan' if has_wordpress and random.random() > 0.3 else random.choice(scan_tools)
        
        training_data['scanning'].append({
            'context': {
                'target_type': 'web',
                'technologies_known': random.randint(0, 10),
                'subdomains_count': random.randint(1, 30),
                'open_ports_found': random.randint(0, 20),
                'scan_coverage': random.uniform(0.2, 0.9),
                'vulnerabilities_found': random.randint(0, 15),
                'services_enumerated': random.randint(0, 10),
                'wordpress_detected': has_wordpress,
                'joomla_detected': random.choice([True, False]) if not has_wordpress else False,
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
        })
    
    # Exploitation tools
    exploit_tools = ['sqlmap', 'metasploit', 'dalfox', 'hydra', 'commix', 'xsser']
    for _ in range(60):
        has_sqli = random.choice([True, False])
        has_xss = random.choice([True, False])
        tool = 'sqlmap' if has_sqli else ('dalfox' if has_xss else random.choice(exploit_tools))
        
        training_data['exploitation'].append({
            'context': {
                'sql_injection_found': has_sqli,
                'xss_found': has_xss,
                'command_injection_found': random.choice([True, False]),
                'xxe_found': random.choice([True, False]),
                'ssrf_found': random.choice([True, False]),
                'file_upload_found': random.choice([True, False]),
                'auth_bypass_found': random.choice([True, False]),
                'highest_severity': random.uniform(5.0, 10.0),
                'num_critical_vulns': random.randint(0, 5),
                'num_exploitable_vulns': random.randint(0, 8),
                'waf_detected': random.choice([True, False]),
                'authentication_required': random.choice([True, False]),
                'target_hardening_level': random.uniform(0.2, 0.8),
                'access_gained': random.choice([True, False]),
                'exploit_attempts': random.randint(1, 10),
                'time_in_phase': random.randint(300, 3600)
            },
            'tool': tool,
            'success': random.choice([True, False, False]),
            'vulns_found': random.randint(0, 3),
            'execution_time': random.uniform(60, 1200)
        })
    
    # Post-exploitation tools
    post_tools = ['linpeas', 'winpeas', 'mimikatz', 'lazagne', 'bloodhound', 'crackmapexec']
    for _ in range(50):
        os_type = random.choice(['linux', 'windows'])
        tool = 'linpeas' if os_type == 'linux' else ('winpeas' if random.random() > 0.5 else random.choice(post_tools))
        
        training_data['post_exploitation'].append({
            'context': {
                'current_user_privilege': random.choice(['user', 'admin', 'root']),
                'os_type': os_type,
                'os_version': f"{random.choice(['Ubuntu 20.04', 'Windows 10', 'Windows Server 2019'])}",
                'privilege_escalated': random.choice([True, False]),
                'persistence_established': random.choice([True, False]),
                'credentials_dumped': random.choice([True, False]),
                'lateral_movement_success': random.choice([True, False]),
                'domain_joined': random.choice([True, False]),
                'antivirus_detected': random.choice([True, False]),
                'edr_detected': random.choice([True, False]),
                'other_hosts_visible': random.randint(0, 20),
                'time_in_phase': random.randint(300, 1800),
                'num_tools_executed': random.randint(1, 6),
                'detection_probability': random.uniform(0.1, 0.7)
            },
            'tool': tool,
            'success': random.choice([True, True, False]),
            'vulns_found': 0,
            'execution_time': random.uniform(30, 600)
        })
    
    # Covering tracks tools
    cleanup_tools = ['clear_logs', 'timestomp', 'shred', 'wevtutil', 'log_wiper']
    for _ in range(40):
        os_type = random.choice(['linux', 'windows'])
        tool = random.choice(cleanup_tools)
        
        training_data['covering_tracks'].append({
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
                'os_type': os_type,
                'admin_access': random.choice([True, False])
            },
            'tool': tool,
            'success': random.choice([True, True, False]),
            'vulns_found': 0,
            'execution_time': random.uniform(5, 120)
        })
    
    # Print statistics
    print("\nGenerated Training Data:")
    for phase, logs in training_data.items():
        tool_counts = Counter(log['tool'] for log in logs)
        print(f"  {phase:20s}: {len(logs):3d} samples, {len(tool_counts)} unique tools")
    
    return training_data

def load_phase_training_data():
    """
    Load collected training logs for each phase and augment with synthetic data
    (Combines real PortSwigger data with synthetic data for better coverage)
    """
    training_data = {}
    
    phases = ['reconnaissance', 'scanning', 'exploitation',
              'post_exploitation', 'covering_tracks']
    
    # Try to load real data
    real_data_found = False
    for phase in phases:
        try:
            with open(f'data/phase_training_logs/{phase}_training_logs.json') as f:
                training_data[phase] = json.load(f)
            print(f"✅ Loaded {len(training_data[phase])} real samples for {phase}")
            real_data_found = True
        except FileNotFoundError:
            training_data[phase] = []
    
    # Augment with synthetic data for better model training
    if real_data_found:
        print("\n📊 Augmenting with synthetic data for better coverage...")
        synthetic_data = generate_synthetic_training_data()
        
        for phase in phases:
            original_count = len(training_data[phase])
            training_data[phase].extend(synthetic_data[phase])
            total_count = len(training_data[phase])
            print(f"  {phase:20s}: {original_count:3d} real + {total_count-original_count:3d} synthetic = {total_count:3d} total")
    else:
        print("\n⚠️  No real training data found, using only synthetic data...")
        training_data = generate_synthetic_training_data()
    
    return training_data

def main():
    """
    Train all phase-specific models
    """
    print("\n" + "="*80)
    print("TRAINING PHASE-SPECIFIC TOOL RECOMMENDER MODELS")
    print("="*80 + "\n")
    
    # Load training data
    print("Loading training data...")
    training_data = load_phase_training_data()
    
    # Train models
    trainer = PhaseSpecificModelTrainer()
    models = trainer.train_all_phase_models(training_data)
    
    # Summary
    print("\n" + "="*80)
    print("TRAINING SUMMARY")
    print("="*80)
    
    if not models:
        print("❌ No models were trained!")
        return
    
    total_accuracy = 0
    for phase, model_data in models.items():
        accuracy = model_data['cv_accuracy']
        total_accuracy += accuracy
        
        status = "✅ GOOD" if accuracy >= 0.70 else "⚠️  NEEDS MORE DATA"
        print(f"{phase:20s}: {accuracy:.1%} accuracy - {status}")
    
    avg_accuracy = total_accuracy / len(models) if models else 0
    print(f"\n{'Average Accuracy':20s}: {avg_accuracy:.1%}")
    
    if avg_accuracy >= 0.75:
        print("\n✅ ALL MODELS APPROVED FOR PRODUCTION")
    elif avg_accuracy >= 0.65:
        print("\n⚠️  MODELS USABLE BUT NEED MORE TRAINING DATA")
    else:
        print("\n❌ MODELS NEED SIGNIFICANTLY MORE TRAINING DATA")

if __name__ == '__main__':
    main()
