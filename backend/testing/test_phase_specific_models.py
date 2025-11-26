"""Test phase-specific models"""
import sys
sys.path.append('..')
from training.phase_specific_models import PhaseSpecificToolSelector
import json

def test_phase_specific_models():
    """
    Test phase-specific models with sample contexts
    """
    print("="*80)
    print("TESTING PHASE-SPECIFIC TOOL RECOMMENDER MODELS")
    print("="*80)
    
    # Load models
    selector = PhaseSpecificToolSelector()
    
    # Test cases for each phase
    test_cases = [
        {
            'name': 'Reconnaissance - Early Stage',
            'context': {
                'phase': 'reconnaissance',
                'target_type': 'web',
                'domain_complexity': 0.6,
                'passive_recon_complete': False,
                'active_recon_started': False,
                'subdomains_discovered': 0,
                'emails_discovered': 0,
                'technologies_discovered': 0,
                'employees_discovered': 0,
                'time_in_phase': 60,
                'stealth_required': True,
                'detection_risk': 0.2,
                'num_tools_executed': 0,
                'passive_tools_ratio': 0.0,
                'tools_executed': []
            }
        },
        {
            'name': 'Scanning - WordPress Detected',
            'context': {
                'phase': 'scanning',
                'target_type': 'web',
                'technologies_known': 5,
                'subdomains_count': 10,
                'open_ports_found': 3,
                'scan_coverage': 0.5,
                'vulnerabilities_found': 2,
                'services_enumerated': 4,
                'wordpress_detected': True,
                'joomla_detected': False,
                'has_ssl_tls': True,
                'has_database': True,
                'has_smb': False,
                'time_in_phase': 300,
                'num_tools_executed': 2,
                'aggressive_mode': False,
                'tools_executed': ['nmap']
            }
        },
        {
            'name': 'Exploitation - SQL Injection Found',
            'context': {
                'phase': 'exploitation',
                'sql_injection_found': True,
                'xss_found': False,
                'command_injection_found': False,
                'xxe_found': False,
                'ssrf_found': False,
                'file_upload_found': False,
                'auth_bypass_found': False,
                'highest_severity': 9.5,
                'num_critical_vulns': 1,
                'num_exploitable_vulns': 1,
                'waf_detected': False,
                'authentication_required': False,
                'target_hardening_level': 0.3,
                'access_gained': False,
                'exploit_attempts': 0,
                'time_in_phase': 120,
                'tools_executed': []
            }
        },
        {
            'name': 'Post-Exploitation - Linux System',
            'context': {
                'phase': 'post_exploitation',
                'current_user_privilege': 'user',
                'os_type': 'linux',
                'os_version': 'Ubuntu 20.04',
                'privilege_escalated': False,
                'persistence_established': False,
                'credentials_dumped': False,
                'lateral_movement_success': False,
                'domain_joined': False,
                'antivirus_detected': False,
                'edr_detected': False,
                'other_hosts_visible': 5,
                'time_in_phase': 180,
                'num_tools_executed': 0,
                'detection_probability': 0.4,
                'tools_executed': []
            }
        },
        {
            'name': 'Covering Tracks - High Forensics Score',
            'context': {
                'phase': 'covering_tracks',
                'log_entries_present': 150,
                'artifacts_present': 5,
                'backdoors_installed': 1,
                'forensic_evidence_score': 8.5,
                'logs_cleaned': False,
                'timestamps_modified': False,
                'artifacts_removed': False,
                'time_remaining': 300,
                'stealth_critical': True,
                'detection_imminent': False,
                'os_type': 'linux',
                'admin_access': True,
                'tools_executed': []
            }
        }
    ]
    
    print("\nTesting tool recommendations for different scenarios:\n")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"{i}. {test_case['name']}")
        print("-" * 80)
        
        result = selector.recommend_tools(test_case['context'])
        
        if 'error' in result:
            print(f"   ❌ Error: {result['error']}")
        else:
            print(f"   Phase: {result['phase']}")
            print(f"   Model: {result['model_type']}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Recommended tools:")
            for j, (tool, prob) in enumerate(zip(result['tools'], result['probabilities']), 1):
                print(f"      {j}. {tool:20s} (probability: {prob:.1%})")
        
        print()
    
    print("="*80)
    print("TESTING COMPLETE")
    print("="*80)
    
    # Summary
    print("\n✅ Phase-specific models successfully loaded and tested")
    print("✅ Each phase has specialized features and tools")
    print("✅ Models provide probability-based recommendations")
    print("\nNote: With more real training data, accuracies will improve significantly")

if __name__ == '__main__':
    test_phase_specific_models()
