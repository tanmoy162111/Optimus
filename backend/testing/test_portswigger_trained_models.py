"""Test phase-specific models trained on PortSwigger dataset"""
import sys
sys.path.append('..')
from training.phase_specific_models import PhaseSpecificToolSelector

def test_portswigger_scenarios():
    """Test with scenarios based on PortSwigger research labs"""
    print("="*80)
    print("TESTING PHASE-SPECIFIC MODELS - PORTSWIGGER DATASET")
    print("="*80)
    
    selector = PhaseSpecificToolSelector()
    
    # Test scenarios based on actual PortSwigger labs
    test_cases = [
        {
            'name': 'Command Injection Lab - Reconnaissance',
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
                'time_in_phase': 120,
                'stealth_required': True,
                'detection_risk': 0.3,
                'num_tools_executed': 0,
                'passive_tools_ratio': 1.0
            }
        },
        {
            'name': 'JWT Signer Lab - Scanning',
            'context': {
                'phase': 'scanning',
                'target_type': 'web',
                'technologies_known': 3,
                'subdomains_count': 5,
                'open_ports_found': 2,
                'scan_coverage': 0.7,
                'vulnerabilities_found': 1,
                'services_enumerated': 3,
                'wordpress_detected': False,
                'joomla_detected': False,
                'has_ssl_tls': True,
                'has_database': True,
                'has_smb': False,
                'time_in_phase': 300,
                'num_tools_executed': 2,
                'aggressive_mode': False
            }
        },
        {
            'name': 'Command Injection - Exploitation',
            'context': {
                'phase': 'exploitation',
                'sql_injection_found': False,
                'xss_found': False,
                'command_injection_found': True,
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
                'time_in_phase': 60
            }
        },
        {
            'name': 'JWT Authentication Bypass - Exploitation',
            'context': {
                'phase': 'exploitation',
                'sql_injection_found': False,
                'xss_found': False,
                'command_injection_found': False,
                'xxe_found': False,
                'ssrf_found': False,
                'file_upload_found': False,
                'auth_bypass_found': True,
                'highest_severity': 8.0,
                'num_critical_vulns': 1,
                'num_exploitable_vulns': 1,
                'waf_detected': False,
                'authentication_required': True,
                'target_hardening_level': 0.5,
                'access_gained': False,
                'exploit_attempts': 0,
                'time_in_phase': 120
            }
        },
        {
            'name': 'Linux System - Post-Exploitation',
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
                'other_hosts_visible': 3,
                'time_in_phase': 180,
                'num_tools_executed': 1,
                'detection_probability': 0.4
            }
        },
        {
            'name': 'High Stealth Cleanup - Covering Tracks',
            'context': {
                'phase': 'covering_tracks',
                'log_entries_present': 150,
                'artifacts_present': 5,
                'backdoors_installed': 1,
                'forensic_evidence_score': 7.5,
                'logs_cleaned': False,
                'timestamps_modified': False,
                'artifacts_removed': False,
                'time_remaining': 300,
                'stealth_critical': True,
                'detection_imminent': False,
                'os_type': 'linux',
                'admin_access': True
            }
        }
    ]
    
    # Run tests
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. {test_case['name']}")
        print("-" * 80)
        
        result = selector.recommend_tools(test_case['context'])
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            continue
        
        print(f"Phase: {result['phase']}")
        print(f"Model: {result['model_type']}")
        print(f"Confidence: {result['confidence']:.1%}")
        print(f"Recommended tools:")
        
        for j, (tool, prob) in enumerate(zip(result['tools'], result['probabilities']), 1):
            print(f"  {j}. {tool:20s} ({prob:.1%})")
        
        # Validate recommendations
        phase = test_case['context']['phase']
        tools = result['tools']
        
        if phase == 'exploitation':
            if test_case['context'].get('command_injection_found'):
                if 'commix' in tools:
                    print("✅ Correctly recommended commix for command injection")
            if test_case['context'].get('auth_bypass_found'):
                if 'jwt_tool' in tools or 'hydra' in tools:
                    print("✅ Correctly recommended auth bypass tool")
        elif phase == 'post_exploitation':
            if test_case['context'].get('os_type') == 'linux':
                if 'linpeas' in tools:
                    print("✅ Correctly recommended linpeas for Linux")
    
    print("\n" + "="*80)
    print("PORTSWIGGER DATASET TESTING COMPLETE")
    print("="*80)

if __name__ == '__main__':
    test_portswigger_scenarios()
