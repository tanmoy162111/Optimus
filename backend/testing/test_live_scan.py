"""Integration test: Complete scan of OWASP Juice Shop"""

import sys
sys.path.insert(0, '..')

from inference.autonomous_agent import AutonomousPentestAgent
from datetime import datetime
import json

def test_juice_shop_scan():
    """Test complete autonomous scan of Juice Shop"""
    print("\n" + "=" * 60)
    print("INTEGRATION TEST: OWASP Juice Shop Scan")
    print("=" * 60)
    
    agent = AutonomousPentestAgent()
    
    target = 'http://192.168.131.128:3000'
    
    config = {
        'max_time': 1800,  # 30 minutes
        'depth': 'normal',
        'stealth': False,
        'aggressive': True,
        'target_type': 'web'
    }
    
    print(f"\nStarting autonomous scan of {target}")
    print(f"Time budget: {config['max_time']}s")
    print(f"Expected: Find SQL injection, complete in <30 iterations\n")
    
    start = datetime.now()
    
    try:
        result = agent.conduct_scan(target, config)
        
        elapsed = (datetime.now() - start).total_seconds()
        
        # Analyze results
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Duration: {elapsed:.0f}s")
        print(f"Iterations: {len(result['tools_executed'])}")
        print(f"Findings: {len(result['findings'])}")
        print(f"Coverage: {result['coverage']:.1%}")
        
        # Check for SQL injection
        sql_findings = [f for f in result['findings']
                        if 'sql' in f.get('type', '').lower()]
        
        print(f"\nSQL Injection findings: {len(sql_findings)}")
        for f in sql_findings[:3]:
            print(f"  - {f.get('name')}: {f.get('severity'):.1f}/10")
        
        # Verify success criteria
        print("\n" + "=" * 60)
        print("SUCCESS CRITERIA")
        print("=" * 60)
        
        checks = {
            'Completed': result.get('status') == 'completed',
            'Iterations < 30': len(result['tools_executed']) < 30,
            'Found vulnerabilities': len(result['findings']) > 0,
            'Found SQL injection': len(sql_findings) > 0,
            'Coverage > 60%': result['coverage'] > 0.6,
            'No tool repeated 3+ times': max([result['tools_executed'].count(t) for t in set([item['tool'] if isinstance(item, dict) else item for item in result['tools_executed']])]) < 3,
        }
        
        for check, passed in checks.items():
            status = "✅" if passed else "❌"
            print(f"{status} {check}")
        
        all_passed = all(checks.values())
        
        if all_passed:
            print("\n✅ ALL CRITERIA PASSED")
        else:
            print("\n❌ SOME CRITERIA FAILED")
        
        # Save detailed results
        with open(f"data/integration_test_{result['scan_id']}.json", 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"\nDetailed results saved to data/integration_test_{result['scan_id']}.json")
        
        return all_passed
        
    except Exception as e:
        print(f"\n❌ SCAN FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_juice_shop_scan()
    sys.exit(0 if success else 1)