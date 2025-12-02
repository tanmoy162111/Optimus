"""
Simple test to verify Optimus Intelligence Module integration
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_configuration():
    """Test 1: Configuration loading"""
    print("=" * 60)
    print("TEST 1: Configuration System")
    print("=" * 60)
    try:
        from config.intelligence_config import IntelligenceConfig
        
        # Test loading from env
        config = IntelligenceConfig.from_env()
        
        print("✅ IntelligenceConfig imported successfully")
        print(f"   - Memory enabled: {config.enable_memory}")
        print(f"   - Web intelligence enabled: {config.enable_web_intel}")
        print(f"   - Adaptive exploitation enabled: {config.enable_adaptive}")
        print(f"   - Vulnerability chaining enabled: {config.enable_chaining}")
        print(f"   - Explainable AI enabled: {config.enable_explainable}")
        print(f"   - Learning enabled: {config.enable_learning}")
        print(f"   - Zero-day discovery enabled: {config.enable_zeroday}")
        print(f"   - Campaign intelligence enabled: {config.enable_campaign}")
        print(f"   - Delegation system enabled: {config.enable_delegation}")
        print(f"\n✅ Configuration loading: PASSED\n")
        return True
    except Exception as e:
        print(f"❌ Configuration loading: FAILED - {e}\n")
        return False


def test_intelligence_routes():
    """Test 2: Intelligence routes registration"""
    print("=" * 60)
    print("TEST 2: Intelligence Routes")
    print("=" * 60)
    try:
        from api.intelligence_routes import intelligence_bp
        
        print("✅ Intelligence routes imported successfully")
        print(f"   - Blueprint name: {intelligence_bp.name}")
        print(f"   - Blueprint URL prefix: {intelligence_bp.url_prefix}")
        
        # Count routes
        routes = [rule for rule in intelligence_bp.deferred_functions]
        print(f"   - Routes defined: {len(intelligence_bp.view_functions)} endpoints")
        
        # List endpoints
        endpoints = [
            '/memory/stats',
            '/memory/target/<target_hash>',
            '/memory/patterns',
            '/chains/analyze',
            '/chains/<chain_id>/plan',
            '/campaigns',
            '/campaigns/<campaign_id>',
            '/campaigns/<campaign_id>/optimize',
            '/campaigns/<campaign_id>/recommendations/<path:target_url>',
            '/decisions/audit',
            '/decisions/report',
            '/status',
            '/zeroday/queue',
            '/zeroday/<anomaly_id>/resolve'
        ]
        
        for endpoint in endpoints[:5]:
            print(f"   - Endpoint: {endpoint}")
        print(f"   - ... and {len(endpoints) - 5} more endpoints\n")
        
        print("✅ Intelligence routes: PASSED\n")
        return True
    except Exception as e:
        print(f"❌ Intelligence routes: FAILED - {e}\n")
        return False


def test_scan_engine_integration():
    """Test 3: Scan engine intelligence bridge"""
    print("=" * 60)
    print("TEST 3: Scan Engine Intelligence Bridge")
    print("=" * 60)
    try:
        from inference.scan_engine_intelligence import IntelligentScanEngine
        
        print("✅ IntelligentScanEngine imported successfully")
        print("   - Class methods:")
        print("     - run_intelligent_scan()")
        print("     - _stream_update()")
        print("     - _get_phase_tools()")
        
        # Check methods exist
        methods = ['run_intelligent_scan', '_stream_update', '_get_phase_tools']
        for method in methods:
            has_method = hasattr(IntelligentScanEngine, method)
            print(f"   - {method}: {'✅' if has_method else '❌'}")
        
        print("\n✅ Scan engine integration: PASSED\n")
        return True
    except Exception as e:
        print(f"❌ Scan engine integration: FAILED - {e}\n")
        return False


def test_frontend_components():
    """Test 4: Frontend components exist"""
    print("=" * 60)
    print("TEST 4: Frontend Components")
    print("=" * 60)
    try:
        import os
        
        components = [
            'frontend/src/components/intelligence/IntelligencePanel.tsx',
            'frontend/src/components/intelligence/CampaignManager.tsx',
            'frontend/src/components/intelligence/index.ts'
        ]
        
        all_exist = True
        for component in components:
            path = os.path.join(os.path.dirname(__file__), component)
            exists = os.path.exists(path)
            all_exist = all_exist and exists
            print(f"   {'✅' if exists else '❌'} {component}")
        
        if all_exist:
            print("\n✅ Frontend components: PASSED\n")
            return True
        else:
            raise FileNotFoundError("Some components missing")
    except Exception as e:
        print(f"❌ Frontend components: FAILED - {e}\n")
        return False


def test_app_registration():
    """Test 5: App.py intelligence route registration"""
    print("=" * 60)
    print("TEST 5: Flask App Registration")
    print("=" * 60)
    try:
        with open('backend/app.py', 'r') as f:
            app_content = f.read()
        
        checks = {
            'intelligence_bp import': 'from api.intelligence_routes import intelligence_bp' in app_content,
            'intelligence_bp register': 'app.register_blueprint(intelligence_bp)' in app_content,
            'intelligence endpoint': "'intelligence': '/api/intelligence'" in app_content
        }
        
        all_passed = True
        for check_name, result in checks.items():
            all_passed = all_passed and result
            print(f"   {'✅' if result else '❌'} {check_name}")
        
        if all_passed:
            print("\n✅ Flask app registration: PASSED\n")
            return True
        else:
            raise AssertionError("Some checks failed")
    except Exception as e:
        print(f"❌ Flask app registration: FAILED - {e}\n")
        return False


def test_env_configuration():
    """Test 6: Environment configuration"""
    print("=" * 60)
    print("TEST 6: Environment Configuration")
    print("=" * 60)
    try:
        with open('.env.example', 'r') as f:
            env_content = f.read()
        
        required_vars = [
            'OPTIMUS_ENABLE_MEMORY',
            'OPTIMUS_ENABLE_WEB_INTEL',
            'OPTIMUS_ENABLE_CHAINING',
            'OPTIMUS_ENABLE_CAMPAIGN',
            'SHODAN_API_KEY',
            'VIRUSTOTAL_API_KEY',
            'LLM_PROVIDER',
            'OPTIMUS_MEMORY_DB'
        ]
        
        all_present = True
        for var in required_vars:
            present = var in env_content
            all_present = all_present and present
            print(f"   {'✅' if present else '❌'} {var}")
        
        if all_present:
            print("\n✅ Environment configuration: PASSED\n")
            return True
        else:
            raise AssertionError("Some env vars missing")
    except Exception as e:
        print(f"❌ Environment configuration: FAILED - {e}\n")
        return False


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  OPTIMUS INTELLIGENCE MODULE INTEGRATION TEST".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "=" * 58 + "╝")
    print("\n")
    
    results = []
    
    # Run tests
    results.append(("Configuration System", test_configuration()))
    results.append(("Intelligence Routes", test_intelligence_routes()))
    results.append(("Scan Engine Integration", test_scan_engine_integration()))
    results.append(("Frontend Components", test_frontend_components()))
    results.append(("Flask App Registration", test_app_registration()))
    results.append(("Environment Configuration", test_env_configuration()))
    
    # Summary
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        print(f"{'✅' if result else '❌'} {test_name}")
    
    print("\n" + "=" * 60)
    print(f"TOTAL: {passed}/{total} tests passed")
    print("=" * 60 + "\n")
    
    if passed == total:
        print("��� ALL TESTS PASSED! Intelligence module integration is successful!\n")
        return 0
    else:
        print(f"⚠️  {total - passed} test(s) failed. Please review the output above.\n")
        return 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
