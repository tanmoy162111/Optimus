"""
Integration Test: Frontend-Backend Communication
Tests API endpoints and WebSocket connectivity
"""
import requests
import json
import sys

API_URL = "http://localhost:5000"

def test_health_check():
    """Test API health endpoint"""
    print("\n[Test 1] Health Check...")
    try:
        response = requests.get(f"{API_URL}/health")
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
        print("  ✓ Health check passed")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False

def test_scan_lifecycle():
    """Test scan creation and retrieval"""
    print("\n[Test 2] Scan Lifecycle...")
    try:
        # Start scan
        response = requests.post(f"{API_URL}/api/scan/start", json={
            'target': 'http://testsite.com'
        })
        assert response.status_code == 200
        data = response.json()
        scan_id = data['scan_id']
        print(f"  ✓ Scan created: {scan_id}")
        
        # Get status
        response = requests.get(f"{API_URL}/api/scan/status/{scan_id}")
        assert response.status_code == 200
        scan_data = response.json()
        assert scan_data['target'] == 'http://testsite.com'
        print(f"  ✓ Status retrieved: {scan_data['phase']}")
        
        # Get results
        response = requests.get(f"{API_URL}/api/scan/results/{scan_id}")
        assert response.status_code == 200
        results = response.json()
        print(f"  ✓ Results retrieved: {results['summary']['total_findings']} findings")
        
        # Stop scan
        response = requests.post(f"{API_URL}/api/scan/stop/{scan_id}")
        assert response.status_code == 200
        print("  ✓ Scan stopped successfully")
        
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False

def test_scan_list():
    """Test listing scans"""
    print("\n[Test 3] List Scans...")
    try:
        response = requests.get(f"{API_URL}/api/scan/list")
        assert response.status_code == 200
        data = response.json()
        print(f"  ✓ Retrieved {data['total_count']} scans ({data['active_count']} active)")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False

def test_training_endpoints():
    """Test training endpoints"""
    print("\n[Test 4] Training Endpoints...")
    try:
        # Start training
        response = requests.post(f"{API_URL}/api/training/start", json={
            'datasets': ['dataset1.csv'],
            'train_rl': True
        })
        assert response.status_code == 200
        data = response.json()
        job_id = data['job_id']
        print(f"  ✓ Training job created: {job_id}")
        
        # Get status
        response = requests.get(f"{API_URL}/api/training/status/{job_id}")
        assert response.status_code == 200
        print(f"  ✓ Training status retrieved")
        
        # List models
        response = requests.get(f"{API_URL}/api/training/models")
        assert response.status_code == 200
        data = response.json()
        print(f"  ✓ Found {data['count']} models")
        
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False

def test_metrics_endpoints():
    """Test metrics endpoints"""
    print("\n[Test 5] Metrics Endpoints...")
    try:
        # ML metrics
        response = requests.get(f"{API_URL}/api/metrics/ml")
        assert response.status_code == 200
        print("  ✓ ML metrics retrieved")
        
        # RL metrics
        response = requests.get(f"{API_URL}/api/metrics/rl")
        assert response.status_code == 200
        print("  ✓ RL metrics retrieved")
        
        # Scan history
        response = requests.get(f"{API_URL}/api/metrics/scan-history")
        assert response.status_code == 200
        print("  ✓ Scan history retrieved")
        
        # System metrics
        response = requests.get(f"{API_URL}/api/metrics/system")
        assert response.status_code == 200
        data = response.json()
        print(f"  ✓ System metrics: CPU {data['cpu_percent']}%")
        
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False

def main():
    print("=" * 60)
    print("Integration Test: Frontend-Backend Communication")
    print("=" * 60)
    
    tests = [
        test_health_check,
        test_scan_lifecycle,
        test_scan_list,
        test_training_endpoints,
        test_metrics_endpoints
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {sum(results)}/{len(results)} tests passed")
    print("=" * 60)
    
    if all(results):
        print("\n✅ All integration tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
