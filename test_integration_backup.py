#!/usr/bin/env python3
"""
Integration Test Script
Tests the communication between the new frontend and backend
"""

import requests
import time
import json

def test_backend_health():
    """Test if the backend is healthy"""
    try:
        response = requests.get('http://localhost:5000/health', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Backend Health Check:")
            print(f"   Status: {data.get('status')}")
            print(f"   Version: {data.get('version')}")
            return True
        else:
            print(f"❌ Backend Health Check Failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Backend not reachable")
        return False
    except Exception as e:
        print(f"❌ Backend Health Check Error: {e}")
        return False

def test_backend_root():
    """Test the backend root endpoint"""
    try:
        response = requests.get('http://localhost:5000/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Backend Root Endpoint:")
            print(f"   Name: {data.get('name')}")
            print(f"   Version: {data.get('version')}")
            return True
        else:
            print(f"❌ Backend Root Endpoint Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Backend Root Endpoint Error: {e}")
        return False

def test_api_endpoints():
    """Test the main API endpoints"""
    try:
        response = requests.get('http://localhost:5000/api/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ API Root Endpoint:")
            print(f"   Status: {data.get('status')}")
            print(f"   Version: {data.get('version')}")
            return True
        else:
            print(f"❌ API Root Endpoint Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API Root Endpoint Error: {e}")
        return False

def test_dashboard_stats():
    """Test the dashboard stats endpoint"""
    try:
        response = requests.get('http://localhost:5000/api/dashboard/stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Dashboard Stats Endpoint:")
            print(f"   Active Scans: {data.get('active_scans', 0)}")
            print(f"   Total Scans: {data.get('total_scans', 0)}")
            print(f"   Tools Available: {data.get('tools_available', 0)}")
            return True
        else:
            print(f"❌ Dashboard Stats Endpoint Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Dashboard Stats Endpoint Error: {e}")
        return False

def test_tool_endpoints():
    """Test the tool endpoints"""
    try:
        # Test tool categories
        response = requests.get('http://localhost:5000/api/tools/categories', timeout=5)
        if response.status_code == 200:
            data = response.json()
            categories = data.get('categories', [])
            print("✅ Tool Categories Endpoint:")
            print(f"   Found {len(categories)} categories")
            if categories:
                print(f"   Sample categories: {categories[:3]}")
            return True
        else:
            print(f"❌ Tool Categories Endpoint Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Tool Categories Endpoint Error: {e}")
        return False

def test_frontend_access():
    """Test if frontend is accessible"""
    try:
        response = requests.get('http://localhost:5173', timeout=5)
        if response.status_code == 200:
            content = response.text
            if '<title>' in content.lower():
                print("✅ Frontend Access:")
                print("   Frontend is serving content")
                return True
            else:
                print("❌ Frontend Access:")
                print("   Frontend returned unexpected content")
                return False
        else:
            print(f"❌ Frontend Access Failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Frontend not reachable")
        return False
    except Exception as e:
        print(f"❌ Frontend Access Error: {e}")
        return False

def main():
    """Run all integration tests"""
    print("🚀 Starting Optimus Integration Tests...\n")
    
    tests = [
        ("Backend Health", test_backend_health),
        ("Backend Root", test_backend_root),
        ("API Endpoints", test_api_endpoints),
        ("Dashboard Stats", test_dashboard_stats),
        ("Tool Endpoints", test_tool_endpoints),
        ("Frontend Access", test_frontend_access)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"Running {test_name} test...")
        if test_func():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"🏁 Integration Tests Complete: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Integration is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Please check the output above.")
        return False

if __name__ == "__main__":
    main()