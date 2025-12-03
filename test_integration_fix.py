#!/usr/bin/env python3
"""
Integration Test Script
Verifies that all components can be imported and initialized correctly
"""

import sys
import os
from pathlib import Path

# Add backend to path
BACKEND_DIR = Path(__file__).parent / 'backend'
sys.path.insert(0, str(BACKEND_DIR))

def test_imports():
    """Test that all major components can be imported"""
    tests = [
        ('Flask App', 'from app import app'),
        ('API Routes', 'from api.routes import api_bp'),
        ('Scan Routes', 'from api.scan_routes import scan_bp'),
        ('Tool Routes', 'from api.tool_routes import tool_bp'),
        ('Intelligence Routes', 'from api.intelligence_routes import intelligence_bp'),
        ('Metrics Routes', 'from api.metrics_routes import metrics_bp'),
        ('Report Routes', 'from api.report_routes import report_bp'),
        ('Training Routes', 'from api.training_routes import training_bp'),
        ('Tool Manager', 'from inference.tool_manager import ToolManager'),
        ('Workflow Engine', 'from inference.workflow_engine import WorkflowEngine'),
        ('Scan Engine', 'from core.scan_engine import get_scan_manager'),
    ]
    
    results = []
    for name, import_stmt in tests:
        try:
            exec(import_stmt)
            results.append((name, True, None))
            print(f"✅ {name}: PASS")
        except Exception as e:
            results.append((name, False, str(e)))
            print(f"❌ {name}: FAIL - {e}")
    
    return results

def main():
    """Run integration tests"""
    print("🔍 Running Integration Tests...\n")
    
    results = test_imports()
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    print(f"\n📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed. Check output above.")
        return 1

if __name__ == '__main__':
    main()