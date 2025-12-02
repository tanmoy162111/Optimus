"""
Test script to verify that the scan engine module works correctly
"""
import sys
from pathlib import Path

# Add backend to path
BACKEND_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BACKEND_DIR))

try:
    # Test importing the scan engine
    from core.scan_engine import get_scan_manager
    print("✅ Successfully imported core.scan_engine")
    
    # Test getting the scan manager
    manager = get_scan_manager()
    print("✅ Successfully got scan manager instance")
    
    # Test calling some methods
    stats = manager.get_statistics()
    print("✅ Successfully called get_statistics()")
    print(f"   Statistics: {stats}")
    
    recommendation = manager.get_tool_recommendation("test_scan", "reconnaissance", {})
    print("✅ Successfully called get_tool_recommendation()")
    print(f"   Recommendation: {recommendation}")
    
    print("\n🎉 All tests passed! The scan engine module is working correctly.")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()