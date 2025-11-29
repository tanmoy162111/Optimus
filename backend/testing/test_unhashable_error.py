"""
Test script to isolate the "unhashable type: 'dict'" error
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from inference.autonomous_agent import AutonomousPentestAgent
from inference.dynamic_tool_database import DynamicToolDatabase
import json

def test_unhashable_error():
    """Test to isolate the unhashable type error"""
    try:
        print("Testing autonomous agent initialization...")
        agent = AutonomousPentestAgent()
        print("✅ Agent initialized successfully")
        
        # Test with a simple config
        config = {
            'max_time': 300,  # 5 minutes
            'depth': 'shallow',
            'stealth': True,
            'aggressive': False,
            'target_type': 'web',
            'learning_mode': True
        }
        
        print("Testing scan with https://landscape.canonical.com...")
        result = agent.run_autonomous_scan("https://landscape.canonical.com", config)
        print("✅ Scan completed successfully")
        print(f"Result: {result}")
        
    except Exception as e:
        print(f"❌ Error occurred: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == '__main__':
    success = test_unhashable_error()
    sys.exit(0 if success else 1)