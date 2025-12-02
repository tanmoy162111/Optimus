import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

try:
    import tools
    print("Tools module imported successfully")
    
    # Try to get the hybrid tool system
    tool_system = tools.get_hybrid_tool_system()
    print("Hybrid tool system created successfully")
    
    # Try to scan for tools
    result = tool_system.scan_for_tools()
    print(f"Tool scan result: {result}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()