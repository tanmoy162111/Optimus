import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

try:
    from tools import get_tool_scanner
    print("Successfully imported get_tool_scanner")
    
    scanner = get_tool_scanner()
    print("Successfully created tool scanner")
    
    result = scanner.scan_system()
    print(f"Scan result: {result}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()