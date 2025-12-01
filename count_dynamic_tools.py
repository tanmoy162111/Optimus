#!/usr/bin/env python3
"""Script to count tools in the dynamic tool database"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from backend.inference.dynamic_tool_database import DynamicToolDatabase

def main():
    db = DynamicToolDatabase()
    tools = list(db.tools.keys())
    
    print(f"Dynamic Tool Database contains {len(tools)} unique tools:")
    for i, tool in enumerate(tools, 1):
        print(f"  {i:2d}. {tool}")
    
    # Also count by category
    print(f"\nTools by category:")
    categories = {}
    for tool_name, tool_info in db.tools.items():
        category = tool_info.get('category', 'uncategorized')
        if category not in categories:
            categories[category] = []
        categories[category].append(tool_name)
    
    for category, tool_list in categories.items():
        print(f"  {category}: {len(tool_list)} tools")
        for tool in tool_list:
            print(f"    - {tool}")

if __name__ == "__main__":
    main()