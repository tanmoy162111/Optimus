"""
Test script for the hybrid tool system
"""
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

def test_hybrid_system():
    """Test the hybrid tool system"""
    try:
        # Import the hybrid tool system
        from tools import get_hybrid_tool_system, ToolSource, ResolutionStatus
        
        print("Testing Hybrid Tool System...")
        
        # Initialize the system
        tool_system = get_hybrid_tool_system()
        print("✓ Hybrid tool system initialized")
        
        # Test tool scanning
        print("\nScanning for tools...")
        scan_result = tool_system.scan_for_tools()
        print(f"✓ Tool scan complete: {scan_result.get('tools_found', 0)} tools found")
        
        # Test resolving a known tool
        print("\nResolving nmap...")
        resolution = tool_system.resolve_tool(
            tool_name="nmap",
            task="Perform a full port scan",
            target="192.168.1.1"
        )
        
        print(f"Tool: {resolution.tool_name}")
        print(f"Source: {resolution.source.value}")
        print(f"Status: {resolution.status.value}")
        print(f"Command: {resolution.command}")
        print(f"Confidence: {resolution.confidence}")
        
        if resolution.status == ResolutionStatus.RESOLVED:
            print("✓ Nmap resolution successful")
        else:
            print("⚠ Nmap resolution failed")
        
        # Test resolving an unknown tool
        print("\nResolving unknown tool...")
        resolution = tool_system.resolve_tool(
            tool_name="rustscan",
            task="Fast port scanning",
            target="192.168.1.1"
        )
        
        print(f"Tool: {resolution.tool_name}")
        print(f"Source: {resolution.source.value}")
        print(f"Status: {resolution.status.value}")
        print(f"Command: {resolution.command}")
        print(f"Confidence: {resolution.confidence}")
        
        # Test getting available tools
        print("\nGetting available tools...")
        tools = tool_system.get_available_tools()
        print(f"✓ Found {len(tools)} available tools")
        
        if tools:
            print("Sample tools:")
            for i, tool in enumerate(tools[:5]):
                print(f"  {i+1}. {tool}")
        
        # Test statistics
        print("\nGetting system statistics...")
        stats = tool_system.get_statistics()
        print(f"✓ Statistics: {stats}")
        
        print("\n🎉 All tests completed successfully!")
        
    except ImportError as e:
        print(f"❌ Hybrid tool system not available: {e}")
        print("Make sure the tools module is properly installed.")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_hybrid_system()