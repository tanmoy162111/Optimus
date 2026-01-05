"""
Test script to verify the tool integration system works properly
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from inference.tool_integration import get_tool_integration_coordinator, sync_all_tools
from execution.ssh_client import KaliSSHClient
from config import Config

def test_integration():
    """Test the tool integration system"""
    print("Testing Tool Integration System...")
    
    try:
        # Try to create SSH client (optional for testing)
        ssh_client = None
        try:
            ssh_client = KaliSSHClient()
            if ssh_client.connect():
                print("✓ SSH connection established")
            else:
                print("⚠ SSH connection failed - using local discovery")
                ssh_client = None
        except Exception as e:
            print(f"⚠ SSH setup failed: {e} - using local discovery")
            ssh_client = None
        
        # Create integration coordinator
        coordinator = get_tool_integration_coordinator(ssh_client)
        print("✓ Tool Integration Coordinator created")
        
        # Test tool synchronization
        print("\nSyncing tools...")
        sync_result = sync_all_tools(ssh_client)
        print(f"✓ Sync completed: {sync_result}")
        
        # Test individual tool availability
        test_tools = ['nmap', 'curl', 'python3']
        for tool in test_tools:
            print(f"\nTesting tool: {tool}")
            exists = coordinator.ensure_tool_availability(tool)
            print(f"  Available: {exists}")
            if exists:
                status = coordinator.get_tool_status(tool)
                print(f"  Status: {status}")
        
        # Test command generation
        print(f"\nTesting command generation...")
        for tool in ['nmap', 'curl']:
            if coordinator.ensure_tool_availability(tool):
                command = coordinator.generate_command_for_tool(tool, '127.0.0.1', {'phase': 'reconnaissance'})
                if command:
                    print(f"  ✓ Generated command for {tool}: {command[:50]}...")
                else:
                    print(f"  ⚠ Could not generate command for {tool}")
        
        print("\n✓ Integration test completed successfully!")
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        if ssh_client:
            try:
                ssh_client.disconnect()
                print("✓ SSH connection closed")
            except:
                pass

if __name__ == "__main__":
    test_integration()