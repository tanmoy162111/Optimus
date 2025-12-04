#!/usr/bin/env python3
"""
Final test of WebSocket connection to Optimus backend
"""
import asyncio
import websockets
import json

async def test_connection():
    uri = "ws://localhost:5000/socket.io/?EIO=4&transport=websocket"
    try:
        print(f"Connecting to {uri}")
        async with websockets.connect(uri) as websocket:
            print("✅ Connected successfully!")
            
            # Read the initial message
            message = await websocket.recv()
            print(f"Received: {message}")
            
            # Send a simple ping
            await websocket.send('42["ping"]')
            print("Sent ping message")
            
            # Wait for a response
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                print(f"Response: {response}")
            except asyncio.TimeoutError:
                print("No response received within timeout")
                
    except Exception as e:
        print(f"❌ Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())