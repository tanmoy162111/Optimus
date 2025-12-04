#!/usr/bin/env python3
"""
Test WebSocket connection to Optimus backend
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
            
            # Read messages
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    print(f"Received: {message}")
                except asyncio.TimeoutError:
                    print("Timeout waiting for message")
                    break
                    
    except Exception as e:
        print(f"❌ Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())