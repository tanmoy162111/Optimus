#!/usr/bin/env python3
"""
Simple WebSocket connection test
"""
import asyncio
import websockets
import json

async def test_websocket():
    uri = "ws://localhost:5000/socket.io/?EIO=4&transport=websocket"
    try:
        async with websockets.connect(uri, extra_headers={"Origin": "http://localhost:5176"}) as websocket:
            print("✅ WebSocket connection established")
            
            # Wait for a message
            message = await websocket.recv()
            print(f"Received: {message}")
            
    except Exception as e:
        print(f"❌ WebSocket connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_websocket())