#!/usr/bin/env python3
"""
Debug HTTP MCP server responses.
"""

import asyncio
import json
import httpx

async def debug_mcp_responses():
    """Debug MCP responses to see what's happening."""
    base_url = "http://127.0.0.1:5001"
    
    async with httpx.AsyncClient() as client:
        # Test initialization to get session
        print("=== INITIALIZATION ===")
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }
        }
        
        response = await client.post(
            f"{base_url}/mcp",
            json=init_request,
            headers={
                "Accept": "application/json",
                "Origin": "http://localhost"
            }
        )
        
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        session_id = response.headers.get("Mcp-Session-Id")
        print(f"Session ID: {session_id}")
        
        if response.status_code == 200:
            print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if session_id:
            # Test tools/list
            print("\n=== TOOLS/LIST ===")
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }
            
            response = await client.post(
                f"{base_url}/mcp",
                json=tools_request,
                headers={
                    "Accept": "application/json",
                    "Origin": "http://localhost",
                    "Mcp-Session-Id": session_id
                }
            )
            
            print(f"Status: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                print(f"Response: {json.dumps(response.json(), indent=2)}")
            else:
                print(f"Error response: {response.text}")

if __name__ == "__main__":
    asyncio.run(debug_mcp_responses())