#!/usr/bin/env python3
"""
Quick test script for the HTTP MCP server.
"""

import asyncio
import json
import httpx

async def test_http_server():
    """Test the HTTP MCP server functionality."""
    base_url = "http://127.0.0.1:5001"
    
    async with httpx.AsyncClient() as client:
        # Test health check
        print("1. Testing health check...")
        response = await client.get(f"{base_url}/health")
        print(f"Health check: {response.status_code}")
        if response.status_code == 200:
            print(f"Response: {response.json()}")
        
        # Test MCP initialization
        print("\n2. Testing MCP initialization...")
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
                "Accept": "application/json, text/event-stream",
                "Origin": "http://localhost"
            }
        )
        
        print(f"Initialize: {response.status_code}")
        if response.status_code == 200:
            init_response = response.json()
            print(f"Response: {json.dumps(init_response, indent=2)}")
            
            # Extract session ID if present
            session_id = response.headers.get("Mcp-Session-Id")
            if session_id:
                print(f"Session ID: {session_id}")
                
                # Test tools/list with session
                print("\n3. Testing tools/list...")
                tools_request = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list"
                }
                
                response = await client.post(
                    f"{base_url}/mcp",
                    json=tools_request,
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Origin": "http://localhost",
                        "Mcp-Session-Id": session_id
                    }
                )
                
                print(f"Tools list: {response.status_code}")
                if response.status_code == 200:
                    tools_response = response.json()
                    print(f"Available tools: {len(tools_response.get('tools', []))}")
                    for tool in tools_response.get('tools', []):
                        print(f"  - {tool['name']}: {tool['description']}")
                
                # Test resources/list with session
                print("\n4. Testing resources/list...")
                resources_request = {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "resources/list"
                }
                
                response = await client.post(
                    f"{base_url}/mcp",
                    json=resources_request,
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Origin": "http://localhost",
                        "Mcp-Session-Id": session_id
                    }
                )
                
                print(f"Resources list: {response.status_code}")
                if response.status_code == 200:
                    resources_response = response.json()
                    print(f"Available resources: {len(resources_response.get('resources', []))}")
                    for resource in resources_response.get('resources', []):
                        print(f"  - {resource['uri']}: {resource['name']}")

if __name__ == "__main__":
    asyncio.run(test_http_server())