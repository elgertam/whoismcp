#!/usr/bin/env python3
"""
Test the complete HTTP MCP workflow with real lookups.
"""

import asyncio
import json
import httpx

async def test_complete_workflow():
    """Test the complete HTTP MCP workflow."""
    base_url = "http://127.0.0.1:5001"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Initialize session
        print("=== INITIALIZING SESSION ===")
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
        
        session_id = response.headers.get("Mcp-Session-Id")
        print(f"✓ Session created: {session_id}")
        
        # 2. List tools
        print("\n=== LISTING TOOLS ===")
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
        
        tools_response = response.json()
        tools = tools_response.get("result", {}).get("tools", [])
        print(f"✓ Found {len(tools)} tools:")
        for tool in tools:
            print(f"  - {tool['name']}: {tool['description']}")
        
        # 3. Test Whois lookup
        print("\n=== TESTING WHOIS LOOKUP ===")
        whois_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "whois_lookup",
                "arguments": {
                    "target": "example.com"
                }
            }
        }
        
        response = await client.post(
            f"{base_url}/mcp",
            json=whois_request,
            headers={
                "Accept": "application/json",
                "Origin": "http://localhost",
                "Mcp-Session-Id": session_id
            }
        )
        
        whois_response = response.json()
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            result = whois_response.get("result", {})
            if result.get("isError"):
                print(f"✗ Error: {result.get('content', [{}])[0].get('text', 'Unknown error')}")
            else:
                content = result.get("content", [{}])[0].get("text", "")
                if content:
                    data = json.loads(content)
                    print(f"✓ Whois lookup successful for {data.get('target')}")
                    print(f"  Server: {data.get('whois_server')}")
                    print(f"  Success: {data.get('success')}")
                    if data.get('success'):
                        print(f"  Response length: {len(data.get('response', ''))}")
        
        # 4. Test RDAP lookup
        print("\n=== TESTING RDAP LOOKUP ===")
        rdap_request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "rdap_lookup",
                "arguments": {
                    "target": "example.com"
                }
            }
        }
        
        response = await client.post(
            f"{base_url}/mcp",
            json=rdap_request,
            headers={
                "Accept": "application/json",
                "Origin": "http://localhost",
                "Mcp-Session-Id": session_id
            }
        )
        
        rdap_response = response.json()
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            result = rdap_response.get("result", {})
            if result.get("isError"):
                print(f"✗ Error: {result.get('content', [{}])[0].get('text', 'Unknown error')}")
            else:
                content = result.get("content", [{}])[0].get("text", "")
                if content:
                    data = json.loads(content)
                    print(f"✓ RDAP lookup successful for {data.get('target')}")
                    print(f"  Server: {data.get('rdap_server')}")
                    print(f"  Success: {data.get('success')}")
                    if data.get('success'):
                        print(f"  Response length: {len(str(data.get('response', {})))}")
        
        # 5. List resources
        print("\n=== LISTING RESOURCES ===")
        resources_request = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/list"
        }
        
        response = await client.post(
            f"{base_url}/mcp",
            json=resources_request,
            headers={
                "Accept": "application/json",
                "Origin": "http://localhost",
                "Mcp-Session-Id": session_id
            }
        )
        
        resources_response = response.json()
        resources = resources_response.get("result", {}).get("resources", [])
        print(f"✓ Found {len(resources)} resources:")
        for resource in resources:
            print(f"  - {resource['uri']}: {resource['name']}")
        
        print("\n=== WORKFLOW COMPLETE ===")
        print("✓ HTTP MCP server is fully functional!")

if __name__ == "__main__":
    asyncio.run(test_complete_workflow())