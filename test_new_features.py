#!/usr/bin/env python3
"""
Test script for new WhoisMCP features:
1. SSE/Streamable HTTP support
2. Brief response mode  
3. Bulk lookup with structured concurrency
"""

import asyncio
import json
import httpx


async def test_http_server():
    """Test the HTTP server endpoints."""
    base_url = "http://localhost:8000"
    
    async with httpx.AsyncClient() as client:
        # Test server info
        print("Testing server info...")
        response = await client.get(f"{base_url}/mcp")
        print(f"Server info: {response.json()}")
        
        # Test brief lookup
        print("\n\nTesting brief lookup...")
        brief_request = {
            "target": "example.com",
            "lookup_type": "whois",
            "fields": ["domain_name", "registrar", "expiration_date"]
        }
        response = await client.post(f"{base_url}/lookup/brief", json=brief_request)
        print(f"Brief lookup result: {json.dumps(response.json(), indent=2)}")
        
        # Test bulk lookup
        print("\n\nTesting bulk lookup...")
        bulk_request = {
            "targets": ["google.com", "github.com", "cloudflare.com"],
            "lookup_type": "whois",
            "brief_mode": True,
            "max_concurrent": 3
        }
        
        # Stream bulk results
        async with client.stream("POST", f"{base_url}/lookup/bulk", json=bulk_request) as response:
            async for line in response.aiter_lines():
                if line:
                    result = json.loads(line)
                    print(f"Bulk result: {result['target']} - {result['status']}")


async def test_mcp_endpoint():
    """Test the MCP protocol endpoint."""
    base_url = "http://localhost:8000"
    
    async with httpx.AsyncClient() as client:
        # Initialize session
        print("\n\nTesting MCP protocol...")
        init_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {}
        }
        
        response = await client.post(
            f"{base_url}/mcp",
            json=init_request,
            headers={"Accept": "application/json"}
        )
        print(f"Initialize response: {json.dumps(response.json(), indent=2)}")
        
        # Test whois lookup with brief mode
        print("\n\nTesting whois lookup with brief mode...")
        lookup_request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 2,
            "params": {
                "name": "whois_lookup",
                "arguments": {
                    "target": "example.com",
                    "brief": True,
                    "fields": ["domain_name", "registrar", "expiration_date"]
                }
            }
        }
        
        response = await client.post(
            f"{base_url}/mcp",
            json=lookup_request,
            headers={"Accept": "application/json"}
        )
        print(f"Whois lookup response: {json.dumps(response.json(), indent=2)}")
        
        # Test bulk lookup
        print("\n\nTesting bulk lookup via MCP...")
        bulk_request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 3,
            "params": {
                "name": "bulk_lookup",
                "arguments": {
                    "targets": ["google.com", "github.com"],
                    "lookup_type": "rdap",
                    "brief": True,
                    "max_concurrent": 2
                }
            }
        }
        
        # Test with SSE for streaming
        response = await client.post(
            f"{base_url}/mcp",
            json=bulk_request,
            headers={"Accept": "text/event-stream"}
        )
        
        print(f"Bulk lookup streaming started...")
        async for line in response.aiter_lines():
            if line.startswith("data: "):
                data = json.loads(line[6:])
                print(f"SSE Event: {json.dumps(data, indent=2)}")


async def test_stdio_server():
    """Test the stdio MCP server with new features."""
    print("\n\nTesting stdio MCP server...")
    
    # Create process for stdio server
    proc = await asyncio.create_subprocess_exec(
        "python", "-m", "whoismcp.mcp_server",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    try:
        # Initialize
        init_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {}
        }) + "\n"
        
        proc.stdin.write(init_msg.encode())
        await proc.stdin.drain()
        
        # Read response
        response = await proc.stdout.readline()
        print(f"Init response: {response.decode()}")
        
        # Test brief whois lookup
        lookup_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 2,
            "params": {
                "name": "whois_lookup",
                "arguments": {
                    "target": "example.com",
                    "brief": True
                }
            }
        }) + "\n"
        
        proc.stdin.write(lookup_msg.encode())
        await proc.stdin.drain()
        
        response = await proc.stdout.readline()
        print(f"Brief lookup response: {response.decode()}")
        
        # Test bulk lookup
        bulk_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 3,
            "params": {
                "name": "bulk_lookup",
                "arguments": {
                    "targets": ["google.com", "github.com"],
                    "lookup_type": "whois",
                    "brief": True,
                    "max_concurrent": 2
                }
            }
        }) + "\n"
        
        proc.stdin.write(bulk_msg.encode())
        await proc.stdin.drain()
        
        response = await proc.stdout.readline()
        result = json.loads(response.decode())
        print(f"Bulk lookup response: {json.dumps(result, indent=2)}")
        
    finally:
        proc.terminate()
        await proc.wait()


async def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing New WhoisMCP Features")
    print("=" * 60)
    
    # Test HTTP server (make sure it's running first)
    try:
        await test_http_server()
        await test_mcp_endpoint()
    except httpx.ConnectError:
        print("\n⚠️  HTTP server not running. Start it with: whoismcp http-server")
    
    # Test stdio server
    await test_stdio_server()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())