#!/usr/bin/env python3
"""
Example HTTP MCP client demonstrating how to use the WhoisMCP HTTP server.

This example shows:
1. How to establish a session with the HTTP MCP server
2. How to list available tools and resources
3. How to perform Whois and RDAP lookups
4. How to access server configuration and statistics
5. Proper session management and cleanup

Usage:
    python examples/http_mcp_client.py
"""

import asyncio
import json
import sys
from typing import Dict, Any, Optional
import httpx

class MCPHttpClient:
    """
    Simple HTTP MCP client for interacting with WhoisMCP HTTP server.
    """
    
    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url
        self.session_id: Optional[str] = None
        self.message_id = 0
        
    def _next_id(self) -> int:
        """Get next message ID."""
        self.message_id += 1
        return self.message_id
    
    async def initialize(self) -> Dict[str, Any]:
        """Initialize MCP session."""
        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/mcp",
                json=request,
                headers={
                    "Accept": "application/json",
                    "Origin": "http://localhost"
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to initialize: {response.status_code}")
            
            self.session_id = response.headers.get("Mcp-Session-Id")
            if not self.session_id:
                raise Exception("No session ID received")
            
            return response.json()
    
    async def _send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a request to the MCP server."""
        if not self.session_id:
            raise Exception("Not initialized - call initialize() first")
        
        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method
        }
        
        if params:
            request["params"] = params
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/mcp",
                json=request,
                headers={
                    "Accept": "application/json",
                    "Origin": "http://localhost",
                    "Mcp-Session-Id": self.session_id
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Request failed: {response.status_code} - {response.text}")
            
            return response.json()
    
    async def list_tools(self) -> Dict[str, Any]:
        """List available tools."""
        return await self._send_request("tools/list")
    
    async def list_resources(self) -> Dict[str, Any]:
        """List available resources."""
        return await self._send_request("resources/list")
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool with arguments."""
        return await self._send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })
    
    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource by URI."""
        return await self._send_request("resources/read", {"uri": uri})
    
    async def whois_lookup(self, target: str, use_cache: bool = True) -> Dict[str, Any]:
        """Perform Whois lookup."""
        return await self.call_tool("whois_lookup", {
            "target": target,
            "use_cache": use_cache
        })
    
    async def rdap_lookup(self, target: str, use_cache: bool = True) -> Dict[str, Any]:
        """Perform RDAP lookup."""
        return await self.call_tool("rdap_lookup", {
            "target": target,
            "use_cache": use_cache
        })
    
    async def close_session(self) -> None:
        """Close the session."""
        if self.session_id:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.delete(
                        f"{self.base_url}/mcp",
                        headers={
                            "Mcp-Session-Id": self.session_id,
                            "Origin": "http://localhost"
                        }
                    )
            except Exception as e:
                print(f"Warning: Failed to close session: {e}")
            finally:
                self.session_id = None


async def main():
    """Main example function."""
    client = MCPHttpClient()
    
    try:
        # Initialize session
        print("=== Initializing MCP Session ===")
        init_result = await client.initialize()
        print(f"✓ Session initialized: {client.session_id}")
        print(f"  Protocol version: {init_result['result']['protocolVersion']}")
        print(f"  Server: {init_result['result']['serverInfo']['name']} v{init_result['result']['serverInfo']['version']}")
        
        # List available tools
        print("\n=== Available Tools ===")
        tools_result = await client.list_tools()
        tools = tools_result["result"]["tools"]
        for tool in tools:
            print(f"• {tool['name']}: {tool['description']}")
        
        # List available resources
        print("\n=== Available Resources ===")
        resources_result = await client.list_resources()
        resources = resources_result["result"]["resources"]
        for resource in resources:
            print(f"• {resource['uri']}: {resource['name']}")
        
        # Test domain lookups
        domain = "example.com"
        print(f"\n=== Testing Lookups for {domain} ===")
        
        # Whois lookup
        print("Performing Whois lookup...")
        whois_result = await client.whois_lookup(domain)
        result = whois_result["result"]
        if result.get("isError"):
            print(f"✗ Whois error: {result['content'][0]['text']}")
        else:
            content = json.loads(result["content"][0]["text"])
            print(f"✓ Whois lookup successful")
            print(f"  Target: {content['target']}")
            print(f"  Server: {content['whois_server']}")
            print(f"  Success: {content['success']}")
        
        # RDAP lookup
        print("Performing RDAP lookup...")
        rdap_result = await client.rdap_lookup(domain)
        result = rdap_result["result"]
        if result.get("isError"):
            print(f"✗ RDAP error: {result['content'][0]['text']}")
        else:
            content = json.loads(result["content"][0]["text"])
            print(f"✓ RDAP lookup successful")
            print(f"  Target: {content['target']}")
            print(f"  Server: {content['rdap_server']}")
            print(f"  Success: {content['success']}")
        
        # Read configuration resource
        print("\n=== Reading Configuration ===")
        config_result = await client.read_resource("whois://config")
        result = config_result["result"]
        if result.get("isError"):
            print(f"✗ Config error: {result['content'][0]['text']}")
        else:
            # Resources return 'contents' array instead of 'content'
            config = json.loads(result["contents"][0]["text"])
            print(f"✓ Configuration loaded")
            print(f"  Whois timeout: {config.get('whois_timeout', 'N/A')}s")
            print(f"  RDAP timeout: {config.get('rdap_timeout', 'N/A')}s")
            print(f"  Cache TTL: {config.get('cache_ttl', 'N/A')}s")
        
        # Read cache statistics
        print("\n=== Cache Statistics ===")
        stats_result = await client.read_resource("cache://stats")
        result = stats_result["result"]
        if result.get("isError"):
            print(f"✗ Stats error: {result['content'][0]['text']}")
        else:
            stats = json.loads(result["contents"][0]["text"])
            print(f"✓ Cache statistics")
            print(f"  Size: {stats.get('size', 'N/A')}")
            print(f"  Max size: {stats.get('max_size', 'N/A')}")
            print(f"  Hit rate: {stats.get('hit_rate', 'N/A')}%")
        
        print("\n=== Example Complete ===")
        print("✓ All HTTP MCP operations completed successfully!")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return 1
    finally:
        await client.close_session()
    
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))