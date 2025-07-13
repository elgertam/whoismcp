# HTTP MCP Server for WhoisMCP

This document provides comprehensive information about the HTTP transport implementation for the WhoisMCP server, supporting remote access through the Streamable HTTP MCP protocol.

## Overview

The HTTP MCP server provides a web-based interface to the WhoisMCP functionality, allowing remote clients to access Whois and RDAP lookup services through HTTP requests. This implementation follows the MCP Streamable HTTP specification (version 2025-03-26).

## Features

- **Full MCP Protocol Support**: Complete implementation of JSON-RPC 2.0 over HTTP
- **Session Management**: Secure session handling with cryptographic session IDs
- **Multiple Transport Methods**: Both synchronous POST and asynchronous GET (Server-Sent Events)
- **Security Features**: Origin validation, DNS rebinding protection, secure session management
- **Resource Management**: Automatic session cleanup, connection pooling, rate limiting
- **Error Handling**: Comprehensive error responses with proper HTTP status codes
- **Resumable Connections**: Support for Last-Event-ID header for connection resumption

## Quick Start

### Starting the HTTP Server

```bash
# Using the CLI command
whoismcp serve-http --host 0.0.0.0 --port 5001

# Or using the direct module
python -m whoismcp.http_server

# Or using the entry point
whoismcp-http
```

### Testing the Server

```bash
# Check health status
curl http://localhost:5001/health

# Test MCP endpoint
curl -X POST http://localhost:5001/mcp \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}}'
```

## API Endpoints

### Health Check
- **URL**: `/health`
- **Method**: GET
- **Response**: JSON with server status and session count

### MCP Endpoint
- **URL**: `/mcp`
- **Methods**: POST, GET, DELETE
- **Content-Type**: `application/json` (POST), `text/event-stream` (GET)

## Client Implementation

### Example HTTP Client

```python
import asyncio
import json
import httpx

class MCPHttpClient:
    def __init__(self, base_url="http://localhost:5001"):
        self.base_url = base_url
        self.session_id = None
        self.message_id = 0
    
    async def initialize(self):
        """Initialize MCP session"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/mcp",
                json=request,
                headers={
                    "Accept": "application/json",
                    "Origin": "http://localhost"
                }
            )
            
            self.session_id = response.headers.get("Mcp-Session-Id")
            return response.json()
    
    async def whois_lookup(self, domain):
        """Perform Whois lookup"""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "whois_lookup",
                "arguments": {"target": domain}
            }
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/mcp",
                json=request,
                headers={
                    "Accept": "application/json",
                    "Origin": "http://localhost",
                    "Mcp-Session-Id": self.session_id
                }
            )
            return response.json()

# Usage
async def main():
    client = MCPHttpClient()
    await client.initialize()
    result = await client.whois_lookup("example.com")
    print(json.dumps(result, indent=2))

asyncio.run(main())
```

## MCP Protocol Support

### Available Tools

1. **whois_lookup**: Perform Whois lookup for domain or IP address
   - Parameters: `target` (string), `use_cache` (boolean, optional)
   - Returns: JSON with lookup results

2. **rdap_lookup**: Perform RDAP lookup for domain or IP address
   - Parameters: `target` (string), `use_cache` (boolean, optional)
   - Returns: JSON with structured RDAP data

### Available Resources

1. **whois://config**: Whois server configuration
2. **rdap://config**: RDAP server configuration
3. **cache://stats**: Cache usage statistics
4. **rate-limit://status**: Rate limiting status

### Session Management

- Sessions are created automatically on first request
- Session IDs are cryptographically secure (256-bit)
- Sessions expire after 1 hour of inactivity
- Background cleanup removes expired sessions every 5 minutes

### Security Features

- **Origin Validation**: Prevents DNS rebinding attacks
- **Session Validation**: Secure session ID format validation
- **Rate Limiting**: Per-client and global rate limiting
- **Error Handling**: Comprehensive error responses

## Configuration

The HTTP server uses the same configuration system as the stdio server:

```bash
# Environment variables
export BIND_HOST=0.0.0.0
export BIND_PORT=5001
export WHOIS_TIMEOUT=30
export RDAP_TIMEOUT=30
export CACHE_TTL=3600
export GLOBAL_RATE_LIMIT_PER_SECOND=10.0
export CLIENT_RATE_LIMIT_PER_SECOND=2.0
```

## Integration Examples

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "whoismcp-http": {
      "command": "whoismcp-http",
      "args": ["--host", "127.0.0.1", "--port", "5001"]
    }
  }
}
```

### JavaScript/TypeScript Client

```typescript
interface MCPRequest {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params?: any;
}

class MCPHttpClient {
  private sessionId?: string;
  private baseUrl: string;
  
  constructor(baseUrl = "http://localhost:5001") {
    this.baseUrl = baseUrl;
  }
  
  async initialize(): Promise<any> {
    const request: MCPRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {}
      }
    };
    
    const response = await fetch(`${this.baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost"
      },
      body: JSON.stringify(request)
    });
    
    this.sessionId = response.headers.get("Mcp-Session-Id") || undefined;
    return response.json();
  }
  
  async whoisLookup(domain: string): Promise<any> {
    const request: MCPRequest = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "whois_lookup",
        arguments: { target: domain }
      }
    };
    
    const response = await fetch(`${this.baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "http://localhost",
        "Mcp-Session-Id": this.sessionId!
      },
      body: JSON.stringify(request)
    });
    
    return response.json();
  }
}
```

## Production Deployment

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install -e .

EXPOSE 5001

CMD ["whoismcp-http", "--host", "0.0.0.0", "--port", "5001"]
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Support for Server-Sent Events
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }
}
```

## Error Handling

The HTTP server provides comprehensive error handling:

- **400 Bad Request**: Invalid JSON or missing parameters
- **403 Forbidden**: Invalid origin or security violation
- **404 Not Found**: Session not found or invalid endpoint
- **500 Internal Server Error**: Server processing error

Example error response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "Invalid Request",
    "data": "Session ID required"
  }
}
```

## Performance Considerations

- **Connection Pooling**: HTTP client uses connection pooling for efficiency
- **Rate Limiting**: Built-in rate limiting prevents abuse
- **Caching**: Automatic caching of lookup results
- **Session Management**: Efficient session cleanup and memory management
- **Async Processing**: Full async/await support for high concurrency

## Monitoring and Observability

The HTTP server provides detailed structured logging:

```python
# Example log output
INFO:__main__:2025-07-13T03:35:32.132627Z [info] Created new MCP session [__main__] session_id=c5b69757-3d35-426f-8229-4ad4650b151e
INFO:whoismcp.services.whois_service:2025-07-13T03:35:32.215969Z [info] Starting domain whois lookup [whoismcp.services.whois_service] domain=example.com
INFO:whoismcp.services.whois_service:2025-07-13T03:35:32.281057Z [info] Domain whois lookup completed successfully [whoismcp.services.whois_service] domain=example.com server=whois.verisign-grs.com
```

## Contributing

When contributing to the HTTP MCP server:

1. Follow the existing code style and patterns
2. Add comprehensive tests for new features
3. Update documentation for any API changes
4. Ensure security best practices are followed
5. Test with multiple concurrent clients

## License

This HTTP MCP server implementation is released under the MIT License, same as the main WhoisMCP project.