"""
HTTP Server with SSE support for MCP protocol.
Implements the Streamable HTTP transport as per MCP specification.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, AsyncIterator, Optional

import anyio
import structlog
from fastapi import FastAPI, HTTPException, Header, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from whoismcp.config import Config
from whoismcp.services.cache_service import CacheService
from whoismcp.services.rdap_service import RDAPService
from whoismcp.services.whois_service import WhoisService
from whoismcp.utils.rate_limiter import RateLimiter
from whoismcp.utils.validators import is_valid_domain, is_valid_ip

logger = structlog.get_logger(__name__)


class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 Request model."""
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[dict[str, Any]] = None


class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 Response model."""
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    result: Optional[Any] = None
    error: Optional[dict[str, Any]] = None


class BulkLookupRequest(BaseModel):
    """Request model for bulk lookups."""
    targets: list[str] = Field(..., description="List of domains/IPs to lookup")
    lookup_type: str = Field("whois", description="Type of lookup: 'whois' or 'rdap'")
    brief_mode: bool = Field(False, description="Return only essential information")
    brief_fields: Optional[list[str]] = Field(None, description="Specific fields to include in brief mode")
    use_cache: bool = Field(True, description="Whether to use cached results")
    max_concurrent: int = Field(10, description="Maximum concurrent lookups", ge=1, le=50)


class BriefLookupRequest(BaseModel):
    """Request model for brief lookups."""
    target: str = Field(..., description="Domain or IP to lookup")
    fields: Optional[list[str]] = Field(None, description="Specific fields to return")
    lookup_type: str = Field("whois", description="Type of lookup: 'whois' or 'rdap'")
    use_cache: bool = Field(True, description="Whether to use cached results")


class HTTPMCPServer:
    """HTTP Server implementing MCP Streamable HTTP transport."""
    
    def __init__(self):
        self.config = Config.from_env()
        self.whois_service = WhoisService(self.config)
        self.rdap_service = RDAPService(self.config)
        self.cache_service = CacheService(self.config)
        self.rate_limiter = RateLimiter(self.config)
        self.sessions: dict[str, dict] = {}
        
        # Server info
        self.server_info = {
            "name": "whoismcp-http",
            "version": "2.0.0",
            "protocolVersion": "2024-11-05"
        }
        
        # Available tools with brief mode support
        self.tools = [
            {
                "name": "whois_lookup",
                "description": "Perform Whois lookup for domain or IP address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Domain name or IP address to lookup"
                        },
                        "brief": {
                            "type": "boolean",
                            "description": "Return only essential information",
                            "default": False
                        },
                        "fields": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific fields to return in brief mode"
                        },
                        "use_cache": {
                            "type": "boolean",
                            "description": "Whether to use cached results",
                            "default": True
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "rdap_lookup",
                "description": "Perform RDAP lookup for domain or IP address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Domain name or IP address to lookup"
                        },
                        "brief": {
                            "type": "boolean",
                            "description": "Return only essential information",
                            "default": False
                        },
                        "fields": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific fields to return in brief mode"
                        },
                        "use_cache": {
                            "type": "boolean",
                            "description": "Whether to use cached results",
                            "default": True
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "bulk_lookup",
                "description": "Perform bulk lookups for multiple domains/IPs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of domains/IPs to lookup"
                        },
                        "lookup_type": {
                            "type": "string",
                            "enum": ["whois", "rdap"],
                            "description": "Type of lookup to perform",
                            "default": "whois"
                        },
                        "brief": {
                            "type": "boolean",
                            "description": "Return only essential information",
                            "default": False
                        },
                        "fields": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific fields to return in brief mode"
                        },
                        "use_cache": {
                            "type": "boolean",
                            "description": "Whether to use cached results",
                            "default": True
                        },
                        "max_concurrent": {
                            "type": "integer",
                            "description": "Maximum concurrent lookups",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 50
                        }
                    },
                    "required": ["targets"]
                }
            }
        ]
    
    def extract_brief_info(self, full_data: dict[str, Any], fields: Optional[list[str]] = None, target_type: str = "domain") -> dict[str, Any]:
        """Extract brief information from full lookup data."""
        if fields:
            # Return only requested fields
            brief = {}
            for field in fields:
                if field in full_data:
                    brief[field] = full_data[field]
                elif "parsed_data" in full_data and field in full_data["parsed_data"]:
                    brief[field] = full_data["parsed_data"][field]
            return brief
        
        # Default brief mode fields based on target type
        if target_type == "domain":
            default_fields = [
                "domain_name", "registrar", "creation_date", 
                "expiration_date", "name_servers", "status"
            ]
        else:  # IP
            default_fields = [
                "ip_address", "network_range", "organization",
                "country", "abuse_contact"
            ]
        
        brief = {
            "target": full_data.get("target"),
            "target_type": full_data.get("target_type"),
            "timestamp": full_data.get("timestamp", datetime.utcnow().isoformat())
        }
        
        # Extract from parsed_data if available
        if "parsed_data" in full_data:
            for field in default_fields:
                if field in full_data["parsed_data"]:
                    brief[field] = full_data["parsed_data"][field]
        
        # For RDAP, extract from response_data
        elif "response_data" in full_data:
            data = full_data["response_data"]
            if target_type == "domain":
                brief["domain_name"] = data.get("ldhName") or data.get("handle")
                brief["status"] = data.get("status", [])
                
                # Extract dates from events
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        brief["creation_date"] = event.get("eventDate")
                    elif event.get("eventAction") == "expiration":
                        brief["expiration_date"] = event.get("eventDate")
                
                # Extract nameservers
                brief["name_servers"] = []
                for ns in data.get("nameservers", []):
                    if ns.get("ldhName"):
                        brief["name_servers"].append(ns["ldhName"])
            else:  # IP
                brief["network_range"] = f"{data.get('startAddress', '')}-{data.get('endAddress', '')}"
                brief["organization"] = data.get("name")
                brief["country"] = data.get("country")
        
        return brief
    
    async def handle_single_lookup(self, target: str, lookup_type: str, brief: bool = False, 
                                  fields: Optional[list[str]] = None, use_cache: bool = True) -> dict[str, Any]:
        """Handle a single lookup request."""
        # Check rate limiting
        if not await self.rate_limiter.acquire("http_client"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Determine target type
        if is_valid_domain(target):
            target_type = "domain"
        elif is_valid_ip(target):
            target_type = "ip"
        else:
            raise ValueError(f"Invalid target: {target}")
        
        # Check cache
        cache_key = f"{lookup_type}:{target}"
        if use_cache:
            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                if brief:
                    return self.extract_brief_info(cached_result, fields, target_type)
                return cached_result
        
        # Perform lookup
        try:
            if lookup_type == "whois":
                service = self.whois_service
                if target_type == "domain":
                    result = await service.lookup_domain(target)
                else:
                    result = await service.lookup_ip(target)
            else:  # rdap
                service = self.rdap_service
                if target_type == "domain":
                    result = await service.lookup_domain(target)
                else:
                    result = await service.lookup_ip(target)
            
            # Cache result
            if use_cache and result.get("success"):
                await self.cache_service.set(cache_key, result)
            
            # Return brief or full result
            if brief:
                return self.extract_brief_info(result, fields, target_type)
            return result
            
        except Exception as e:
            logger.error(f"Lookup failed for {target}", error=str(e))
            raise
    
    async def handle_bulk_lookup(self, request: BulkLookupRequest) -> AsyncIterator[dict[str, Any]]:
        """Handle bulk lookup with structured concurrency."""
        semaphore = anyio.Semaphore(request.max_concurrent)
        
        async def lookup_with_semaphore(target: str) -> dict[str, Any]:
            async with semaphore:
                try:
                    result = await self.handle_single_lookup(
                        target=target,
                        lookup_type=request.lookup_type,
                        brief=request.brief_mode,
                        fields=request.brief_fields,
                        use_cache=request.use_cache
                    )
                    return {
                        "target": target,
                        "status": "success",
                        "data": result
                    }
                except Exception as e:
                    logger.error(f"Bulk lookup failed for {target}", error=str(e))
                    return {
                        "target": target,
                        "status": "error",
                        "error": str(e)
                    }
        
        # Create task group for structured concurrency
        async with anyio.create_task_group() as tg:
            # Create a memory object stream for results
            send_stream, receive_stream = anyio.create_memory_object_stream(max_buffer_size=len(request.targets))
            
            async def process_target(target: str):
                result = await lookup_with_semaphore(target)
                await send_stream.send(result)
            
            # Start all tasks
            for target in request.targets:
                tg.start_soon(process_target, target)
            
            # Close send stream when all tasks complete
            async def close_on_completion():
                await tg.__aexit__(None, None, None)
                await send_stream.aclose()
            
            tg.start_soon(close_on_completion)
            
            # Yield results as they complete
            async with receive_stream:
                async for result in receive_stream:
                    yield result
    
    async def process_jsonrpc_request(self, request: JSONRPCRequest, session_id: Optional[str] = None) -> JSONRPCResponse:
        """Process a single JSON-RPC request."""
        try:
            method = request.method
            params = request.params or {}
            
            # Handle different methods
            if method == "initialize":
                result = await self.handle_initialize(params, session_id)
            elif method == "tools/list":
                result = {"tools": self.tools}
            elif method == "tools/call":
                result = await self.handle_tool_call(params)
            else:
                return JSONRPCResponse(
                    id=request.id,
                    error={"code": -32601, "message": f"Method not found: {method}"}
                )
            
            return JSONRPCResponse(id=request.id, result=result)
            
        except Exception as e:
            logger.error(f"Request processing failed", error=str(e))
            return JSONRPCResponse(
                id=request.id,
                error={"code": -32603, "message": str(e)}
            )
    
    async def handle_initialize(self, params: dict[str, Any], session_id: Optional[str] = None) -> dict[str, Any]:
        """Handle initialization request."""
        # Create or update session
        if not session_id:
            session_id = str(uuid.uuid4())
        
        self.sessions[session_id] = {
            "initialized_at": datetime.utcnow().isoformat(),
            "client_info": params.get("clientInfo", {})
        }
        
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {}
            },
            "serverInfo": self.server_info,
            "sessionId": session_id
        }
    
    async def handle_tool_call(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle tool call request."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        try:
            if tool_name == "whois_lookup":
                result = await self.handle_single_lookup(
                    target=arguments.get("target"),
                    lookup_type="whois",
                    brief=arguments.get("brief", False),
                    fields=arguments.get("fields"),
                    use_cache=arguments.get("use_cache", True)
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]}
                
            elif tool_name == "rdap_lookup":
                result = await self.handle_single_lookup(
                    target=arguments.get("target"),
                    lookup_type="rdap",
                    brief=arguments.get("brief", False),
                    fields=arguments.get("fields"),
                    use_cache=arguments.get("use_cache", True)
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]}
                
            elif tool_name == "bulk_lookup":
                # For bulk lookup, we'll collect all results first
                request = BulkLookupRequest(**arguments)
                results = []
                async for result in self.handle_bulk_lookup(request):
                    results.append(result)
                return {"content": [{"type": "text", "text": json.dumps(results, indent=2, default=str)}]}
                
            else:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}]
                }
                
        except Exception as e:
            logger.error(f"Tool call failed", tool=tool_name, error=str(e))
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Tool execution failed: {str(e)}"}]
            }


# Create FastAPI app
app = FastAPI(title="WhoisMCP HTTP Server", version="2.0.0")
server = HTTPMCPServer()


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    await server.cache_service.start()
    logger.info("HTTP MCP Server started")


@app.post("/mcp")
async def mcp_endpoint(
    request: Request,
    accept: Optional[str] = Header(None),
    session_id: Optional[str] = Header(None, alias="X-Session-ID")
):
    """
    Main MCP endpoint supporting both JSON and SSE responses.
    Implements the Streamable HTTP transport specification.
    """
    # Parse request body
    try:
        body = await request.json()
    except Exception as e:
        return Response(
            content=json.dumps({"error": "Invalid JSON"}),
            status_code=400,
            media_type="application/json"
        )
    
    # Check if it's a batch request
    is_batch = isinstance(body, list)
    requests = body if is_batch else [body]
    
    # Parse requests
    parsed_requests = []
    for req in requests:
        try:
            parsed_requests.append(JSONRPCRequest(**req))
        except Exception as e:
            logger.error("Invalid request format", error=str(e))
            continue
    
    # Check if client accepts SSE
    accepts_sse = accept and "text/event-stream" in accept
    
    # Process requests
    responses = []
    has_bulk = any(r.method == "tools/call" and r.params and r.params.get("name") == "bulk_lookup" 
                   for r in parsed_requests)
    
    if accepts_sse and has_bulk:
        # Stream responses for bulk operations
        async def generate_sse():
            for req in parsed_requests:
                if req.method == "tools/call" and req.params.get("name") == "bulk_lookup":
                    # Stream bulk results
                    arguments = req.params.get("arguments", {})
                    bulk_request = BulkLookupRequest(**arguments)
                    
                    # Send initial response
                    yield {
                        "data": json.dumps({
                            "jsonrpc": "2.0",
                            "id": req.id,
                            "result": {
                                "streaming": True,
                                "total": len(bulk_request.targets)
                            }
                        })
                    }
                    
                    # Stream individual results
                    async for result in server.handle_bulk_lookup(bulk_request):
                        yield {
                            "data": json.dumps({
                                "jsonrpc": "2.0",
                                "id": req.id,
                                "result": {"item": result}
                            })
                        }
                    
                    # Send completion event
                    yield {
                        "data": json.dumps({
                            "jsonrpc": "2.0",
                            "id": req.id,
                            "result": {"complete": True}
                        })
                    }
                else:
                    # Regular request
                    response = await server.process_jsonrpc_request(req, session_id)
                    yield {"data": json.dumps(response.dict(exclude_none=True))}
        
        return EventSourceResponse(generate_sse())
    
    else:
        # Return JSON response
        for req in parsed_requests:
            response = await server.process_jsonrpc_request(req, session_id)
            responses.append(response.dict(exclude_none=True))
        
        # Return batch or single response
        if is_batch:
            return responses
        else:
            return responses[0] if responses else {"error": "No valid requests"}


@app.get("/mcp")
async def mcp_info():
    """GET endpoint returns server information."""
    return {
        "name": server.server_info["name"],
        "version": server.server_info["version"],
        "protocolVersion": server.server_info["protocolVersion"],
        "capabilities": {
            "streaming": True,
            "bulk": True,
            "brief": True
        }
    }


# Additional REST endpoints for convenience
@app.post("/lookup/brief")
async def brief_lookup(request: BriefLookupRequest):
    """Convenience endpoint for brief lookups."""
    try:
        result = await server.handle_single_lookup(
            target=request.target,
            lookup_type=request.lookup_type,
            brief=True,
            fields=request.fields,
            use_cache=request.use_cache
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/lookup/bulk")
async def bulk_lookup_stream(request: BulkLookupRequest):
    """Streaming endpoint for bulk lookups."""
    async def generate():
        async for result in server.handle_bulk_lookup(request):
            yield json.dumps(result) + "\n"
    
    return StreamingResponse(generate(), media_type="application/x-ndjson")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)