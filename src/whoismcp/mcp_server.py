#!/usr/bin/env python3
"""
MCP Server for Whois/RDAP lookups using stdio communication.
This implements the Model Context Protocol specification for AI integration.
"""

import asyncio
import json
import logging
import sys
from typing import Any

import structlog

from whoismcp.config import Config
from whoismcp.services.cache_service import CacheService
from whoismcp.services.rdap_service import RDAPService
from whoismcp.services.whois_service import WhoisService
from whoismcp.services.concurrent_service import ConcurrentLookupService
from whoismcp.utils.rate_limiter import RateLimiter
from whoismcp.utils.validators import is_valid_domain, is_valid_ip

# Configure structlog to output to stderr for MCP compatibility
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logging.basicConfig(stream=sys.stderr, level=logging.INFO, force=True)
logger = structlog.get_logger(__name__)


class MCPServer:
    """MCP Server that communicates via stdin/stdout."""

    def __init__(self) -> None:
        self.config = Config.from_env()
        self.whois_service = WhoisService(self.config)
        self.rdap_service = RDAPService(self.config)
        self.cache_service = CacheService(self.config)
        self.rate_limiter = RateLimiter(self.config)
        self.concurrent_service = ConcurrentLookupService(self.config)

        # Server info
        self.server_info = {"name": "whoismcp", "version": "2.0.0"}

        # Define available tools
        self.tools = [
            {
                "name": "whois_lookup",
                "description": "Perform Whois lookup for domain or IP address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Domain name or IP address to lookup",
                        },
                        "use_cache": {
                            "type": "boolean",
                            "description": "Whether to use cached results",
                            "default": True,
                        },
                        "brief": {
                            "type": "boolean",
                            "description": "Return only essential information",
                            "default": False,
                        },
                        "fields": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific fields to return in brief mode",
                        },
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "rdap_lookup",
                "description": "Perform RDAP lookup for domain or IP address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Domain name or IP address to lookup",
                        },
                        "use_cache": {
                            "type": "boolean",
                            "description": "Whether to use cached results",
                            "default": True,
                        },
                        "brief": {
                            "type": "boolean",
                            "description": "Return only essential information",
                            "default": False,
                        },
                        "fields": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific fields to return in brief mode",
                        },
                    },
                    "required": ["target"],
                },
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
                            "description": "List of domains/IPs to lookup",
                        },
                        "lookup_type": {
                            "type": "string",
                            "enum": ["whois", "rdap"],
                            "description": "Type of lookup to perform",
                            "default": "whois",
                        },
                        "brief": {
                            "type": "boolean",
                            "description": "Return only essential information",
                            "default": False,
                        },
                        "use_cache": {
                            "type": "boolean",
                            "description": "Whether to use cached results",
                            "default": True,
                        },
                        "max_concurrent": {
                            "type": "integer",
                            "description": "Maximum concurrent lookups",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 50,
                        },
                    },
                    "required": ["targets"],
                },
            },
        ]

        # Define available resources
        self.resources = [
            {
                "uri": "whois://config",
                "name": "Whois Server Configuration",
                "description": "Current configuration for Whois servers and settings",
                "mimeType": "application/json"
            },
            {
                "uri": "rdap://config", 
                "name": "RDAP Server Configuration",
                "description": "Current configuration for RDAP servers and settings",
                "mimeType": "application/json"
            },
            {
                "uri": "cache://stats",
                "name": "Cache Statistics",
                "description": "Current cache usage and performance statistics",
                "mimeType": "application/json"
            },
            {
                "uri": "rate-limit://status",
                "name": "Rate Limit Status",
                "description": "Current rate limiting status and configuration",
                "mimeType": "application/json"
            }
        ]

    def write_message(self, message: dict[str, Any]) -> None:
        """Write a message to stdout."""
        json_str = json.dumps(message)
        print(json_str, flush=True)

    def read_message(self) -> dict[str, Any] | None:
        """Read a message from stdin."""
        try:
            line = sys.stdin.readline()
            if not line:
                return None
            return json.loads(line.strip())
        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON", error=str(e))
            return None
        except Exception as e:
            logger.error("Failed to read message", error=str(e))
            return None
    
    def extract_brief_info(self, full_data: dict[str, Any], fields: list[str] | None = None, target_type: str = "domain") -> dict[str, Any]:
        """Extract brief information from full lookup data."""
        from datetime import datetime
        
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

    async def handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle MCP initialize request."""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": self.server_info,
        }

    async def handle_list_tools(self) -> dict[str, Any]:
        """Handle tools/list request."""
        return {"tools": self.tools}

    async def handle_list_resources(self) -> dict[str, Any]:
        """Handle resources/list request."""
        return {"resources": self.resources}

    async def handle_call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle tools/call request."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        try:
            if tool_name == "whois_lookup":
                return await self._handle_whois_lookup(arguments)
            elif tool_name == "rdap_lookup":
                return await self._handle_rdap_lookup(arguments)
            elif tool_name == "bulk_lookup":
                return await self._handle_bulk_lookup(arguments)
            else:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                }
        except Exception as e:
            logger.error("Tool call failed", tool=tool_name, error=str(e))
            return {
                "isError": True,
                "content": [
                    {"type": "text", "text": f"Tool execution failed: {str(e)}"}
                ],
            }

    async def _handle_whois_lookup(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle whois lookup tool call."""
        target = arguments.get("target")
        use_cache = arguments.get("use_cache", True)
        brief = arguments.get("brief", False)
        fields = arguments.get("fields")

        if not target:
            return {
                "isError": True,
                "content": [
                    {"type": "text", "text": "Missing required argument: target"}
                ],
            }

        # Check rate limiting
        if not await self.rate_limiter.acquire("mcp_client"):
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": "Rate limit exceeded. Please try again later.",
                    }
                ],
            }

        # Check cache if enabled
        cache_key = f"whois:{target}"
        if use_cache:
            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                # Apply brief mode if requested
                if brief:
                    target_type = "domain" if is_valid_domain(target) else "ip"
                    cached_result = self.extract_brief_info(cached_result, fields, target_type)
                return {
                    "content": [
                        {"type": "text", "text": json.dumps(cached_result, indent=2)}
                    ]
                }

        # Determine if target is domain or IP and call appropriate method
        try:
            if is_valid_domain(target):
                result_dict = await self.whois_service.lookup_domain(target)
            elif is_valid_ip(target):
                result_dict = await self.whois_service.lookup_ip(target)
            else:
                return {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Invalid target format: {target}. Must be a domain name or IP address.",
                        }
                    ],
                }

            # Cache result if successful
            if use_cache and result_dict.get("success"):
                await self.cache_service.set(cache_key, result_dict)
            
            # Apply brief mode if requested
            if brief:
                target_type = result_dict.get("target_type", "domain")
                result_dict = self.extract_brief_info(result_dict, fields, target_type)

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result_dict, indent=2, default=str),
                    }
                ]
            }

        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Whois lookup failed: {str(e)}"}],
            }

    async def _handle_rdap_lookup(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle RDAP lookup tool call."""
        target = arguments.get("target")
        use_cache = arguments.get("use_cache", True)
        brief = arguments.get("brief", False)
        fields = arguments.get("fields")

        if not target:
            return {
                "isError": True,
                "content": [
                    {"type": "text", "text": "Missing required argument: target"}
                ],
            }

        # Check rate limiting
        if not await self.rate_limiter.acquire("mcp_client"):
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": "Rate limit exceeded. Please try again later.",
                    }
                ],
            }

        # Check cache if enabled
        cache_key = f"rdap:{target}"
        if use_cache:
            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                # Apply brief mode if requested
                if brief:
                    target_type = "domain" if is_valid_domain(target) else "ip"
                    cached_result = self.extract_brief_info(cached_result, fields, target_type)
                return {
                    "content": [
                        {"type": "text", "text": json.dumps(cached_result, indent=2)}
                    ]
                }

        # Determine if target is domain or IP and call appropriate method
        try:
            if is_valid_domain(target):
                result_dict = await self.rdap_service.lookup_domain(target)
            elif is_valid_ip(target):
                result_dict = await self.rdap_service.lookup_ip(target)
            else:
                return {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Invalid target format: {target}. Must be a domain name or IP address.",
                        }
                    ],
                }

            # Cache result if successful
            if use_cache and result_dict.get("success"):
                await self.cache_service.set(cache_key, result_dict)
            
            # Apply brief mode if requested
            if brief:
                target_type = result_dict.get("target_type", "domain")
                result_dict = self.extract_brief_info(result_dict, fields, target_type)

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result_dict, indent=2, default=str),
                    }
                ]
            }

        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"RDAP lookup failed: {str(e)}"}],
            }
    
    async def _handle_bulk_lookup(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle bulk lookup tool call."""
        targets = arguments.get("targets", [])
        lookup_type = arguments.get("lookup_type", "whois")
        use_cache = arguments.get("use_cache", True)
        max_concurrent = arguments.get("max_concurrent", 10)
        brief = arguments.get("brief", False)
        
        if not targets:
            return {
                "isError": True,
                "content": [
                    {"type": "text", "text": "Missing required argument: targets"}
                ],
            }
        
        try:
            results = []
            # Use concurrent service for bulk operations
            async for result in self.concurrent_service.bulk_lookup(
                targets=targets,
                lookup_type=lookup_type,
                use_cache=use_cache,
                max_concurrent=max_concurrent
            ):
                # Convert to dict for serialization
                result_dict = {
                    "target": result.target,
                    "status": result.status,
                    "from_cache": result.from_cache,
                    "timestamp": result.timestamp.isoformat() if result.timestamp else None
                }
                
                if result.status == "success" and result.data:
                    # Apply brief mode if requested
                    if brief:
                        target_type = result.data.get("target_type", "domain")
                        result_dict["data"] = self.extract_brief_info(result.data, None, target_type)
                    else:
                        result_dict["data"] = result.data
                elif result.error:
                    result_dict["error"] = result.error
                
                results.append(result_dict)
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "total": len(results),
                            "results": results
                        }, indent=2, default=str),
                    }
                ]
            }
            
        except Exception as e:
            logger.error("Bulk lookup failed", error=str(e))
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Bulk lookup failed: {str(e)}"}],
            }

    async def handle_read_resource(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle resources/read request."""
        uri = params.get("uri", "")

        try:
            if uri == "whois://config":
                config_data = {
                    "whois_timeout": self.config.whois_timeout,
                    "whois_servers": getattr(self.whois_service, 'WHOIS_SERVERS', {}),
                    "max_retries": self.config.max_retries,
                    "retry_delay": self.config.retry_delay
                }
                return {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(config_data, indent=2, default=str),
                        }
                    ]
                }
            elif uri == "rdap://config":
                config_data = {
                    "rdap_timeout": self.config.rdap_timeout,
                    "rdap_servers": getattr(self.rdap_service, 'RDAP_SERVERS', {}),
                    "max_connections": self.config.max_connections,
                    "max_keepalive_connections": self.config.max_keepalive_connections
                }
                return {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(config_data, indent=2, default=str),
                        }
                    ]
                }
            elif uri == "cache://stats":
                stats_data = {
                    "cache_size": len(self.cache_service._cache),
                    "cache_max_size": self.config.cache_max_size,
                    "cache_ttl": self.config.cache_ttl,
                    "cache_cleanup_interval": self.config.cache_cleanup_interval
                }
                return {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(stats_data, indent=2, default=str),
                        }
                    ]
                }
            elif uri == "rate-limit://status":
                rate_limit_data = {
                    "global_rate_limit_per_second": self.config.global_rate_limit_per_second,
                    "global_rate_limit_burst": self.config.global_rate_limit_burst,
                    "client_rate_limit_per_second": self.config.client_rate_limit_per_second,
                    "client_rate_limit_burst": self.config.client_rate_limit_burst,
                    "active_clients": len(self.rate_limiter.client_buckets)
                }
                return {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(rate_limit_data, indent=2, default=str),
                        }
                    ]
                }
            else:
                return {
                    "isError": True,
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/plain",
                            "text": f"Unsupported resource URI: {uri}",
                        }
                    ],
                }
        except Exception as e:
            logger.error("Resource read failed", uri=uri, error=str(e))
            return {
                "isError": True,
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": f"Failed to read resource: {str(e)}",
                    }
                ],
            }

    async def process_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Process a JSON-RPC request."""
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")

        if request_id is None:
            logger.debug(f"Received notification {method}")

            if method == "notifications/initialized":
                # Handle initialize notification
                logger.info("Client initialized notification received")

            return None

        try:
            if method == "initialize":
                result = await self.handle_initialize(params)
            elif method == "tools/list":
                result = await self.handle_list_tools()
            elif method == "tools/call":
                result = await self.handle_call_tool(params)
            elif method == "resources/list":
                result = await self.handle_list_resources()
            elif method == "resources/read":
                result = await self.handle_read_resource(params)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }

            return {"jsonrpc": "2.0", "id": request_id, "result": result}

        except Exception as e:
            logger.error("Request processing failed", method=method, error=str(e))
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
            }

    async def run(self) -> None:
        """Main server loop."""
        logger.info("MCP stdio server starting")

        # Start cache service
        await self.cache_service.start()

        try:
            while True:
                # Read request from stdin
                request = self.read_message()
                if request is None:
                    break

                # Process request
                response = await self.process_request(request)

                if response is not None:
                    self.write_message(response)

        except KeyboardInterrupt:
            logger.info("Server shutting down")
        except Exception as e:
            logger.error("Server error", error=str(e))
            raise


def main() -> None:
    """Main entry point."""

    async def run_server():
        server = MCPServer()
        await server.run()

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
