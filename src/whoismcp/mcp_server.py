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

        # Server info
        self.server_info = {"name": "whoismcp", "version": "1.0.0"}

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
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "check_domains_bulk",
                "description": "Check registration status of multiple domains efficiently. Returns succinct results with minimal token usage.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of domain names to check (max 100)",
                        },
                        "use_cache": {
                            "type": "boolean",
                            "description": "Whether to use cached results",
                            "default": True,
                        },
                    },
                    "required": ["domains"],
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
            elif tool_name == "check_domains_bulk":
                return await self._handle_bulk_check(arguments)
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

    async def _check_domain_status(
        self, domain: str, use_cache: bool = True
    ) -> tuple[str, str]:
        """
        Check if a domain is registered using RDAP.
        Returns (domain, status) where status is "registered", "available", or "error".
        """
        # Check cache first
        cache_key = f"bulk_check:{domain}"
        if use_cache:
            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                return (domain, cached_result)

        try:
            # Use RDAP for quick lookup
            result = await self.rdap_service.lookup_domain(domain)

            if result.get("success"):
                # Check if domain has data indicating it's registered
                response_data = result.get("response_data", {})

                # RDAP returns data for registered domains
                # Check for common indicators of registration
                if response_data.get("objectClassName") == "domain":
                    # Domain exists in RDAP, it's registered
                    status = "registered"
                elif "ldhName" in response_data or "handle" in response_data:
                    # Has domain name or handle field, it's registered
                    status = "registered"
                elif "status" in response_data:
                    # Has status field (even if empty list), likely registered
                    status = "registered"
                else:
                    # No clear data, consider available
                    status = "available"
            else:
                # RDAP lookup failed or returned no data
                error = result.get("error", "")
                if "not found" in error.lower() or "404" in error:
                    status = "available"
                else:
                    status = "error"

            # Cache the result
            if use_cache:
                await self.cache_service.set(cache_key, status)

            return (domain, status)

        except Exception as e:
            logger.error("Domain check failed", domain=domain, error=str(e))
            return (domain, "error")

    async def _handle_bulk_check(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle bulk domain check tool call."""
        domains = arguments.get("domains", [])
        use_cache = arguments.get("use_cache", True)

        if not domains:
            return {
                "isError": True,
                "content": [
                    {"type": "text", "text": "Missing required argument: domains"}
                ],
            }

        # Validate domain count
        if len(domains) > self.config.bulk_check_max_domains:
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": f"Too many domains. Maximum allowed: {self.config.bulk_check_max_domains}",
                    }
                ],
            }

        # Validate all domains
        invalid_domains = [d for d in domains if not is_valid_domain(d)]
        if invalid_domains:
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": f"Invalid domain names: {', '.join(invalid_domains[:5])}",
                    }
                ],
            }

        # Check rate limiting (use fewer tokens for bulk operation)
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

        try:
            # Process domains concurrently with limit
            semaphore = asyncio.Semaphore(self.config.bulk_check_concurrency)

            async def check_with_limit(domain: str) -> tuple[str, str]:
                async with semaphore:
                    return await self._check_domain_status(domain, use_cache)

            # Run all checks concurrently
            results = await asyncio.gather(
                *[check_with_limit(domain) for domain in domains]
            )

            # Format results as simple dict
            result_dict = {domain: status for domain, status in results}

            # Return succinct JSON format
            return {
                "content": [
                    {"type": "text", "text": json.dumps(result_dict, indent=2)}
                ]
            }

        except Exception as e:
            logger.error("Bulk check failed", error=str(e))
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Bulk check failed: {str(e)}"}],
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
