#!/usr/bin/env python3
"""
MCP Server for Whois/RDAP lookups using SSE (Server-Sent Events) transport.
This allows remote access to the MCP server via HTTP/HTTPS.
"""

import asyncio
import json
import uuid
from typing import Any

import structlog
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from whoismcp.config import Config
from whoismcp.mcp_core import MCPServerCore

# Configure structlog
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

logger = structlog.get_logger(__name__)


class SSEMCPServer:
    """MCP Server that communicates via SSE over HTTP."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.from_env()
        # Use shared core implementation with SSE-specific rate limit ID
        self.core = MCPServerCore(self.config, rate_limit_client_id="sse_client")

        # Session management (for future SSE streaming support)
        self.sessions: dict[str, dict[str, Any]] = {}


# Create global server instance
_server: SSEMCPServer | None = None


async def get_server() -> SSEMCPServer:
    """Get or create the global server instance."""
    global _server
    if _server is None:
        _server = SSEMCPServer()
        await _server.core.cache_service.start()
    return _server


async def handle_sse(request: Request) -> StreamingResponse:
    """Handle SSE endpoint - establishes event stream for MCP communication."""
    server = await get_server()
    session_id = str(uuid.uuid4())

    logger.info("New SSE connection", session_id=session_id)

    async def event_generator():
        """Generate SSE events."""
        try:
            # Send initial connection event
            yield f"data: {json.dumps({'type': 'connected', 'session_id': session_id})}\n\n"

            # Keep connection alive with periodic pings
            while True:
                await asyncio.sleep(30)
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

        except asyncio.CancelledError:
            logger.info("SSE connection closed", session_id=session_id)
            raise

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


async def handle_message(request: Request) -> JSONResponse:
    """Handle HTTP POST requests with MCP JSON-RPC messages."""
    server = await get_server()

    try:
        # Parse incoming JSON-RPC request
        body = await request.json()
        logger.debug("Received message", method=body.get("method"))

        # Process the request using core
        response = await server.core.process_request(body)

        if response is None:
            # Notification - no response needed
            return JSONResponse({"status": "ok"})

        return JSONResponse(response)

    except json.JSONDecodeError as e:
        logger.error("Invalid JSON", error=str(e))
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            },
            status_code=400,
        )
    except Exception as e:
        logger.error("Request handling failed", error=str(e))
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
            },
            status_code=500,
        )


async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint."""
    server = await get_server()
    return JSONResponse(
        {
            "status": "healthy",
            "server": server.core.server_info,
            "cache_size": len(server.core.cache_service._cache),
        }
    )


def create_app(config: Config | None = None) -> Starlette:
    """Create and configure the Starlette application."""
    cfg = config or Config.from_env()

    routes = [
        Route("/sse", handle_sse),
        Route("/message", handle_message, methods=["POST"]),
        Route("/health", health_check),
    ]

    app = Starlette(debug=False, routes=routes)

    # Add CORS middleware
    allowed_origins = cfg.cors_allowed_origins.split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return app


def main() -> None:
    """Main entry point for SSE server."""
    import uvicorn

    config = Config.from_env()
    config.validate()

    logger.info(
        "Starting SSE MCP server",
        host=config.bind_host,
        port=config.bind_port,
    )

    app = create_app(config)

    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.bind_port,
        log_level=config.log_level.lower(),
    )


if __name__ == "__main__":
    main()
