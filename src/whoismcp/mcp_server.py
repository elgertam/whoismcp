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

from whoismcp import __version__
from whoismcp.config import Config
from whoismcp.mcp_core import MCPServerCore

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
        # Use shared core implementation with stdio-specific rate limit ID
        self.core = MCPServerCore(self.config, rate_limit_client_id="mcp_client")

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

    async def run(self) -> None:
        """Main server loop."""
        logger.info("MCP stdio server starting")

        # Start cache service
        await self.core.cache_service.start()

        try:
            while True:
                # Read request from stdin
                request = self.read_message()
                if request is None:
                    break

                # Process request using core
                response = await self.core.process_request(request)

                if response is not None:
                    self.write_message(response)

        except KeyboardInterrupt:
            logger.info("Server shutting down")
        except Exception as e:
            logger.error("Server error", error=str(e))
            raise


def main() -> None:
    """Main entry point."""
    # Check for --version flag
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-v"):
        print(f"whoismcp-server {__version__}")
        sys.exit(0)

    async def run_server():
        server = MCPServer()
        await server.run()

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
