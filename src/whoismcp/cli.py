#!/usr/bin/env python3
"""
Command-line interface for the WhoisMCP server.
"""

import asyncio
import json
import sys

import click
import structlog

from whoismcp.config import Config
from whoismcp.services.rdap_service import RDAPService
from whoismcp.services.whois_service import WhoisService
from whoismcp.utils.validators import is_valid_domain, is_valid_ip

logger = structlog.get_logger(__name__)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """WhoisMCP server CLI tool."""
    # Ensure that ctx.obj exists and is a dict
    ctx.ensure_object(dict)

    # Configure logging
    import logging

    log_level = logging.DEBUG if verbose else logging.INFO
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(log_level))

    ctx.obj["config"] = Config.from_env()


@cli.command()
@click.argument("target")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.option("--raw", is_flag=True, help="Show raw whois response")
@click.pass_context
def whois(ctx: click.Context, target: str, output: str, raw: bool) -> None:
    """Perform Whois lookup for domain or IP address."""

    async def run_whois() -> None:
        config = ctx.obj["config"]
        service = WhoisService(config)

        try:
            if is_valid_domain(target):
                result = await service.lookup_domain(target)
            elif is_valid_ip(target):
                result = await service.lookup_ip(target)
            else:
                click.echo(
                    f"Error: Invalid target '{target}'. Must be a domain or IP address.",
                    err=True,
                )
                sys.exit(1)

            if output == "json":
                click.echo(json.dumps(result, indent=2, default=str))
            else:
                if result.get("success"):
                    click.echo(f"Target: {result['target']}")
                    click.echo(f"Type: {result['target_type']}")
                    click.echo(f"Server: {result['whois_server']}")

                    if raw:
                        click.echo("\nRaw Response:")
                        click.echo("-" * 40)
                        click.echo(result["raw_response"])
                    else:
                        parsed = result.get("parsed_data", {})
                        if parsed:
                            click.echo("\nParsed Information:")
                            click.echo("-" * 40)
                            for key, value in parsed.items():
                                if value:
                                    click.echo(f"{key}: {value}")
                        else:
                            click.echo("\nRaw Response:")
                            click.echo("-" * 40)
                            click.echo(result["raw_response"])
                else:
                    click.echo(
                        f"Error: {result.get('error', 'Unknown error')}", err=True
                    )
                    sys.exit(1)

        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    asyncio.run(run_whois())


@cli.command()
@click.argument("target")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.pass_context
def rdap(ctx: click.Context, target: str, output: str) -> None:
    """Perform RDAP lookup for domain or IP address."""

    async def run_rdap() -> None:
        config = ctx.obj["config"]
        service = RDAPService(config)

        try:
            if is_valid_domain(target):
                result = await service.lookup_domain(target)
            elif is_valid_ip(target):
                result = await service.lookup_ip(target)
            else:
                click.echo(
                    f"Error: Invalid target '{target}'. Must be a domain or IP address.",
                    err=True,
                )
                sys.exit(1)

            if output == "json":
                click.echo(json.dumps(result, indent=2, default=str))
            else:
                if result.get("success"):
                    click.echo(f"Target: {result['target']}")
                    click.echo(f"Type: {result['target_type']}")
                    click.echo(f"Server: {result['rdap_server']}")

                    response_data = result.get("response_data", {})
                    if response_data:
                        click.echo("\nRDAP Information:")
                        click.echo("-" * 40)

                        # Display key RDAP fields
                        if "ldhName" in response_data:
                            click.echo(f"Domain: {response_data['ldhName']}")
                        if "unicodeName" in response_data:
                            click.echo(f"Unicode Name: {response_data['unicodeName']}")

                        # Status
                        if "status" in response_data:
                            click.echo(f"Status: {', '.join(response_data['status'])}")

                        # Nameservers
                        nameservers = response_data.get("nameservers", [])
                        if nameservers:
                            click.echo("Nameservers:")
                            for ns in nameservers:
                                if "ldhName" in ns:
                                    click.echo(f"  - {ns['ldhName']}")

                        # Entities (registrar, registrant, etc.)
                        entities = response_data.get("entities", [])
                        for entity in entities:
                            roles = entity.get("roles", [])
                            if roles:
                                role_str = ", ".join(roles)
                                vcards = entity.get("vcardArray", [])
                                if vcards and len(vcards) > 1:
                                    vcard_data = vcards[1]
                                    for item in vcard_data:
                                        if len(item) >= 4 and item[0] == "fn":
                                            click.echo(f"{role_str.title()}: {item[3]}")
                                            break

                        # Events
                        events = response_data.get("events", [])
                        for event in events:
                            action = event.get("eventAction", "")
                            date = event.get("eventDate", "")
                            if action and date:
                                click.echo(
                                    f"{action.replace('_', ' ').title()}: {date}"
                                )
                else:
                    click.echo(
                        f"Error: {result.get('error', 'Unknown error')}", err=True
                    )
                    sys.exit(1)

        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    asyncio.run(run_rdap())


@cli.command()
@click.option("--host", default="127.0.0.1", help="MCP server host")
@click.option("--port", default=5001, help="MCP server port")
@click.pass_context
def test_server(ctx: click.Context, host: str, port: int) -> None:
    """Test MCP server connectivity."""

    async def run_test() -> None:
        import anyio

        try:
            async with anyio.connect_tcp(host, port) as stream:
                click.echo(f"✓ Successfully connected to MCP server at {host}:{port}")

                # Send a simple test message
                test_msg = {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "id": 1,
                    "params": {},
                }
                await stream.send(json.dumps(test_msg).encode() + b"\n")

                # Read response
                response_data = await stream.receive(1024)
                response = json.loads(response_data.decode())

                if "result" in response:
                    click.echo("✓ MCP server responded correctly")
                    click.echo(
                        f"Server: {response['result'].get('serverInfo', {}).get('name', 'Unknown')}"
                    )
                else:
                    click.echo("✗ Unexpected response from server")

        except Exception as e:
            click.echo(f"✗ Failed to connect to MCP server: {e}", err=True)
            sys.exit(1)

    asyncio.run(run_test())


@cli.command()
@click.argument("target")
@click.option(
    "--method",
    type=click.Choice(["whois", "rdap"]),
    default="whois",
    help="Lookup method to test",
)
@click.option("--host", default="127.0.0.1", help="MCP server host")
@click.option("--port", default=5001, help="MCP server port")
@click.pass_context
def test_lookup(
    ctx: click.Context, target: str, method: str, host: str, port: int
) -> None:
    """Test lookup via MCP server."""

    async def run_lookup() -> None:
        import anyio

        try:
            async with anyio.connect_tcp(host, port) as stream:
                # Initialize
                init_msg = {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "id": 1,
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
                }
                await stream.send(json.dumps(init_msg).encode() + b"\n")
                await stream.receive(1024)  # Read and discard init response

                # Call tool
                tool_msg = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 2,
                    "params": {
                        "name": f"{method}_lookup",
                        "arguments": {"target": target, "use_cache": False},
                    },
                }
                await stream.send(json.dumps(tool_msg).encode() + b"\n")

                # Read response
                response_data = await stream.receive(4096)
                response = json.loads(response_data.decode())

                if "result" in response and "content" in response["result"]:
                    content = response["result"]["content"][0]["text"]
                    result = json.loads(content)

                    click.echo(f"✓ {method.upper()} lookup completed")
                    click.echo(f"Target: {result.get('target')}")
                    click.echo(f"Success: {result.get('success')}")
                    if result.get("success"):
                        server_key = (
                            f"{method}_server" if method == "rdap" else "whois_server"
                        )
                        click.echo(f"Server: {result.get(server_key)}")
                    else:
                        click.echo(f"Error: {result.get('error')}")
                else:
                    click.echo("✗ Unexpected response format")
                    click.echo(json.dumps(response, indent=2))

        except Exception as e:
            click.echo(f"✗ Test failed: {e}", err=True)
            sys.exit(1)

    asyncio.run(run_lookup())


@cli.command("config")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Show current configuration."""
    config = ctx.obj["config"]
    config_dict = config.to_dict()

    click.echo("Current Configuration:")
    click.echo("=" * 40)

    for key, value in config_dict.items():
        # Don't show sensitive information
        if "password" in key.lower() or "secret" in key.lower():
            value = "***"
        click.echo(f"{key}: {value}")


@cli.command("serve")
@click.option(
    "--mode",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="Server transport mode",
)
@click.option("--host", default=None, help="Host to bind to (SSE mode only)")
@click.option("--port", default=None, type=int, help="Port to bind to (SSE mode only)")
@click.pass_context
def serve(ctx: click.Context, mode: str, host: str | None, port: int | None) -> None:
    """Start the MCP server in specified mode."""
    config = ctx.obj["config"]

    if mode == "stdio":
        click.echo("Starting MCP server in stdio mode...", err=True)
        from whoismcp.mcp_server import main as stdio_main

        stdio_main()
    elif mode == "sse":
        # Override config if host/port provided
        if host:
            config.bind_host = host
        if port:
            config.bind_port = port

        config.validate()

        click.echo(
            f"Starting MCP server in SSE mode on {config.bind_host}:{config.bind_port}...",
            err=True,
        )
        from whoismcp.sse_server import main as sse_main

        sse_main()


@cli.command("bulk-check")
@click.argument("domains", nargs=-1, required=True)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.pass_context
def bulk_check(ctx: click.Context, domains: tuple[str, ...], output: str) -> None:
    """Check registration status of multiple domains."""

    async def run_bulk_check() -> None:
        from whoismcp.services.cache_service import CacheService
        from whoismcp.services.rdap_service import RDAPService

        config = ctx.obj["config"]
        rdap_service = RDAPService(config)
        cache_service = CacheService(config)

        await cache_service.start()

        try:
            results = {}

            async def check_domain(domain: str) -> None:
                try:
                    result = await rdap_service.lookup_domain(domain)
                    if result.get("success"):
                        response_data = result.get("response_data", {})
                        # Check for common RDAP indicators of registration
                        if (response_data.get("objectClassName") == "domain" or
                            "ldhName" in response_data or
                            "handle" in response_data or
                            "status" in response_data):
                            results[domain] = "registered"
                        else:
                            results[domain] = "available"
                    else:
                        error = result.get("error", "")
                        if "not found" in error.lower() or "404" in error:
                            results[domain] = "available"
                        else:
                            results[domain] = "error"
                except Exception as e:
                    logger.error("Domain check failed", domain=domain, error=str(e))
                    results[domain] = "error"

            # Process domains concurrently
            semaphore = asyncio.Semaphore(config.bulk_check_concurrency)

            async def check_with_limit(domain: str) -> None:
                async with semaphore:
                    await check_domain(domain)

            await asyncio.gather(*[check_with_limit(d) for d in domains])

            if output == "json":
                click.echo(json.dumps(results, indent=2))
            else:
                click.echo("\nDomain Registration Status:")
                click.echo("=" * 60)
                for domain, status in results.items():
                    status_icon = "✓" if status == "registered" else "✗" if status == "available" else "!"
                    click.echo(f"{status_icon} {domain:40} {status}")

        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    asyncio.run(run_bulk_check())


def main() -> None:
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
