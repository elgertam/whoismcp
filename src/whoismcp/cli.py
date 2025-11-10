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


@cli.command("http-server")
@click.option("--host", default=None, help="HTTP server host (default: from config or 0.0.0.0)")
@click.option("--port", default=None, type=int, help="HTTP server port (default: from config or 8000)")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
@click.pass_context
def http_server(ctx: click.Context, host: str, port: int, reload: bool) -> None:
    """Run the HTTP/SSE MCP server."""
    config = ctx.obj["config"]
    
    # Use provided values or fall back to config
    host = host or config.http_host
    port = port or config.http_port
    
    click.echo(f"Starting HTTP/SSE MCP server on {host}:{port}")
    click.echo("Press Ctrl+C to stop")
    
    try:
        import uvicorn
        uvicorn.run(
            "whoismcp.http_server:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info" if not ctx.parent.params.get("verbose") else "debug"
        )
    except ImportError:
        click.echo("Error: uvicorn is not installed. Please install it with: pip install uvicorn", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nServer stopped")
    except Exception as e:
        click.echo(f"Error starting server: {e}", err=True)
        sys.exit(1)


@cli.command("bulk-lookup")
@click.argument("targets", nargs=-1, required=True)
@click.option("--method", type=click.Choice(["whois", "rdap", "both"]), default="whois", help="Lookup method")
@click.option("--max-concurrent", default=10, type=int, help="Maximum concurrent lookups")
@click.option("--brief", is_flag=True, help="Return only essential information")
@click.option("--output", "-o", type=click.Choice(["json", "text"]), default="text", help="Output format")
@click.pass_context
def bulk_lookup(ctx: click.Context, targets: tuple, method: str, max_concurrent: int, brief: bool, output: str) -> None:
    """Perform bulk lookups for multiple domains/IPs."""
    from whoismcp.services.concurrent_service import ConcurrentLookupService
    
    async def run_bulk() -> None:
        config = ctx.obj["config"]
        service = ConcurrentLookupService(config)
        
        target_list = list(targets)
        click.echo(f"Starting bulk lookup for {len(target_list)} targets...")
        
        results = []
        if method == "both":
            # Use parallel lookup for both services
            all_results = await service.parallel_lookup(
                targets=target_list,
                use_both_services=True,
                max_concurrent=max_concurrent
            )
            
            if output == "json":
                click.echo(json.dumps(all_results, indent=2, default=str))
            else:
                for target, services in all_results.items():
                    click.echo(f"\n{target}:")
                    click.echo("-" * 40)
                    for service_type, result in services.items():
                        if result.status == "success":
                            click.echo(f"  {service_type.upper()}: ✓ Success")
                            if brief and result.data:
                                # Show brief info
                                parsed = result.data.get("parsed_data", {})
                                if parsed:
                                    if "domain_name" in parsed:
                                        click.echo(f"    Registrar: {parsed.get('registrar', 'N/A')}")
                                        click.echo(f"    Expires: {parsed.get('expiration_date', 'N/A')}")
                                    elif "organization" in parsed:
                                        click.echo(f"    Organization: {parsed.get('organization', 'N/A')}")
                                        click.echo(f"    Country: {parsed.get('country', 'N/A')}")
                        else:
                            click.echo(f"  {service_type.upper()}: ✗ {result.error}")
        else:
            # Single service lookup
            async for result in service.bulk_lookup(
                targets=target_list,
                lookup_type=method,
                max_concurrent=max_concurrent
            ):
                results.append(result)
                
                if output == "text":
                    # Stream results as they come
                    if result.status == "success":
                        click.echo(f"✓ {result.target}")
                        if brief and result.data:
                            # Show brief info inline
                            parsed = result.data.get("parsed_data", {})
                            if parsed:
                                if "domain_name" in parsed:
                                    click.echo(f"  Registrar: {parsed.get('registrar', 'N/A')}")
                                elif "organization" in parsed:
                                    click.echo(f"  Organization: {parsed.get('organization', 'N/A')}")
                    else:
                        click.echo(f"✗ {result.target}: {result.error}")
            
            if output == "json":
                # Output all results as JSON
                json_results = [
                    {
                        "target": r.target,
                        "status": r.status,
                        "data": r.data if r.status == "success" else None,
                        "error": r.error,
                        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                        "from_cache": r.from_cache
                    }
                    for r in results
                ]
                click.echo(json.dumps(json_results, indent=2, default=str))
        
        # Summary
        if output == "text":
            click.echo(f"\nCompleted {len(results)} lookups")
            stats = service.get_statistics()
            click.echo(f"Success rate: {stats['success_rate']:.1%}")
            click.echo(f"Cache hits: {sum(1 for r in results if r.from_cache)}")
    
    asyncio.run(run_bulk())


def main() -> None:
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
