# WhoisMCP

A modern, high-performance Model Context Protocol (MCP) server providing domain and IP address lookup services using both traditional Whois and modern RDAP protocols.

## Features

✨ **Modern Architecture**: Clean package structure with `uv` for dependency management
🚀 **High Performance**: Asynchronous operations with connection pooling
🌐 **Remote Access**: SSE-based transport for remote MCP access over HTTP/HTTPS
⚡ **Bulk Domain Check**: Efficient batch checking with minimal token usage
🛡️ **Rate Limiting**: Built-in protection for external registry servers
💾 **Smart Caching**: In-memory LRU cache with TTL for optimal performance
🔍 **Dual Protocols**: Support for both Whois (TCP) and RDAP (HTTPS) lookups
🌍 **Global Coverage**: Comprehensive support for major TLDs and Regional Internet Registries
📊 **Structured Logging**: Detailed logging with structured output
🧪 **Comprehensive Testing**: Full test suite with pytest and asyncio support

## Quick Start

### Development Setup

```bash
# Clone the repository
git clone <repository-url>
cd whoismcp

# Install with uv (recommended)
uv sync --extra dev

# Or install with pip
pip install -e ".[dev]"
```

### Running the MCP Server

The MCP server supports two transport modes:

#### stdio Mode (Default)

Traditional MCP mode for local clients via stdin/stdout:

```bash
# Using uv (recommended)
uv run whoismcp-server

# Or using the CLI
uv run whoismcp serve --mode stdio

# For development
python -m whoismcp.mcp_server
```

#### SSE Mode (Remote Access)

HTTP/SSE transport for remote access:

```bash
# Start SSE server (default: http://0.0.0.0:5001)
uv run whoismcp serve --mode sse

# Custom host and port
uv run whoismcp serve --mode sse --host 127.0.0.1 --port 8080

# Or directly
uv run whoismcp-sse

# For development
python -m whoismcp.sse_server
```

The SSE server provides:
- `/message` - POST endpoint for JSON-RPC requests
- `/sse` - SSE endpoint for event streaming
- `/health` - Health check endpoint

### Using the CLI

```bash
# Interactive whois lookup
uv run whoismcp whois example.com

# RDAP lookup with JSON output
uv run whoismcp rdap example.com --output json

# Bulk domain check (new!)
uv run whoismcp bulk-check example.com google.com github.com
uv run whoismcp bulk-check domain1.com domain2.com --output json

# Test server connectivity
uv run whoismcp test-server --host localhost --port 5001

# Show configuration
uv run whoismcp config
```

### Web Demo

A web interface demonstrates the functionality:

```bash
python main.py
# Visit http://localhost:5000
```

## MCP Integration

### Client Configuration

#### stdio Mode (Local)

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "whoismcp": {
      "command": "/path/to/whoismcp/.venv/bin/python",
      "args": ["-m", "whoismcp.mcp_server"],
      "cwd": "/path/to/whoismcp"
    }
  }
}
```

#### SSE Mode (Remote)

For remote access, start the SSE server first:

```bash
uv run whoismcp serve --mode sse --host 0.0.0.0 --port 5001
```

Then configure your MCP client to connect via HTTP:

```json
{
  "mcpServers": {
    "whoismcp-remote": {
      "url": "http://your-server:5001/message",
      "transport": "sse"
    }
  }
}
```

### Available Tools

- **`whois_lookup`**: Perform Whois lookup for domain or IP address
  - Returns full whois data with raw response and parsed fields
  - Supports both domains and IP addresses

- **`rdap_lookup`**: Perform RDAP lookup for domain or IP address
  - Returns structured RDAP JSON data
  - Supports domains and IP addresses with automatic server discovery

- **`check_domains_bulk`**: Check registration status of multiple domains (new!)
  - Efficient batch processing with concurrency control
  - Returns simple status: "registered", "available", or "error"
  - Minimal token usage - perfect for checking large lists
  - Example response: `{"example.com": "registered", "available-domain.com": "available"}`

## Package Structure

```tree
whoismcp/
├── .github/
│   └── workflows/
│       └── build.yml       # GitHub Actions workflow
├── scripts/
│   ├── README.md           # Documentation for scripts
│   └── build.py            # Build script
├── src/whoismcp/           # Main package
│   ├── __init__.py         # Package exports
│   ├── config.py           # Configuration management
│   ├── mcp_server.py       # MCP server (stdio transport)
│   ├── sse_server.py       # MCP server (SSE/HTTP transport) [NEW]
│   ├── cli.py              # Command-line interface
│   ├── models/             # Data models
│   │   ├── __init__.py
│   │   └── domain_models.py
│   ├── services/           # Core services
│   │   ├── __init__.py
│   │   ├── whois_service.py
│   │   ├── rdap_service.py
│   │   └── cache_service.py
│   └── utils/              # Utilities
│       ├── __init__.py
│       ├── validators.py
│       ├── parsers.py
│       └── rate_limiter.py
├── tests/                  # Test suite
├── BUILD.md                # Build documentation
├── README.md               # This file
├── pyproject.toml          # Package configuration
└── whoismcp.spec           # PyInstaller spec (stays in root)
```

## Configuration

Environment variables for customization:

```bash
# Server settings
BIND_HOST=0.0.0.0           # Bind host (default: 0.0.0.0)
BIND_PORT=5001              # Bind port (default: 5001)
TRANSPORT_MODE=stdio        # Transport mode: stdio or sse (default: stdio)

# SSE server settings
SSE_ENDPOINT=/sse           # SSE endpoint path (default: /sse)
CORS_ALLOWED_ORIGINS=*      # CORS allowed origins (default: *)

# Bulk check settings
BULK_CHECK_MAX_DOMAINS=100  # Max domains per bulk check (default: 100)
BULK_CHECK_CONCURRENCY=10   # Concurrent checks limit (default: 10)

# Timeouts
WHOIS_TIMEOUT=30            # Whois timeout in seconds
RDAP_TIMEOUT=30             # RDAP timeout in seconds

# Caching
CACHE_TTL=3600              # Cache TTL in seconds
CACHE_MAX_SIZE=1000         # Maximum cache entries
CACHE_CLEANUP_INTERVAL=300  # Cleanup interval in seconds

# Rate limiting
GLOBAL_RATE_LIMIT_PER_SECOND=10.0    # Global rate limit
GLOBAL_RATE_LIMIT_BURST=50           # Global burst limit
CLIENT_RATE_LIMIT_PER_SECOND=2.0     # Per-client rate limit
CLIENT_RATE_LIMIT_BURST=10           # Per-client burst limit

# Logging
LOG_LEVEL=INFO              # Logging level (DEBUG, INFO, WARNING, ERROR)
```

## Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/whoismcp --cov-report=html

# Run specific test file
uv run pytest tests/test_mcp_server.py -v
```

### Code Quality

```bash
# Format code
uv run black src/ tests/

# Lint code
uv run ruff check src/ tests/

# Type checking
uv run mypy src/whoismcp/
```

### Project Management

This project uses `uv` for modern Python package management:

```bash
# Add dependency
uv add httpx

# Add development dependency
uv add --dev pytest

# Update dependencies
uv sync

# Build package
uv build
```

## Architecture

### MCP Protocol

- **JSON-RPC 2.0**: Standard protocol over stdin/stdout
- **Initialize**: Handshake and capability negotiation
- **Tools**: Available lookup functions
- **Resources**: URI-based data access
- **Streaming**: Real-time request/response handling

### Services Architecture

- **WhoisService**: Asynchronous TCP connections to global Whois servers
- **RDAPService**: HTTPS requests to structured RDAP endpoints with bootstrap discovery
- **CacheService**: In-memory LRU cache with TTL for performance optimization
- **RateLimiter**: Token bucket implementation with per-client and global limits

### Data Flow

1. **Request Processing**: MCP client sends JSON-RPC request via stdin
2. **Validation**: Input validation for domain/IP format
3. **Rate Limiting**: Enforce per-client and global rate limits
4. **Cache Check**: Attempt to serve from cache if available
5. **Service Dispatch**: Route to appropriate service (Whois/RDAP)
6. **Data Retrieval**: Query external servers with connection pooling
7. **Response Parsing**: Parse and structure response data
8. **Caching**: Store successful results for future requests
9. **Response**: Return structured JSON-RPC response via stdout

## Registry Support

### Whois Servers

- **Generic TLDs**: .com, .net, .org, .info, .biz, and more
- **Country TLDs**: .uk, .de, .fr, .nl, .au, .ca, .jp, and more
- **Regional Internet Registries**: ARIN, RIPE, APNIC, LACNIC, AFRINIC

### RDAP Servers

- **Bootstrap Discovery**: Automatic server discovery via IANA bootstrap
- **Structured Data**: Modern JSON-based responses
- **Standardized Format**: Consistent data structure across registries

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes with tests
4. Run the test suite: `uv run pytest`
5. Check code quality: `uv run black . && uv run ruff check .`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
