# WhoisMCP

A modern, high-performance Model Context Protocol (MCP) server providing domain and IP address lookup services using both traditional Whois and modern RDAP protocols.

## Features

✨ **Modern Architecture**: Clean package structure with `uv` for dependency management
🚀 **High Performance**: Asynchronous operations with connection pooling and structured concurrency
🛡️ **Rate Limiting**: Built-in protection for external registry servers
💾 **Smart Caching**: In-memory LRU cache with TTL for optimal performance
🔍 **Dual Protocols**: Support for both Whois (TCP) and RDAP (HTTPS) lookups
🌍 **Global Coverage**: Comprehensive support for major TLDs and Regional Internet Registries
📊 **Structured Logging**: Detailed logging with structured output
🧪 **Comprehensive Testing**: Full test suite with pytest and asyncio support

### New in v2.0

🌐 **Web-based MCP**: HTTP server with SSE (Server-Sent Events) support for streaming responses
📝 **Brief Mode**: Get only essential information instead of full WHOIS/RDAP dumps
🔄 **Bulk Lookups**: Efficiently query multiple domains/IPs with structured concurrency
⚡ **Streamable HTTP Transport**: Compliant with MCP specification 2024-11-05

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

#### Standard (stdio) MCP Server

The MCP server communicates via stdin/stdout as per the MCP specification:

```bash
# Using uv (recommended)
uv run whoismcp-server

# Or directly
./mcp_server_new

# For development
python -m whoismcp.mcp_server
```

#### HTTP/SSE MCP Server (New!)

Run the HTTP server with SSE support for web-based clients:

```bash
# Start HTTP server on port 8000 (default)
uv run whoismcp http-server

# Custom host and port
uv run whoismcp http-server --host 0.0.0.0 --port 3000

# Development mode with auto-reload
uv run whoismcp http-server --reload
```

### Using the CLI

```bash
# Interactive whois lookup
uv run whoismcp whois example.com

# RDAP lookup with JSON output
uv run whoismcp rdap example.com --output json

# Bulk lookup (New!)
uv run whoismcp bulk-lookup google.com github.com cloudflare.com --brief

# Bulk lookup with both services
uv run whoismcp bulk-lookup example.com google.com --method both --output json

# Test server connectivity
uv run whoismcp test-server --host localhost --port 5001
```

### Web Demo

A web interface demonstrates the functionality:

```bash
python main.py
# Visit http://localhost:5000
```

## MCP Integration

### Client Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "whoismcp": {
      "command": "/path/to/whoismcp/.venv/bin/python",
      "args": ["run", "-m", "whoismcp.mcp_server"],
      "cwd": "/path/to/whoismcp"
    }
  }
}
```

### Available Tools

- **`whois_lookup`**: Perform Whois lookup for domain or IP address
  - Now supports `brief` mode and custom `fields` selection
- **`rdap_lookup`**: Perform RDAP lookup for domain or IP address
  - Now supports `brief` mode and custom `fields` selection
- **`bulk_lookup`** (New!): Perform bulk lookups for multiple domains/IPs
  - Efficient concurrent processing with configurable concurrency
  - Support for both Whois and RDAP protocols
  - Brief mode for all results

## New Features Details

### Brief Response Mode

Get only the essential information without the full WHOIS/RDAP dump:

```json
{
  "target": "example.com",
  "domain_name": "example.com",
  "registrar": "Example Registrar Inc.",
  "creation_date": "1995-08-14",
  "expiration_date": "2025-08-13",
  "name_servers": ["ns1.example.com", "ns2.example.com"]
}
```

You can also specify custom fields to return:
```json
{
  "brief": true,
  "fields": ["domain_name", "registrar", "expiration_date"]
}
```

### Bulk Lookup with Structured Concurrency

Efficiently query multiple domains/IPs using AnyIO's structured concurrency:

- Configurable concurrency limit (1-50 simultaneous lookups)
- Rate limiting to avoid overwhelming WHOIS/RDAP servers
- Streaming results as they complete
- Support for mixed domain and IP lookups

### HTTP/SSE Transport

The new HTTP server supports the MCP Streamable HTTP transport specification:

- Single endpoint (`/mcp`) for all operations
- Server-Sent Events (SSE) for streaming responses
- Batch request support
- Session management
- Compatible with web-based MCP clients

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
│   ├── mcp_server.py       # MCP server implementation (stdio)
│   ├── http_server.py      # HTTP/SSE server (New!)
│   ├── cli.py              # Command-line interface
│   ├── models/             # Data models
│   │   ├── __init__.py
│   │   └── domain_models.py
│   ├── services/           # Core services
│   │   ├── __init__.py
│   │   ├── whois_service.py
│   │   ├── rdap_service.py
│   │   ├── cache_service.py
│   │   └── concurrent_service.py  # Bulk lookup service (New!)
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
HTTP_HOST=0.0.0.0           # HTTP server host (default: 0.0.0.0)
HTTP_PORT=8000              # HTTP server port (default: 8000)

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

# Concurrent lookup settings
MAX_CONCURRENT_LOOKUPS=10    # Max concurrent operations
DELAY_BETWEEN_REQUESTS=0.1   # Delay between requests in seconds

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
