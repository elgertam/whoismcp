# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WhoisMCP is a Model Context Protocol (MCP) server providing domain and IP address lookup services using both traditional Whois and modern RDAP protocols. It's built with Python 3.11+ and uses `uv` for package management.

## Commands

### Development Setup
```bash
# Install dependencies (using uv)
uv sync --extra dev

# Or with pip
pip install -e ".[dev]"
```

### Running the MCP Server
```bash
# Using uv
uv run whoismcp-server

# For development
python -m whoismcp.mcp_server

# Via executable script
./mcp_server_new
```

### Testing
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

### Building Binaries
```bash
# Run build script
python scripts/build.py

# Or manually with PyInstaller
pyinstaller whoismcp.spec
```

## Architecture

### Core Components

1. **MCP Server** (`src/whoismcp/mcp_server.py`)
   - JSON-RPC 2.0 protocol over stdin/stdout
   - Handles tool registration and request routing
   - Integrates all services

2. **Services** (`src/whoismcp/services/`)
   - `whois_service.py`: Async TCP connections to global Whois servers
   - `rdap_service.py`: HTTPS requests to RDAP endpoints with bootstrap discovery
   - `cache_service.py`: In-memory LRU cache with TTL

3. **Models** (`src/whoismcp/models/`)
   - `domain_models.py`: Pydantic models for domain/IP data
   - `mcp_models.py`: MCP protocol message models

4. **Utils** (`src/whoismcp/utils/`)
   - `validators.py`: Domain and IP validation
   - `parsers.py`: Response parsing logic
   - `rate_limiter.py`: Token bucket rate limiting

### Request Flow

1. MCP client sends JSON-RPC request via stdin
2. Server validates input (domain/IP format)
3. Rate limiter checks request limits
4. Cache service checks for cached results
5. If not cached, dispatches to Whois/RDAP service
6. Service queries external registry servers
7. Response is parsed, cached, and returned via stdout

### Configuration

Environment variables control behavior (see `src/whoismcp/config.py`):
- `WHOIS_TIMEOUT`: Whois query timeout (default: 30s)
- `RDAP_TIMEOUT`: RDAP query timeout (default: 30s)
- `CACHE_TTL`: Cache time-to-live (default: 3600s)
- `CACHE_MAX_SIZE`: Maximum cache entries (default: 1000)
- Rate limiting: `GLOBAL_RATE_LIMIT_PER_SECOND`, `CLIENT_RATE_LIMIT_PER_SECOND`

### MCP Tools

The server exposes two main tools:
- `whois_lookup`: Traditional Whois protocol lookup
- `rdap_lookup`: Modern RDAP protocol lookup

Both accept domain names or IP addresses and return structured data.

## Dependencies

Core dependencies managed via `pyproject.toml`:
- `anyio`: Async I/O
- `httpx`: HTTP client for RDAP
- `pydantic`: Data validation
- `structlog`: Structured logging
- `click`: CLI framework

Development dependencies:
- `pytest`, `pytest-asyncio`: Testing
- `black`, `ruff`: Code formatting and linting
- `mypy`: Type checking
- `pyinstaller`: Binary building (in `whoismcp.spec`)