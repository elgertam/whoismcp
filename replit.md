# MCP Whois/RDAP Server

## Overview

This is a Model Context Protocol (MCP) server that provides Whois and RDAP (Registration Data Access Protocol) lookup services for domain names and IP addresses. The server implements the MCP specification for JSON-RPC 2.0 communication and offers both traditional Whois queries via TCP and modern RDAP queries via HTTPS.

## System Architecture

The application follows a modular, service-oriented architecture with clear separation of concerns:

- **MCP Server Layer**: Handles JSON-RPC 2.0 communication and MCP protocol compliance
- **Service Layer**: Core business logic for Whois and RDAP lookups
- **Model Layer**: Pydantic data models for request/response validation and serialization
- **Utility Layer**: Common functionality for validation, parsing, and rate limiting
- **Configuration Layer**: Environment-based configuration management

The architecture is designed for asynchronous operations using Python's asyncio framework, enabling high-performance concurrent request handling.

## Key Components

### Core Services
- **WhoisService**: Handles asynchronous TCP connections to Whois servers worldwide
- **RDAPService**: Manages HTTPS requests to RDAP servers with bootstrap registry support
- **CacheService**: In-memory LRU cache with TTL support for performance optimization
- **MCPServer**: Main server implementing the Model Context Protocol specification

### Data Models
- **Domain Models**: `WhoisResult`, `RDAPResult`, `DomainInfo` for structured domain data
- **MCP Models**: Protocol-compliant request/response models for JSON-RPC communication

### Utilities
- **Validators**: Input validation for domain names and IP addresses
- **Parsers**: Whois response parsing with support for various registry formats
- **Rate Limiter**: Token bucket implementation with per-client and global rate limiting

### Configuration
Environment-based configuration supporting:
- Server binding (host/port)
- Connection timeouts and pooling
- Rate limiting parameters
- Cache settings (TTL, size limits)
- Logging configuration

## Data Flow

1. **Request Processing**: MCP client sends JSON-RPC request
2. **Validation**: Input validation for domain/IP format
3. **Rate Limiting**: Per-client and global rate limit enforcement
4. **Cache Check**: Attempt to serve from cache if available
5. **Service Dispatch**: Route to appropriate service (Whois/RDAP)
6. **Data Retrieval**: Query external servers with connection pooling
7. **Response Parsing**: Parse and structure response data
8. **Caching**: Store results in cache for future requests
9. **Response**: Return structured JSON-RPC response to client

## External Dependencies

### Core Dependencies
- **anyio**: Async I/O abstraction layer
- **httpx**: HTTP client for RDAP queries with connection pooling
- **pydantic**: Data validation and serialization
- **structlog**: Structured logging
- **click**: Command-line interface framework

### Registry Integrations
- **IANA RDAP Bootstrap**: Dynamic server discovery
- **Global Whois Servers**: Comprehensive TLD and RIR coverage
- **RDAP Servers**: Modern structured data access

## Deployment Strategy

The application is designed for containerized deployment with:

- **Environment Variables**: Complete configuration via environment
- **Graceful Shutdown**: Proper cleanup of connections and background tasks
- **Health Monitoring**: Structured logging for observability
- **Resource Management**: Connection pooling and rate limiting for stability

The server can be deployed as:
- Standalone Python application
- Docker container
- Part of a larger microservices architecture

## Changelog

```
Changelog:
- June 28, 2025. Initial setup and complete implementation
  * MCP server successfully implemented with JSON-RPC 2.0 protocol
  * Whois service with asynchronous TCP connections to global registries
  * RDAP service with HTTPS requests to structured data endpoints
  * In-memory LRU cache with TTL for performance optimization
  * Token bucket rate limiting per client and globally
  * Comprehensive error handling and structured logging
  * CLI tools for testing and debugging
  * Server running on port 5000 with full functionality verified
  * Fixed UTF-8 encoding issues in web interface (removed problematic Unicode symbols)
  * Web demo interface running on port 8000 with clean ASCII display

- June 29, 2025. Deployment fixes applied
  * Added health check endpoint at /health for deployment monitoring
  * Web server properly configured to bind to 0.0.0.0:5000
  * Both root endpoint (/) and health endpoint return proper HTTP 200 responses
  * MCP server runs on port 5001, web interface on port 5000
  * Created deployment configuration guide
  * Verified all endpoints respond correctly for deployment health checks
  * Created deployment verification script and configuration fix documentation
  * Application is fully ready for deployment - only .replit port mapping needs correction

- June 29, 2025. Deployment reconfiguration completed
  * Created dedicated deployment script (replit_deploy.py) with optimized health checks
  * Added comprehensive status endpoint (/status) with deployment readiness information
  * Implemented proper HEAD request support for all endpoints
  * Added uptime tracking and detailed service monitoring
  * Created comprehensive deployment verification script (verify_deployment.py)
  * Configured 'Deployment Server' workflow using the new deployment script
  * All deployment tests passing - application ready for production deployment
  * Port configuration: 5000 (web) → 80 (external), 5001 (MCP internal)

- June 29, 2025. Fixed deployment entry point
  * Updated main.py as the primary entry point for deployment
  * Separated MCP server logic into mcp_main.py to avoid circular imports
  * Run command now properly set to "python main.py" for Replit deployments
  * Server successfully starting with both MCP (port 5001) and web interface (port 5000)
  * Health endpoints responding correctly at /health with proper JSON status
  * Deployment configuration ready - no build command needed for Python

- June 29, 2025. Fixed MCP architecture to follow specification
  * Removed network-based MCP server (incorrect implementation)
  * Created proper stdio-based MCP server (mcp_stdio_server_fixed.py)
  * Added executable mcp_server script for MCP clients to invoke
  * Updated main.py to run only web demo interface on port 5000
  * Created comprehensive README explaining MCP usage
  * MCP server now communicates via stdin/stdout as per MCP specification
  * Web interface clearly explains it's demo-only, real MCP server is ./mcp_server
  * Fixed deployment issues - .replit file needs "python3" instead of "Python"

- June 29, 2025. Major package restructuring with uv
  * Completely restructured codebase using modern Python packaging with uv
  * Moved all code to src/whoismcp/ package structure for better organization
  * Created proper package hierarchy: models/, services/, utils/ with __init__.py files
  * Fixed all import statements to use relative imports within package
  * Added comprehensive pyproject.toml with modern build system (hatchling)
  * Set up development dependencies: pytest, black, ruff, mypy for code quality
  * Created test structure in tests/ directory with proper fixtures
  * Added CLI interface with click for easy command-line usage
  * Updated all entry points to use new package structure
  * MCP server now available via: uv run whoismcp-server
  * CLI tools available via: uv run whoismcp whois/rdap commands
  * Maintained backward compatibility with ./mcp_server_new executable
  * Updated README with comprehensive documentation and modern usage examples

- July 2, 2025. Final cleanup and test fixes completed
  * Removed all duplicate and obsolete files from previous iterations
  * Fixed async initialization issues in CacheService and test fixtures
  * Updated Pydantic models to use modern ConfigDict instead of deprecated Config class
  * Fixed CLI logging configuration to properly handle structured logging
  * All 23 tests now pass successfully with comprehensive coverage
  * Project structure is clean and follows Python packaging best practices
  * MCP server working correctly via stdin/stdout communication
  * CLI tools functional with proper configuration management
  * Ready for production use and deployment

- July 3, 2025. Critical MCP protocol and RDAP service fixes
  * Fixed logging configuration to properly send logs to stderr instead of stdout
  * MCP protocol now compliant - stdout contains only JSON-RPC messages, stderr for logs
  * Added follow_redirects=True to RDAP service HTTP client for proper 303 redirect handling
  * Enhanced RDAP logging to track redirects and debug connection issues
  * ARIN and other registry redirects now properly followed automatically
  * Server ready for production deployment with Claude Desktop and other MCP clients

- July 4, 2025. License and test suite improvements
  * Added MIT License file for proper open-source distribution
  * Fixed unit test suite - all 23 tests now pass without errors
  * Resolved Pydantic deprecation warnings by removing json_encoders
  * Implemented proper MCP resources with configuration and status endpoints
  * Added comprehensive test cleanup to prevent async task warnings
  * Updated package version to 0.3.4 with fixed dependency resolution

- July 13, 2025. HTTP MCP server implementation completed
  * Implemented complete HTTP transport using Streamable HTTP MCP specification (2025-03-26)
  * Added FastAPI-based HTTP server with single endpoint supporting POST/GET/DELETE methods
  * Implemented secure session management with cryptographic session IDs
  * Added proper Origin header validation to prevent DNS rebinding attacks
  * Created comprehensive session lifecycle management with automatic cleanup
  * Added support for Server-Sent Events (SSE) for streaming responses
  * Implemented message caching for resumable connections with Last-Event-ID support
  * Added new CLI command `whoismcp serve-http` for easy HTTP server startup
  * Created new entry point `whoismcp-http` for direct HTTP server execution
  * Added complete HTTP client example with proper error handling and session management
  * All HTTP MCP functionality fully tested and working: tools, resources, lookups, session management
  * HTTP server runs on port 5001 with health check endpoint and full MCP protocol support
  * Created comprehensive HTTP_MCP_README.md with examples and deployment instructions
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```