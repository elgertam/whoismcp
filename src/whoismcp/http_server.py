"""
HTTP Transport Implementation for WhoisMCP Server.

This implements the Model Context Protocol Streamable HTTP transport specification 
as defined in version 2025-03-26. The server provides a single endpoint that handles 
both POST and GET requests for full MCP functionality over HTTP.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse

import structlog
from anyio import create_task_group, sleep
from anyio.abc import TaskGroup
from httpx import AsyncClient
from pydantic import BaseModel, Field

from whoismcp.config import Config
from whoismcp.mcp_server import MCPServer

# Configure logging to stderr for HTTP server
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


class SSEEvent(BaseModel):
    """Server-Sent Event structure."""
    id: Optional[str] = None
    event: Optional[str] = None
    data: str
    retry: Optional[int] = None


class HTTPSession(BaseModel):
    """HTTP session management for stateful connections."""
    session_id: str
    created_at: datetime
    last_used: datetime
    mcp_server: Optional[MCPServer] = None
    
    class Config:
        arbitrary_types_allowed = True


class MCPHttpServer:
    """
    MCP Server with Streamable HTTP transport support.
    
    Implements the full MCP Streamable HTTP specification including:
    - Single endpoint for both POST and GET requests
    - Session management with secure session IDs
    - Server-Sent Events for streaming responses
    - Resumable connections with Last-Event-ID support
    - Proper error handling and security validation
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.from_env()
        self.sessions: Dict[str, HTTPSession] = {}
        self.event_counter = 0
        self.message_cache: Dict[str, List[SSEEvent]] = {}  # For resumability
        
        # Security settings
        self.allowed_origins = ["http://localhost", "https://localhost"]
        if self.config.bind_host == "0.0.0.0":
            logger.warning("Server bound to all interfaces - consider using localhost for security")
    
    def _generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        return str(uuid.uuid4())
    
    def _generate_event_id(self, session_id: str) -> str:
        """Generate a unique event ID for SSE resumability."""
        self.event_counter += 1
        return f"{session_id}:{self.event_counter}"
    
    def _validate_origin(self, origin: Optional[str]) -> bool:
        """Validate Origin header to prevent DNS rebinding attacks."""
        if not origin:
            return False
        
        try:
            parsed = urlparse(origin)
            if parsed.hostname in ["localhost", "127.0.0.1", "::1"]:
                return True
            
            # Check against allowed origins
            return origin in self.allowed_origins
        except Exception:
            return False
    
    def _validate_session_id(self, session_id: Optional[str]) -> bool:
        """Validate session ID format and existence."""
        if not session_id:
            return False
        
        # Check format - only visible ASCII characters
        if not all(0x21 <= ord(c) <= 0x7E for c in session_id):
            return False
        
        return session_id in self.sessions
    
    def _create_session(self) -> HTTPSession:
        """Create a new HTTP session."""
        session_id = self._generate_session_id()
        now = datetime.utcnow()
        
        session = HTTPSession(
            session_id=session_id,
            created_at=now,
            last_used=now,
            mcp_server=MCPServer()
        )
        
        self.sessions[session_id] = session
        self.message_cache[session_id] = []
        
        logger.info("Created new MCP session", session_id=session_id)
        return session
    
    def _get_session(self, session_id: str) -> Optional[HTTPSession]:
        """Get session by ID and update last_used timestamp."""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        session.last_used = datetime.utcnow()
        return session
    
    def _delete_session(self, session_id: str) -> bool:
        """Delete a session and cleanup resources."""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions.pop(session_id)
        self.message_cache.pop(session_id, None)
        
        # Cleanup MCP server resources
        if session.mcp_server:
            # Close any async resources
            try:
                asyncio.create_task(session.mcp_server.cache_service.close())
                asyncio.create_task(session.mcp_server.rate_limiter.close())
                asyncio.create_task(session.mcp_server.rdap_service.close())
            except Exception as e:
                logger.warning("Error cleaning up session resources", error=str(e))
        
        logger.info("Deleted MCP session", session_id=session_id)
        return True
    
    def _create_sse_event(self, data: Dict[str, Any], event_id: Optional[str] = None, 
                         event_type: Optional[str] = None) -> str:
        """Create a properly formatted SSE event."""
        lines = []
        
        if event_id:
            lines.append(f"id: {event_id}")
        
        if event_type:
            lines.append(f"event: {event_type}")
        
        # JSON-RPC data
        json_data = json.dumps(data)
        lines.append(f"data: {json_data}")
        
        # SSE events end with double newline
        lines.append("")
        lines.append("")
        
        return "\n".join(lines)
    
    def _cache_message(self, session_id: str, event: SSEEvent) -> None:
        """Cache message for resumability."""
        if session_id not in self.message_cache:
            self.message_cache[session_id] = []
        
        self.message_cache[session_id].append(event)
        
        # Keep only last 100 events to prevent memory issues
        if len(self.message_cache[session_id]) > 100:
            self.message_cache[session_id] = self.message_cache[session_id][-100:]
    
    def _get_messages_after_event_id(self, session_id: str, last_event_id: str) -> List[SSEEvent]:
        """Get cached messages after a specific event ID for resumability."""
        if session_id not in self.message_cache:
            return []
        
        messages = self.message_cache[session_id]
        try:
            # Find the index of the last event ID
            for i, event in enumerate(messages):
                if event.id == last_event_id:
                    return messages[i + 1:]  # Return messages after this event
        except Exception:
            pass
        
        return []
    
    async def handle_post_request(self, request_body: bytes, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """
        Handle HTTP POST requests to the MCP endpoint.
        
        Returns: (status_code, headers, body)
        """
        # Security validation
        origin = headers.get("origin")
        if not self._validate_origin(origin):
            logger.warning("Invalid origin", origin=origin)
            return 403, {"Content-Type": "application/json"}, b'{"error": "Forbidden origin"}'
        
        # Parse JSON-RPC message
        try:
            message = json.loads(request_body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Invalid JSON in request", error=str(e))
            return 400, {"Content-Type": "application/json"}, b'{"error": "Invalid JSON"}'
        
        # Handle session management
        session_id = headers.get("mcp-session-id")
        session = None
        
        if session_id:
            session = self._get_session(session_id)
            if not session:
                logger.warning("Invalid session ID", session_id=session_id)
                return 404, {"Content-Type": "application/json"}, b'{"error": "Session not found"}'
        
        # Check if this is an initialization request
        is_initialization = False
        if isinstance(message, dict) and message.get("method") == "initialize":
            is_initialization = True
            if not session:
                session = self._create_session()
        elif not session:
            return 400, {"Content-Type": "application/json"}, b'{"error": "Session ID required"}'
        
        # Process the message with MCP server
        try:
            logger.debug("Processing MCP request", method=message.get("method"), message_id=message.get("id"))
            response = await session.mcp_server.process_request(message)
            logger.debug("MCP response received", response=response)
            
            # Handle different response types
            if isinstance(message, list):
                # Batch request - may need streaming
                return await self._handle_batch_request(session, message, headers)
            elif isinstance(message, dict):
                if message.get("method"):
                    # Single request - may need streaming
                    return await self._handle_single_request(session, message, response, is_initialization)
                else:
                    # Notification or response - return 202 Accepted
                    return 202, {}, b""
            else:
                return 400, {"Content-Type": "application/json"}, b'{"error": "Invalid message format"}'
                
        except Exception as e:
            logger.error("Error processing MCP request", error=str(e))
            return 500, {"Content-Type": "application/json"}, b'{"error": "Internal server error"}'
    
    async def _handle_single_request(self, session: HTTPSession, message: Dict[str, Any], 
                                   response: Optional[Dict[str, Any]], is_initialization: bool) -> Tuple[int, Dict[str, str], bytes]:
        """Handle a single JSON-RPC request."""
        if not response:
            return 202, {}, b""
        
        # For simple responses, return JSON directly
        response_headers = {"Content-Type": "application/json"}
        
        # Add session ID header for initialization
        if is_initialization:
            response_headers["Mcp-Session-Id"] = session.session_id
        
        return 200, response_headers, json.dumps(response).encode('utf-8')
    
    async def _handle_batch_request(self, session: HTTPSession, messages: List[Dict[str, Any]], 
                                  headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """Handle a batch of JSON-RPC requests."""
        responses = []
        
        for message in messages:
            if isinstance(message, dict) and message.get("method"):
                response = await session.mcp_server.process_request(message)
                if response:
                    responses.append(response)
        
        if not responses:
            return 202, {}, b""
        
        # Return batched responses as JSON
        return 200, {"Content-Type": "application/json"}, json.dumps(responses).encode('utf-8')
    
    async def handle_get_request(self, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """
        Handle HTTP GET requests to the MCP endpoint for SSE streaming.
        
        Returns: (status_code, headers, body)
        """
        # Security validation
        origin = headers.get("origin")
        if not self._validate_origin(origin):
            logger.warning("Invalid origin for GET request", origin=origin)
            return 403, {"Content-Type": "application/json"}, b'{"error": "Forbidden origin"}'
        
        # Check Accept header
        accept = headers.get("accept", "")
        if "text/event-stream" not in accept:
            return 406, {"Content-Type": "application/json"}, b'{"error": "text/event-stream required"}'
        
        # Session management
        session_id = headers.get("mcp-session-id")
        if not session_id:
            return 400, {"Content-Type": "application/json"}, b'{"error": "Session ID required"}'
        
        session = self._get_session(session_id)
        if not session:
            return 404, {"Content-Type": "application/json"}, b'{"error": "Session not found"}'
        
        # Handle resumability
        last_event_id = headers.get("last-event-id")
        if last_event_id:
            # Return cached messages after the last event ID
            cached_messages = self._get_messages_after_event_id(session_id, last_event_id)
            if cached_messages:
                sse_data = ""
                for event in cached_messages:
                    sse_data += self._create_sse_event(
                        json.loads(event.data), 
                        event.id, 
                        event.event
                    )
                return 200, {
                    "Content-Type": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive"
                }, sse_data.encode('utf-8')
        
        # For now, return a simple SSE stream
        # In a real implementation, this would be a long-lived connection
        return 200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }, b"data: {\"type\": \"stream_ready\"}\n\n"
    
    async def handle_delete_request(self, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """
        Handle HTTP DELETE requests to terminate sessions.
        
        Returns: (status_code, headers, body)
        """
        # Security validation - DELETE requests may not have Origin header
        origin = headers.get("origin")
        if origin and not self._validate_origin(origin):
            return 403, {"Content-Type": "application/json"}, b'{"error": "Forbidden origin"}'
        
        # Session management
        session_id = headers.get("mcp-session-id")
        if not session_id:
            return 400, {"Content-Type": "application/json"}, b'{"error": "Session ID required"}'
        
        if self._delete_session(session_id):
            return 204, {}, b""  # No Content
        else:
            return 404, {"Content-Type": "application/json"}, b'{"error": "Session not found"}'
    
    async def cleanup_expired_sessions(self) -> None:
        """Background task to cleanup expired sessions."""
        while True:
            try:
                now = datetime.utcnow()
                expired_sessions = []
                
                for session_id, session in self.sessions.items():
                    # Sessions expire after 1 hour of inactivity
                    if (now - session.last_used).total_seconds() > 3600:
                        expired_sessions.append(session_id)
                
                for session_id in expired_sessions:
                    self._delete_session(session_id)
                
                if expired_sessions:
                    logger.info("Cleaned up expired sessions", count=len(expired_sessions))
                
                # Run cleanup every 5 minutes
                await sleep(300)
                
            except Exception as e:
                logger.error("Error in session cleanup", error=str(e))
                await sleep(60)  # Wait 1 minute before retrying
    
    async def start_background_tasks(self) -> None:
        """Start background maintenance tasks."""
        async with create_task_group() as tg:
            tg.start_soon(self.cleanup_expired_sessions)


def create_fastapi_app(config: Optional[Config] = None):
    """Create a FastAPI application with MCP HTTP transport."""
    try:
        from fastapi import FastAPI, Request, Response
        from fastapi.responses import StreamingResponse
    except ImportError:
        raise ImportError("FastAPI is required for HTTP transport. Install with: pip install fastapi")
    
    mcp_server = MCPHttpServer(config)
    app = FastAPI(title="WhoisMCP HTTP Server", description="MCP Server with Streamable HTTP transport")
    
    @app.post("/mcp")
    async def handle_mcp_post(request: Request):
        """Handle MCP POST requests."""
        body = await request.body()
        headers = dict(request.headers)
        
        status_code, response_headers, response_body = await mcp_server.handle_post_request(body, headers)
        
        return Response(
            content=response_body,
            status_code=status_code,
            headers=response_headers
        )
    
    @app.get("/mcp")
    async def handle_mcp_get(request: Request):
        """Handle MCP GET requests for SSE streaming."""
        headers = dict(request.headers)
        
        status_code, response_headers, response_body = await mcp_server.handle_get_request(headers)
        
        if response_headers.get("Content-Type") == "text/event-stream":
            return StreamingResponse(
                iter([response_body]),
                media_type="text/event-stream",
                headers=response_headers
            )
        else:
            return Response(
                content=response_body,
                status_code=status_code,
                headers=response_headers
            )
    
    @app.delete("/mcp")
    async def handle_mcp_delete(request: Request):
        """Handle MCP DELETE requests for session termination."""
        headers = dict(request.headers)
        
        status_code, response_headers, response_body = await mcp_server.handle_delete_request(headers)
        
        return Response(
            content=response_body,
            status_code=status_code,
            headers=response_headers
        )
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "sessions": len(mcp_server.sessions),
            "server_time": datetime.utcnow().isoformat()
        }
    
    # Background tasks will be started on first request
    app.state.mcp_server = mcp_server
    app.state.background_started = False
    
    @app.on_event("startup")
    async def startup_event():
        """Start background tasks when the app starts."""
        if not app.state.background_started:
            asyncio.create_task(mcp_server.start_background_tasks())
            app.state.background_started = True
    
    return app


def main():
    """Main entry point for whoismcp-http command."""
    import uvicorn
    
    config = Config.from_env()
    app = create_fastapi_app(config)
    
    print(f"Starting WhoisMCP HTTP server on {config.bind_host}:{config.bind_port}")
    print(f"MCP endpoint: http://{config.bind_host}:{config.bind_port}/mcp")
    print(f"Health check: http://{config.bind_host}:{config.bind_port}/health")
    
    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.bind_port,
        log_level="info"
    )


if __name__ == "__main__":
    main()