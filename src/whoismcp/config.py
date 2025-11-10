"""
Configuration management for the MCP server.
"""

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Config:
    """Configuration for the MCP Whois/RDAP server."""

    # Server configuration
    bind_host: str = field(default_factory=lambda: os.getenv("BIND_HOST", "0.0.0.0"))
    bind_port: int = field(default_factory=lambda: int(os.getenv("BIND_PORT", "5001")))

    # Timeout configuration (seconds)
    whois_timeout: int = field(
        default_factory=lambda: int(os.getenv("WHOIS_TIMEOUT", "30"))
    )
    rdap_timeout: int = field(
        default_factory=lambda: int(os.getenv("RDAP_TIMEOUT", "30"))
    )

    # Rate limiting configuration
    global_rate_limit_per_second: float = field(
        default_factory=lambda: float(os.getenv("GLOBAL_RATE_LIMIT_PER_SECOND", "10.0"))
    )
    global_rate_limit_burst: int = field(
        default_factory=lambda: int(os.getenv("GLOBAL_RATE_LIMIT_BURST", "50"))
    )
    client_rate_limit_per_second: float = field(
        default_factory=lambda: float(os.getenv("CLIENT_RATE_LIMIT_PER_SECOND", "2.0"))
    )
    client_rate_limit_burst: int = field(
        default_factory=lambda: int(os.getenv("CLIENT_RATE_LIMIT_BURST", "10"))
    )

    # Cache configuration
    cache_ttl: int = field(
        default_factory=lambda: int(os.getenv("CACHE_TTL", "3600"))
    )  # 1 hour
    cache_max_size: int = field(
        default_factory=lambda: int(os.getenv("CACHE_MAX_SIZE", "1000"))
    )
    cache_cleanup_interval: int = field(
        default_factory=lambda: int(
            os.getenv("CACHE_CLEANUP_INTERVAL", "300")
        )  # 5 minutes
    )

    # Logging configuration
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # Connection pooling
    max_connections: int = field(
        default_factory=lambda: int(os.getenv("MAX_CONNECTIONS", "100"))
    )
    max_keepalive_connections: int = field(
        default_factory=lambda: int(os.getenv("MAX_KEEPALIVE_CONNECTIONS", "20"))
    )

    # Retry configuration
    max_retries: int = field(default_factory=lambda: int(os.getenv("MAX_RETRIES", "3")))
    retry_delay: float = field(
        default_factory=lambda: float(os.getenv("RETRY_DELAY", "1.0"))
    )
    
    # Concurrent lookup configuration
    max_concurrent_lookups: int = field(
        default_factory=lambda: int(os.getenv("MAX_CONCURRENT_LOOKUPS", "10"))
    )
    delay_between_requests: float = field(
        default_factory=lambda: float(os.getenv("DELAY_BETWEEN_REQUESTS", "0.1"))
    )
    
    # HTTP server configuration
    http_host: str = field(default_factory=lambda: os.getenv("HTTP_HOST", "0.0.0.0"))
    http_port: int = field(default_factory=lambda: int(os.getenv("HTTP_PORT", "8000")))

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "whois_timeout": self.whois_timeout,
            "rdap_timeout": self.rdap_timeout,
            "global_rate_limit_per_second": self.global_rate_limit_per_second,
            "global_rate_limit_burst": self.global_rate_limit_burst,
            "client_rate_limit_per_second": self.client_rate_limit_per_second,
            "client_rate_limit_burst": self.client_rate_limit_burst,
            "cache_ttl": self.cache_ttl,
            "cache_max_size": self.cache_max_size,
            "cache_cleanup_interval": self.cache_cleanup_interval,
            "log_level": self.log_level,
            "max_connections": self.max_connections,
            "max_keepalive_connections": self.max_keepalive_connections,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "max_concurrent_lookups": self.max_concurrent_lookups,
            "delay_between_requests": self.delay_between_requests,
            "http_host": self.http_host,
            "http_port": self.http_port,
        }

    @classmethod
    def from_env(cls) -> "Config":
        """Create config from environment variables."""
        return cls()

    def validate(self) -> None:
        """Validate configuration values."""
        if self.bind_port < 1 or self.bind_port > 65535:
            raise ValueError(f"Invalid port number: {self.bind_port}")

        if self.whois_timeout <= 0:
            raise ValueError(f"Invalid whois timeout: {self.whois_timeout}")

        if self.rdap_timeout <= 0:
            raise ValueError(f"Invalid RDAP timeout: {self.rdap_timeout}")

        if self.global_rate_limit_per_second <= 0:
            raise ValueError(
                f"Invalid global rate limit: {self.global_rate_limit_per_second}"
            )

        if self.client_rate_limit_per_second <= 0:
            raise ValueError(
                f"Invalid client rate limit: {self.client_rate_limit_per_second}"
            )

        if self.cache_ttl <= 0:
            raise ValueError(f"Invalid cache TTL: {self.cache_ttl}")

        if self.cache_max_size <= 0:
            raise ValueError(f"Invalid cache max size: {self.cache_max_size}")

        if self.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            raise ValueError(f"Invalid log level: {self.log_level}")


# Global config instance
config = Config()
