"""
WhoisMCP - Model Context Protocol Server for Whois and RDAP lookups.

A high-performance MCP server providing domain and IP address lookup services
using both traditional Whois and modern RDAP protocols.
"""

__version__ = "0.4.0"
__author__ = "Whois MCP Server"
__email__ = "server@example.com"

from .config import Config
from .models import DomainInfo, IPInfo, RDAPResult, WhoisResult
from .services import CacheService, RDAPService, WhoisService

__all__ = [
    "Config",
    "WhoisService",
    "RDAPService",
    "CacheService",
    "WhoisResult",
    "RDAPResult",
    "DomainInfo",
    "IPInfo",
]
