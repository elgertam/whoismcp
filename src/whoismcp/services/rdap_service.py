"""
RDAP (Registration Data Access Protocol) service implementation.
Handles HTTPS requests to RDAP servers for structured domain data.
"""

import json
from typing import Any

import httpx
import structlog

from ..config import Config
from ..models.domain_models import RDAPResult
from ..utils.validators import is_valid_domain, is_valid_ip

logger = structlog.get_logger(__name__)


class RDAPService:
    """Asynchronous RDAP service for domain and IP lookups."""

    # RDAP bootstrap registry URLs
    RDAP_BOOTSTRAP_URLS = {
        "domain": "https://data.iana.org/rdap/dns.json",
        "ipv4": "https://data.iana.org/rdap/ipv4.json",
        "ipv6": "https://data.iana.org/rdap/ipv6.json",
        "asn": "https://data.iana.org/rdap/asn.json",
    }

    # Common RDAP servers (fallback when bootstrap fails)
    RDAP_SERVERS = {
        # Generic TLDs
        "com": ["https://rdap.verisign.com/com/v1/"],
        "net": ["https://rdap.verisign.com/net/v1/"],
        "org": ["https://rdap.publicinterestregistry.org/rdap/"],
        "info": ["https://rdap.afilias.net/rdap.afilias.info/"],
        "biz": ["https://rdap.nic.biz/"],
        # Country code TLDs
        "uk": ["https://rdap.nominet.uk/uk/"],
        "de": ["https://rdap.denic.de/"],
        "fr": ["https://rdap.nic.fr/"],
        "nl": ["https://rdap.dns.nl/"],
        "au": ["https://rdap.audns.net.au/"],
        # Regional Internet Registries
        "arin": ["https://rdap.arin.net/registry/"],
        "ripe": ["https://rdap.db.ripe.net/"],
        "apnic": ["https://rdap.apnic.net/"],
        "lacnic": ["https://rdap.lacnic.net/rdap/"],
        "afrinic": ["https://rdap.afrinic.net/rdap/"],
    }

    def __init__(self, config: Config):
        self.config = config
        self._bootstrap_cache = {}
        self._http_client = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with connection pooling."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.rdap_timeout),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
                headers={
                    "User-Agent": "MCP-Whois-RDAP-Server/1.0.0",
                    "Accept": "application/rdap+json, application/json",
                },
                follow_redirects=True,
            )
        return self._http_client

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Perform RDAP lookup for a domain name."""
        if not is_valid_domain(domain):
            raise ValueError(f"Invalid domain name: {domain}")

        logger.info("Starting domain RDAP lookup", domain=domain)

        try:
            # Get RDAP servers for the domain
            rdap_servers = await self._get_domain_rdap_servers(domain)

            # Try each server until one succeeds
            last_error = None
            for server in rdap_servers:
                try:
                    response = await self._query_rdap_server(server, f"domain/{domain}")

                    result = RDAPResult(
                        target=domain,
                        target_type="domain",
                        rdap_server=server,
                        response_data=response,
                        success=True,
                        error=None,
                    )

                    logger.info(
                        "Domain RDAP lookup completed successfully",
                        domain=domain,
                        server=server,
                    )

                    return result.model_dump(mode="json")

                except Exception as e:
                    last_error = e
                    logger.warning(
                        "RDAP server failed, trying next",
                        domain=domain,
                        server=server,
                        error=str(e),
                    )
                    continue

            # All servers failed - preserve the last error type
            if last_error and "not found" in str(last_error).lower():
                raise ValueError(f"Domain not found: {domain}") from last_error
            else:
                raise RuntimeError("All RDAP servers failed")

        except Exception as e:
            logger.error("Domain RDAP lookup failed", domain=domain, error=str(e))

            return RDAPResult(
                target=domain,
                target_type="domain",
                rdap_server="unknown",
                response_data={},
                success=False,
                error=str(e),
            ).model_dump(mode="json")

    async def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        """Perform RDAP lookup for an IP address."""
        if not is_valid_ip(ip_address):
            raise ValueError(f"Invalid IP address: {ip_address}")

        logger.info("Starting IP RDAP lookup", ip=ip_address)

        try:
            # Get RDAP servers for the IP
            rdap_servers = await self._get_ip_rdap_servers(ip_address)

            # Try each server until one succeeds
            for server in rdap_servers:
                try:
                    response = await self._query_rdap_server(server, f"ip/{ip_address}")

                    result = RDAPResult(
                        target=ip_address,
                        target_type="ip",
                        rdap_server=server,
                        response_data=response,
                        success=True,
                        error=None,
                    )

                    logger.info(
                        "IP RDAP lookup completed successfully",
                        ip=ip_address,
                        server=server,
                    )

                    return result.model_dump(mode="json")

                except Exception as e:
                    logger.warning(
                        "RDAP server failed, trying next",
                        ip=ip_address,
                        server=server,
                        error=str(e),
                    )
                    continue

            # All servers failed
            raise RuntimeError("All RDAP servers failed")

        except Exception as e:
            logger.error("IP RDAP lookup failed", ip=ip_address, error=str(e))

            return RDAPResult(
                target=ip_address,
                target_type="ip",
                rdap_server="unknown",
                response_data={},
                success=False,
                error=str(e),
            ).model_dump(mode="json")

    async def _get_domain_rdap_servers(self, domain: str) -> list[str]:
        """Get RDAP servers for a domain using bootstrap registry."""
        try:
            # Try bootstrap registry first
            bootstrap_data = await self._get_bootstrap_data("domain")
            if bootstrap_data:
                tld = domain.split(".")[-1].lower()
                servers = self._find_servers_in_bootstrap(bootstrap_data, tld)
                if servers:
                    return servers
        except Exception as e:
            logger.warning("Bootstrap registry failed", error=str(e))

        # Fallback to static server list
        tld = domain.split(".")[-1].lower()
        return self.RDAP_SERVERS.get(tld, [f"https://rdap.nic.{tld}/"])

    async def _get_ip_rdap_servers(self, ip_address: str) -> list[str]:
        """Get RDAP servers for an IP address using bootstrap registry."""
        try:
            # Try bootstrap registry first
            ip_version = "ipv6" if ":" in ip_address else "ipv4"
            bootstrap_data = await self._get_bootstrap_data(ip_version)
            if bootstrap_data:
                servers = self._find_servers_in_bootstrap(bootstrap_data, ip_address)
                if servers:
                    return servers
        except Exception as e:
            logger.warning("Bootstrap registry failed", error=str(e))

        # Fallback to RIR servers
        registry = self._get_ip_registry(ip_address)
        return self.RDAP_SERVERS.get(registry, self.RDAP_SERVERS["arin"])

    async def _get_bootstrap_data(self, registry_type: str) -> dict[str, Any] | None:
        """Get bootstrap data from IANA registry."""
        if registry_type in self._bootstrap_cache:
            return self._bootstrap_cache[registry_type]

        try:
            url = self.RDAP_BOOTSTRAP_URLS.get(registry_type)
            if not url:
                return None

            client = await self._get_http_client()
            response = await client.get(url)
            response.raise_for_status()

            data = response.json()
            self._bootstrap_cache[registry_type] = data
            return data

        except Exception as e:
            logger.warning(
                "Failed to fetch bootstrap data",
                registry_type=registry_type,
                error=str(e),
            )
            return None

    def _find_servers_in_bootstrap(
        self, bootstrap_data: dict[str, Any], target: str
    ) -> list[str]:
        """Find RDAP servers in bootstrap data for a target."""
        services = bootstrap_data.get("services", [])

        for service in services:
            if len(service) >= 2:
                patterns = service[0]  # First element contains patterns
                servers = service[1]  # Second element contains servers

                # Check if target matches any pattern
                for pattern in patterns:
                    if self._matches_pattern(target, pattern):
                        return servers

        return []

    def _matches_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches a bootstrap pattern."""
        # For domains, check TLD match
        if "." in target:
            target_tld = target.split(".")[-1].lower()
            return target_tld == pattern.lower()

        # For IPs, check if IP is in CIDR range
        try:
            import ipaddress

            if "/" in pattern:
                network = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(target)
                return ip in network
            else:
                return target == pattern
        except Exception:
            return False

    def _get_ip_registry(self, ip_address: str) -> str:
        """Get the registry for an IP address (simplified)."""
        try:
            import ipaddress

            ip = ipaddress.IPv4Address(ip_address)

            # Simplified regional allocation
            if ip in ipaddress.IPv4Network("192.0.0.0/3"):  # Americas
                return "arin"
            elif ip in ipaddress.IPv4Network("80.0.0.0/4"):  # Europe
                return "ripe"
            elif ip in ipaddress.IPv4Network("58.0.0.0/7"):  # Asia Pacific
                return "apnic"
            else:
                return "arin"  # Default fallback

        except Exception:
            return "arin"  # Default fallback

    async def _query_rdap_server(self, server: str, path: str) -> dict[str, Any]:
        """Query an RDAP server and return parsed response."""
        try:
            # Construct full URL
            if not server.endswith("/"):
                server += "/"
            url = f"{server}{path}"

            # Make HTTP request
            client = await self._get_http_client()
            response = await client.get(url)

            # Log redirect information if any
            if response.history:
                logger.debug(
                    "RDAP request redirected",
                    original_url=url,
                    final_url=str(response.url),
                    redirect_count=len(response.history),
                    redirect_codes=[r.status_code for r in response.history],
                )

            response.raise_for_status()

            # Parse JSON response
            data = response.json()

            # Validate RDAP response structure
            if not isinstance(data, dict):
                raise ValueError("Invalid RDAP response format")

            logger.debug(
                "RDAP query successful",
                server=server,
                path=path,
                response_size=len(str(data)),
            )

            return data

        except httpx.TimeoutException as te:
            raise TimeoutError(f"RDAP query timeout for {server}") from te
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise ValueError(f"Resource not found: {path}") from e
            else:
                raise RuntimeError(
                    f"RDAP server error {e.response.status_code}: {e}"
                ) from e
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON response from RDAP server: {e}") from e
        except Exception as e:
            raise RuntimeError(f"RDAP query failed: {e}") from e

    async def close(self):
        """Close HTTP client and cleanup resources."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
