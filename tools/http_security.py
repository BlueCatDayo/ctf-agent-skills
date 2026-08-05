"""Centralized HTTP URL safety validation.

Only http:// and https:// targets are allowed.  Requests to loopback,
link-local, cloud-metadata, and private-network addresses are blocked
unless explicitly enabled by configuration.
"""

import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")

# Hostnames that resolve to cloud metadata endpoints
BLOCKED_METADATA_HOSTNAMES = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}

# Loopback networks, allowed only when allow_localhost is enabled
LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),   # IPv4 loopback
    ipaddress.ip_network("::1/128"),       # IPv6 loopback
]

# IP networks that are always blocked (metadata + link-local)
ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),     # link-local
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("169.254.169.254/32"), # AWS metadata
    ipaddress.ip_network("169.254.170.2/32"),   # AWS ECS metadata
    ipaddress.ip_network("100.100.100.200/32"), # Alibaba metadata
    ipaddress.ip_network("100.100.100.201/32"), # Alibaba metadata
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 metadata
    ipaddress.ip_network("0.0.0.0/8"),          # "this network"
    ipaddress.ip_network("240.0.0.0/4"),        # reserved
]

# Private networks, blocked unless allow_private is enabled
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


class HttpSecurityError(Exception):
    """Raised when a URL fails safety validation."""
    pass


def validate_http_url(
    url: str,
    allow_localhost: bool = False,
    allow_private: bool = False,
) -> Tuple[str, Optional[str]]:
    """Validate a URL for HTTP use.

    Returns ``(cleaned_url, None)`` on success or ``(None, error_message)``
    on failure.
    """
    if not url or not isinstance(url, str):
        return None, "URL must be a non-empty string."
    url = url.strip()
    if not url:
        return None, "URL must be a non-empty string."

    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()

    if scheme not in ALLOWED_SCHEMES:
        display = scheme if scheme else "(none)"
        return None, (
            f"Unsupported URL scheme '{display}'. "
            f"Only http:// and https:// are allowed."
        )

    if parsed.username or parsed.password:
        return None, "URLs containing embedded credentials (user:pass@host) are not allowed."

    host = parsed.hostname
    if not host:
        return None, "URL has no valid host."

    # Basic hostname sanity
    if any(ch.isspace() for ch in host) or ".." in host or host.startswith(".") or host.endswith("."):
        return None, f"Invalid host: {host!r}"

    host_lower = host.lower()

    # Hostname-based localhost / metadata checks
    if host_lower == "localhost" or host_lower.endswith(".localhost"):
        if not allow_localhost:
            return None, "Requests to localhost are blocked (set ALLOW_LOCALHOST_TARGETS=true to enable)."
        return url, None

    if host_lower in BLOCKED_METADATA_HOSTNAMES:
        return None, f"Host '{host}' is a known metadata endpoint and is blocked."

    # Try to interpret the host as an IP literal
    try:
        ip = ipaddress.ip_address(host_lower)
    except ValueError:
        ip = None

    if ip is not None:
        # Loopback addresses: blocked unless explicitly enabled
        if not allow_localhost:
            for net in LOOPBACK_NETWORKS:
                if ip in net:
                    return None, (
                        f"Address {host} is a loopback address and is blocked "
                        f"(set ALLOW_LOCALHOST_TARGETS=true to enable)."
                    )
        # Metadata / link-local: always blocked
        for net in ALWAYS_BLOCKED_NETWORKS:
            if ip in net:
                return None, (
                    f"Address {host} is a link-local/metadata address and is blocked."
                )
        if not allow_private:
            for net in PRIVATE_NETWORKS:
                if ip in net:
                    return None, (
                        f"Address {host} is in a private network range and is blocked "
                        f"(set ALLOW_PRIVATE_TARGETS=true to enable)."
                    )
    return url, None
