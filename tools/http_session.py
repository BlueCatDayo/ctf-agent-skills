"""Reusable HTTP session logic for CTF web challenge analysis.

Centralizes the httpx client, persistent cookie jar, default headers,
and sensitive-value masking.  Network and parsing concerns stay separate
(see http_tools.py / html_parser.py).
"""

from typing import Any, Dict, List, Optional

import httpx

DEFAULT_USER_AGENT = "CTF-Agent/1.0 (educational; authorized targets only)"

# Headers whose values must never be shown unmasked
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "proxy-authenticate",
    "x-api-key",
    "api-key",
    "apikey",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "session",
    "session-id",
    "x-session-token",
}

# Cookie names treated as sensitive
SENSITIVE_COOKIE_NAMES = (
    "session",
    "sessionid",
    "sid",
    "token",
    "auth",
    "jwt",
    "csrf",  # CSRF tokens are still masked by default for safety
)


def mask_value(value: str, visible_chars: int = 4) -> str:
    """Mask a sensitive value, keeping only the first few characters."""
    if not value:
        return "(empty)"
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * 8


def is_sensitive_header(name: str) -> bool:
    """Return True if a header should be masked in output."""
    return name.lower() in SENSITIVE_HEADERS


def is_sensitive_cookie(name: str) -> bool:
    """Return True if a cookie should be masked in output."""
    lower = name.lower()
    return any(key in lower for key in SENSITIVE_COOKIE_NAMES)


class HttpSessionManager:
    """Manages a persistent HTTP session with cookie and header state."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 5,
        user_agent: str = DEFAULT_USER_AGENT,
        allow_localhost: bool = False,
        allow_private: bool = False,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.allow_localhost = allow_localhost
        self.allow_private = allow_private
        self._transport = transport
        self.cookies: httpx.Cookies = httpx.Cookies()
        self.default_headers: Dict[str, str] = {"User-Agent": user_agent}
        self._client: Optional[httpx.Client] = None

    # ---- client lifecycle -------------------------------------------------

    def get_client(self) -> httpx.Client:
        """Return the shared httpx client, creating it if needed."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                timeout=self.timeout,
                cookies=self.cookies,
                headers=self.default_headers,
                transport=self._transport,
                follow_redirects=False,
            )
        return self._client

    def reset_session(self) -> None:
        """Clear cookies and default headers, and close the client."""
        if self._client is not None:
            self._client.close()
            self._client = None
        self.cookies = httpx.Cookies()
        self.default_headers = {"User-Agent": self.user_agent}

    # ---- cookies ----------------------------------------------------------

    def show_cookies(self) -> str:
        """Return a safe summary of stored cookies (values masked)."""
        if not self.cookies:
            return "No cookies stored in the session."
        lines = []
        for cookie in self.cookies.jar:
            value = cookie.value or ""
            shown = mask_value(value) if is_sensitive_cookie(cookie.name) else value
            lines.append(f"  {cookie.name} = {shown}  (domain={cookie.domain or '*'})")
        return "Stored cookies:\n" + "\n".join(lines)

    def set_cookie(self, name: str, value: str, domain: str = "") -> str:
        """Set a cookie on the session jar."""
        self.cookies.set(name, value, domain=domain, path="/")
        return f"Cookie set: {name} (domain={domain or 'default'})"

    def remove_cookie(self, name: str, domain: str = "") -> str:
        """Remove a cookie from the session jar."""
        before = len(self.cookies.jar)
        try:
            self.cookies.delete(name, domain=domain, path="/")
        except KeyError:
            pass
        after = len(self.cookies.jar)
        if before == after:
            return f"Cookie not found: {name}"
        return f"Cookie removed: {name}"

    def clear_cookies(self) -> str:
        """Remove all cookies from the session jar."""
        count = len(self.cookies.jar)
        self.cookies.clear()
        return f"Cleared {count} cookie(s)."

    # ---- default headers --------------------------------------------------

    def show_headers(self) -> str:
        """Return a safe summary of default headers (sensitive values masked)."""
        if not self.default_headers:
            return "No default headers configured."
        lines = []
        for name, value in self.default_headers.items():
            shown = mask_value(value) if is_sensitive_header(name) else value
            lines.append(f"  {name}: {shown}")
        return "Default headers:\n" + "\n".join(lines)

    def set_header(self, name: str, value: str) -> str:
        """Set a default header on the session."""
        self.default_headers[name] = value
        shown = mask_value(value) if is_sensitive_header(name) else value
        return f"Header set: {name}: {shown}"

    def remove_header(self, name: str) -> str:
        """Remove a default header from the session."""
        if name in self.default_headers:
            del self.default_headers[name]
            return f"Header removed: {name}"
        return f"Header not found: {name}"


# Shared manager used by the tools and the /session CLI command
session_manager = HttpSessionManager()
