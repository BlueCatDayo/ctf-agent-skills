"""Stage 5 web exploitation tools.

Reusable, callable tools for authorized CTF web challenges:
- Convenience HTTP wrappers (GET/POST/PUT/DELETE)
- Cookie and session management (delegates to the shared HTTP session)
- Header analysis, robots.txt / sitemap.xml readers
- HTML parsing: links, forms, JavaScript, comments
- Endpoint discovery: directories, API routes, hidden endpoints
- JWT decoding / parsing (delegates to decoder_tools)

All network access goes through :func:`tools.http_tools._fetch` so URL
safety validation (localhost/private/metadata blocking) always applies.
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .http_tools import _fetch, _format_response, DEFAULT_BODY_LIMIT, http_request, manage_http_session
from .http_session import is_sensitive_cookie, is_sensitive_header, mask_value
from .html_parser import (
    extract_api_routes,
    extract_comments,
    extract_forms,
    extract_links,
    extract_scripts,
    extract_visible_text,
)

# Small, conservative default wordlists (no large-scale brute forcing).
# These are common paths used by CTF challenges, not exhaustive wordlists.
DEFAULT_DIRECTORY_WORDLIST = [
    "admin", "api", "backup", "config", "debug", "dev", "flag", "hidden",
    "login", "logout", "panel", "private", "secret", "server-status",
    "shell", "static", "test", "tmp", "upload", "uploads", "user", "users",
]

DEFAULT_API_WORDLIST = [
    "api", "api/v1", "api/v2", "api/users", "api/admin", "api/login",
    "api/config", "api/flag", "api/status", "api/debug", "api/health",
    "api/auth", "api/token", "api/version", "graphql", "swagger",
    "openapi.json", "swagger.json", "swagger-ui",
]

DEFAULT_HIDDEN_WORDLIST = [
    ".git/HEAD", ".git/config", ".env", ".htaccess", "robots.txt",
    "sitemap.xml", "backup.zip", "backup.tar.gz", "config.php.bak",
    "config.json", "db.sql", "database.sql", "flag.txt", "index.php.bak",
    "wp-config.php", "source.zip", "www.zip", "error.log", "debug.log",
]

# Interesting paths for recon helpers
LOGIN_PATHS = [
    "login", "signin", "sign-in", "auth", "auth/login", "login.php",
    "index.php?page=login", "user/login", "account/login", "wp-login.php",
    "admin/login", "api/login",
]

ADMIN_PATHS = [
    "admin", "administrator", "admin.php", "panel", "controlpanel",
    "admin/login", "adminpanel", "dashboard", "manage", "backend",
    "wp-admin", "api/admin",
]

BACKUP_SUFFIXES = [
    ".bak", ".old", "~", ".swp", ".swo", ".save", ".orig", ".tmp",
    ".zip", ".tar.gz", ".sql", ".json", ".txt",
]


def _normalize_base(url: str) -> str:
    """Normalize a base URL for path joining.

    Removes trailing slashes and any existing path so that sub-resource
    lookups are predictable.
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _path_url(base: str, path: str) -> str:
    """Join *base* and *path* with a single slash."""
    base = _normalize_base(base)
    if path.startswith("/"):
        return base + path
    return base + "/" + path


# ---------------------------------------------------------------------------
# Convenience HTTP wrappers
# ---------------------------------------------------------------------------

def http_get(
    url: str,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Send a GET request to an authorized CTF target.

    Returns status, headers, cookies, redirects, and truncated body.
    """
    return http_request(
        url, method="GET", params=params, headers=headers, cookies=cookies,
        timeout=timeout, max_body_chars=max_body_chars,
    )


def http_post(
    url: str,
    form_data: Optional[Dict[str, str]] = None,
    json_body: Any = None,
    raw_body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Send a POST request with form/JSON/raw body support."""
    return http_request(
        url, method="POST", form_data=form_data, json_body=json_body,
        raw_body=raw_body, headers=headers, cookies=cookies, params=params,
        timeout=timeout, max_body_chars=max_body_chars,
    )


def http_put(
    url: str,
    json_body: Any = None,
    raw_body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Send a PUT request with JSON or raw body support."""
    return http_request(
        url, method="PUT", json_body=json_body, raw_body=raw_body,
        headers=headers, cookies=cookies, timeout=timeout,
        max_body_chars=max_body_chars,
    )


def http_delete(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Send a DELETE request to an authorized CTF target."""
    return http_request(
        url, method="DELETE", headers=headers, cookies=cookies,
        timeout=timeout, max_body_chars=max_body_chars,
    )


def manage_cookies(
    operation: str = "show",
    cookie_name: Optional[str] = None,
    cookie_value: Optional[str] = None,
    cookie_domain: str = "",
) -> str:
    """Manage the shared HTTP session's cookies.

    Operations: show, clear_cookies, set_cookie, remove_cookie.
    """
    return manage_http_session(
        operation=operation,
        cookie_name=cookie_name,
        cookie_value=cookie_value,
        cookie_domain=cookie_domain,
    )


def manage_session(
    operation: str = "show",
    header_name: Optional[str] = None,
    header_value: Optional[str] = None,
) -> str:
    """Manage the shared HTTP session.

    Operations: show (summary), show_headers, set_header, remove_header,
    reset.  Cookie operations are handled by manage_cookies.
    """
    return manage_http_session(
        operation=operation,
        header_name=header_name,
        header_value=header_value,
    )


# ---------------------------------------------------------------------------
# Header / resource readers
# ---------------------------------------------------------------------------

def analyze_headers(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Fetch *url* (GET) and report the full response header set.

    Highlights security-related headers and cookie attributes.
    """
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)

    headers = res.get("headers") or {}
    cookies = res.get("cookies") or {}
    lines = [
        f"URL: {res.get('url')}",
        f"Final URL: {res.get('final_url')}",
        f"Status code: {res.get('status_code')}",
        f"Content type: {res.get('content_type') or '(none)'}",
    ]
    if headers:
        lines.append(f"All response headers ({len(headers)}):")
        for name, value in sorted(headers.items()):
            lower = name.lower()
            if is_sensitive_header(name):
                shown = mask_value(value)
                lines.append(f"  {name}: {shown}")
            else:
                lines.append(f"  {name}: {value}")

    security = [
        "content-security-policy", "strict-transport-security",
        "x-content-type-options", "x-frame-options", "x-xss-protection",
        "referrer-policy", "permissions-policy", "server", "x-powered-by",
    ]
    present = [h for h in security if h in headers]
    missing = [h for h in security if h not in headers]
    lines.append(f"Security headers present: {', '.join(present) or 'none'}")
    lines.append(f"Security headers missing: {', '.join(missing) or 'none'}")

    if cookies:
        lines.append("Cookies:")
        for name, value in cookies.items():
            shown = mask_value(value) if is_sensitive_cookie(name) else value
            lines.append(f"  {name} = {shown}")
    return "\n".join(lines)


def read_robots_txt(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Fetch ``/robots.txt`` from the target and summarize its rules.

    Returns the raw directives (User-agent, Allow, Disallow, Sitemap)
    plus any interesting paths they reference.
    """
    base = _normalize_base(url)
    robots_url = _path_url(base, "robots.txt")
    res = _fetch(robots_url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)

    body = res.get("body") or ""
    if res.get("status_code") == 404 or (not body.strip() and res.get("body_length") == 0):
        return f"robots.txt not found at {robots_url} (status {res.get('status_code')})."

    lines = [
        f"robots.txt at {robots_url} (status {res.get('status_code')}, "
        f"{res.get('body_length')} bytes):",
    ]
    disallowed = []
    allowed = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(f"  {stripped}")
        lower = stripped.lower()
        if lower.startswith("disallow:"):
            path = stripped.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif lower.startswith("allow:"):
            path = stripped.split(":", 1)[1].strip()
            if path:
                allowed.append(path)

    if disallowed:
        lines.append(f"Disallowed paths ({len(disallowed)}): {', '.join(disallowed)}")
    if allowed:
        lines.append(f"Allowed paths ({len(allowed)}): {', '.join(allowed)}")
    if not disallowed and not allowed:
        lines.append("No Allow/Disallow directives found (empty robots.txt).")
    return "\n".join(lines)


def read_sitemap_xml(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Fetch ``/sitemap.xml`` and list all URLs it references.

    Handles both sitemap index files (nested <sitemap> entries) and
    plain URL sets (<url>/<loc>).
    """
    base = _normalize_base(url)
    sitemap_url = _path_url(base, "sitemap.xml")
    res = _fetch(sitemap_url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)

    body = res.get("body") or ""
    if res.get("status_code") == 404 or not body.strip():
        return f"sitemap.xml not found at {sitemap_url} (status {res.get('status_code')})."

    import xml.etree.ElementTree as ET
    urls = []
    try:
        root = ET.fromstring(body)
        ns = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
        for loc in root.iter(f"{ns}loc"):
            if loc.text:
                urls.append(loc.text.strip())
    except ET.ParseError as e:
        # Fall back to regex extraction of <loc> content.
        urls = re.findall(r"<loc>\s*(.*?)\s*</loc>", body, re.IGNORECASE | re.DOTALL)
        if not urls:
            return f"sitemap.xml exists but could not be parsed ({e}). Body preview:\n{body[:500]}"

    lines = [
        f"sitemap.xml at {sitemap_url} (status {res.get('status_code')}, "
        f"{res.get('body_length')} bytes, {len(urls)} URLs):",
    ]
    for u in urls:
        lines.append(f"  {u}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML extraction wrappers
# ---------------------------------------------------------------------------

def extract_links_from_page(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Extract all links (href/src) from a page, resolved to absolute URLs."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(res.get("body") or "", "html.parser")
    links = extract_links(soup, res.get("url") or url)
    return f"Links ({len(links)}):\n" + "\n".join(f"  {l}" for l in links)


def extract_forms_from_page(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Extract forms from a page: action, method, and all input fields."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(res.get("body") or "", "html.parser")
    page_url = res.get("url") or url
    forms = extract_forms(soup, page_url)
    if not forms:
        return "No forms found on the page."
    lines = [f"Forms ({len(forms)}):"]
    for f in forms:
        lines.append(f"  [{f['index']}] {f['method']} -> {f['action']}")
        for inp in f["inputs"]:
            lines.append(
                f"      name={inp['name']} type={inp['type']} hidden={inp['hidden']}"
            )
    return "\n".join(lines)


def extract_javascript_from_page(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Extract JavaScript references and inline scripts from a page."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(res.get("body") or "", "html.parser")
    scripts = extract_scripts(soup, res.get("url") or url)
    if not scripts:
        return "No JavaScript found on the page."
    lines = [f"Scripts ({len(scripts)}):"]
    for s in scripts:
        lines.append(f"  {s[:200]}")
    return "\n".join(lines)


def extract_html_comments(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Extract HTML comments from a page (often hide hints/endpoints)."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(res.get("body") or "", "html.parser")
    comments = extract_comments(soup)
    if not comments:
        return "No HTML comments found on the page."
    lines = [f"HTML comments ({len(comments)}):"]
    for c in comments:
        lines.append(f"  {c}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------

def enumerate_directories(
    url: str,
    wordlist: Optional[List[str]] = None,
    max_checks: int = 40,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Probe common directory paths on the target and report their status.

    Uses a small, conservative built-in wordlist (no brute-force scanning).
    Only the configured number of paths are checked (default max 40).

    Returns a table of path -> status for interesting (non-404) results.
    """
    paths = wordlist or DEFAULT_DIRECTORY_WORDLIST
    paths = paths[:max_checks]
    base = _normalize_base(url)

    results = []
    for path in paths:
        target = _path_url(base, path)
        res = _fetch(target, method="GET")
        status = res.get("status_code")
        length = res.get("body_length") or 0
        if res.get("error_type"):
            results.append((path, f"error: {res.get('error_type')}", 0))
            continue
        # Ignore obvious 404s; report everything else as interesting.
        if status == 404:
            continue
        results.append((path, str(status), length))

    if not results:
        return (
            f"No interesting paths found for {base} "
            f"(checked {len(paths)} common paths; all returned 404)."
        )

    lines = [
        f"Directory enumeration for {base} "
        f"(checked {len(paths)} paths, {len(results)} interesting):"
    ]
    for path, status, length in results:
        lines.append(f"  /{path.lstrip('/')} -> status {status} ({length} bytes)")
    return "\n".join(lines)


def discover_api_endpoints(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Discover API endpoints from page source and common API paths.

    Combines client-side route extraction (scripts, inline JS) with a
    small probe list of common API paths.
    """
    base = _normalize_base(url)
    res = _fetch(url, method="GET")
    source_routes: List[str] = []
    if not res.get("error_type"):
        body = res.get("body") or ""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "html.parser")
        source_routes = extract_api_routes(soup, body)

    lines = [f"API endpoint discovery for {base}:"]
    if source_routes:
        lines.append(f"From page source ({len(source_routes)}):")
        for r in sorted(set(source_routes))[:30]:
            lines.append(f"  {r}")
    else:
        lines.append("No API routes found in page source.")

    probed = []
    for path in DEFAULT_API_WORDLIST:
        target = _path_url(base, path)
        r = _fetch(target, method="GET")
        status = r.get("status_code")
        if r.get("error_type") or status == 404:
            continue
        probed.append((path, status, r.get("body_length") or 0))

    if probed:
        lines.append(f"Probed common API paths ({len(probed)} interesting):")
        for path, status, length in probed:
            lines.append(f"  /{path} -> status {status} ({length} bytes)")
    else:
        lines.append("No common API paths responded with a non-404 status.")

    return "\n".join(lines)


def discover_hidden_endpoints(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Discover hidden endpoints: sensitive files, backups, and metadata.

    Checks page comments/scripts for hints and probes a small list of
    sensitive paths (.git, .env, backups, debug logs, flag files).
    """
    base = _normalize_base(url)
    hints: List[str] = []
    res = _fetch(url, method="GET")
    if not res.get("error_type"):
        body = res.get("body") or ""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "html.parser")
        for c in extract_comments(soup):
            for m in re.findall(r"[\w\-./]{3,}", c):
                if ("/" in m or "." in m) and not m.startswith("http"):
                    hints.append(m)
        for s in extract_scripts(soup, res.get("url") or url):
            for m in re.findall(r"(?:src|href)=[\"']([^\"']+)[\"']", s, re.IGNORECASE):
                if "/" in m:
                    hints.append(m)

    lines = [f"Hidden endpoint discovery for {base}:"]
    if hints:
        seen = sorted(set(hints))[:20]
        lines.append(f"Hints from page ({len(seen)} unique):")
        for h in seen:
            lines.append(f"  {h}")
    else:
        lines.append("No hidden endpoint hints found in page source.")

    found = []
    for path in DEFAULT_HIDDEN_WORDLIST:
        target = _path_url(base, path)
        r = _fetch(target, method="GET")
        status = r.get("status_code")
        if r.get("error_type") or status == 404:
            continue
        found.append((path, status, r.get("body_length") or 0))

    if found:
        lines.append(f"Sensitive paths found ({len(found)}):")
        for path, status, length in found:
            lines.append(f"  /{path} -> status {status} ({length} bytes)")
    else:
        lines.append("No sensitive paths responded with a non-404 status.")

    return "\n".join(lines)
