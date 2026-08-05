"""Stage 5 recon helper tools.

Helpers for web reconnaissance on authorized CTF targets:

- find_login_page / find_admin_page
- find_api_endpoints
- find_backup_files
- detect_framework / detect_server / detect_technology_stack
- extract_emails
- extract_version_info

Every helper is conservative: small built-in candidate lists, sequential
requests, and full reliance on the shared URL-safety validation.
"""

import re
from typing import Dict, List, Optional

from .http_tools import _fetch, _format_response, DEFAULT_BODY_LIMIT
from .web_tools import (
    LOGIN_PATHS,
    ADMIN_PATHS,
    BACKUP_SUFFIXES,
    DEFAULT_API_WORDLIST,
    _normalize_base,
    _path_url,
)


def _extract_title(body: str) -> str:
    """Extract the <title> text from an HTML body (best effort)."""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:80]
    return ""


# ---------------------------------------------------------------------------
# Page finders
# ---------------------------------------------------------------------------

def find_login_page(
    url: str,
    max_checks: int = 12,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Probe common login paths and report which exist (non-404).

    Returns found login URLs with status codes and a hint of page title.
    """
    base = _normalize_base(url)
    found = []
    for path in LOGIN_PATHS[:max_checks]:
        target = _path_url(base, path)
        res = _fetch(target, method="GET")
        status = res.get("status_code")
        if res.get("error_type") or status == 404:
            continue
        title = _extract_title(res.get("body") or "")
        found.append((target, status, title))

    if not found:
        return (
            f"No common login pages found at {base} "
            f"(checked {min(len(LOGIN_PATHS), max_checks)} paths)."
        )

    lines = [f"Login pages found at {base} ({len(found)}):"]
    for target, status, title in found:
        lines.append(f"  {target} -> status {status} ({title or 'no title'})")
    return "\n".join(lines)


def find_admin_page(
    url: str,
    max_checks: int = 12,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Probe common admin paths and report which exist (non-404)."""
    base = _normalize_base(url)
    found = []
    for path in ADMIN_PATHS[:max_checks]:
        target = _path_url(base, path)
        res = _fetch(target, method="GET")
        status = res.get("status_code")
        if res.get("error_type") or status == 404:
            continue
        title = _extract_title(res.get("body") or "")
        found.append((target, status, title))

    if not found:
        return (
            f"No common admin pages found at {base} "
            f"(checked {min(len(ADMIN_PATHS), max_checks)} paths)."
        )

    lines = [f"Admin pages found at {base} ({len(found)}):"]
    for target, status, title in found:
        lines.append(f"  {target} -> status {status} ({title or 'no title'})")
    return "\n".join(lines)


def find_api_endpoints(
    url: str,
    max_checks: int = 20,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Probe common API endpoints and report which respond.

    Also scans the main page source for client-side API route references.
    """
    base = _normalize_base(url)
    found = []
    for path in DEFAULT_API_WORDLIST[:max_checks]:
        target = _path_url(base, path)
        res = _fetch(target, method="GET")
        status = res.get("status_code")
        if res.get("error_type") or status == 404:
            continue
        found.append((target, status, res.get("body_length") or 0))

    if not found:
        return (
            f"No common API endpoints found at {base} "
            f"(checked {min(len(DEFAULT_API_WORDLIST), max_checks)} paths)."
        )

    lines = [f"API endpoints found at {base} ({len(found)}):"]
    for target, status, length in found:
        lines.append(f"  {target} -> status {status} ({length} bytes)")
    return "\n".join(lines)


def find_backup_files(
    url: str,
    file_paths: Optional[List[str]] = None,
    max_checks: int = 30,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Probe for backup files: ``index.php.bak``, ``db.sql``, etc.

    Generates candidates from common base filenames combined with common
    backup suffixes.  Stops after *max_checks* probes.
    """
    base = _normalize_base(url)
    bases = file_paths or [
        "index", "index.php", "config", "config.php", "db", "database",
        "backup", "site", "app", "main", "default", "wp-config", "server",
    ]
    candidates = []
    for b in bases:
        for suffix in BACKUP_SUFFIXES:
            candidates.append(f"{b}{suffix}")

    found = []
    for path in candidates[:max_checks]:
        target = _path_url(base, path)
        res = _fetch(target, method="GET")
        status = res.get("status_code")
        if res.get("error_type") or status == 404:
            continue
        found.append((target, status, res.get("body_length") or 0))

    if not found:
        return (
            f"No backup files found at {base} "
            f"(checked {min(len(candidates), max_checks)} candidates)."
        )

    lines = [f"Backup files found at {base} ({len(found)}):"]
    for target, status, length in found:
        lines.append(f"  {target} -> status {status} ({length} bytes)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Technology detection
# ---------------------------------------------------------------------------

def detect_framework(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Detect the web framework from page source markers and headers."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    body = (res.get("body") or "").lower()
    headers = res.get("headers") or {}
    server = (headers.get("Server") or headers.get("server") or "").lower()

    evidence: Dict[str, str] = {}
    markers = {
        "Django": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "Flask": ["flask", "__debugger__"],
        "Laravel": ["laravel", "csrf-token", "laravel_session"],
        "Express": ["x-powered-by: express"],
        "Next.js": ["__next", "next.js", "_next/static"],
        "React": ["react", "_next/static"],
        "Angular": ["ng-", "angular"],
        "Vue": ["vue", "data-v-"],
        "WordPress": ["wp-content", "wp-includes", "wp-json"],
        "Drupal": ["drupal", "sites/default"],
        "Joomla": ["joomla", "com_content"],
        "ASP.NET": ["__viewstate", "asp.net", ".aspx"],
        "Ruby on Rails": ["rails", "authenticity_token"],
        "Spring": ["spring", "javax.servlet"],
        "Symfony": ["symfony", "_csrf"],
    }
    for framework, needles in markers.items():
        if any(n in body for n in needles):
            evidence[framework] = "page source marker"
            break  # one marker per family is enough to flag

    for s in ["laravel", "django", "flask", "express", "asp.net", "spring"]:
        if s in server:
            evidence[s.title()] = f"server header contains '{s}'"

    if not evidence:
        return (
            f"No framework confidently identified at {url}. "
            f"Server header: {server or '(none)'}."
        )
    lines = [f"Framework detection for {url}:"]
    for name, why in sorted(evidence.items()):
        lines.append(f"  {name}: {why}")
    return "\n".join(lines)


def detect_server(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Report the server software from response headers."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    headers = res.get("headers") or {}
    interesting = {}
    for name, value in headers.items():
        lower = name.lower()
        if lower in (
            "server", "x-powered-by", "x-aspnet-version", "via",
            "x-backend-server", "x-forwarded-server", "x-generator",
            "x-drupal-cache", "x-served-by",
        ):
            interesting[name] = value

    if not interesting:
        return f"No identifying server headers at {url}."
    lines = [f"Server detection for {url}:"]
    for name, value in sorted(interesting.items()):
        lines.append(f"  {name}: {value}")
    return "\n".join(lines)


def detect_technology_stack(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Combine server + framework + frontend library detection."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    body = (res.get("body") or "").lower()
    headers = res.get("headers") or {}

    stack = []

    server = (headers.get("Server") or headers.get("server") or "").strip()
    if server:
        stack.append(f"Server: {server}")
    for name, value in headers.items():
        if name.lower() == "x-powered-by":
            stack.append(f"X-Powered-By: {value}")

    js_libs = []
    for lib, needles in {
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "React": ["react"],
        "Vue": ["vue"],
        "Angular": ["angular", "ng-"],
        "HTMX": ["htmx"],
        "Alpine.js": ["alpine"],
        "Tailwind CSS": ["tailwind"],
    }.items():
        if any(n in body for n in needles):
            js_libs.append(lib)
    if js_libs:
        stack.append(f"Frontend libraries: {', '.join(js_libs)}")

    if not stack:
        return f"No technology stack confidently identified at {url}."

    lines = [f"Technology stack detection for {url}:"]
    for item in stack:
        lines.append(f"  {item}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Content extraction
# ---------------------------------------------------------------------------

def extract_emails(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Extract email addresses from the page body."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    body = res.get("body") or ""
    emails = re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", body)
    unique = sorted(set(emails))
    if not unique:
        return f"No email addresses found at {url}."
    lines = [f"Emails found at {url} ({len(unique)}):"]
    for e in unique:
        lines.append(f"  {e}")
    return "\n".join(lines)


def extract_version_info(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Extract version numbers from headers and page source."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)
    body = res.get("body") or ""
    headers = res.get("headers") or {}

    lines = [f"Version info for {url}:"]
    found_any = False

    for name, value in headers.items():
        if re.search(r"\d+\.\d+(\.\d+)?", str(value)):
            lines.append(f"  Header {name}: {value}")
            found_any = True

    patterns = [
        (r"(?:jquery|jquery\.min\.js)[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)", "jQuery"),
        (r"bootstrap[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)", "Bootstrap"),
        (r"react[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)", "React"),
        (r"(?:vue|vue\.js)[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)", "Vue"),
        (r"generator[^>]*content=[\"']([^\"']+)[\"']", "Generator meta"),
        (r"wordpress[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)", "WordPress"),
        (r"drupal[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)", "Drupal"),
        (r"php[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)", "PHP"),
    ]
    for pat, label in patterns:
        for m in re.finditer(pat, body, re.IGNORECASE):
            lines.append(f"  {label}: {m.group(1)}")
            found_any = True
            break

    if not found_any:
        return f"No version information found at {url}."
    return "\n".join(lines)
