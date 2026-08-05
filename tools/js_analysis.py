"""Stage 7 JavaScript analysis tools (spec 6).

Downloads/reads JavaScript and extracts:

- endpoints and API base URLs
- tokens and secrets
- source-map references
- fetch and XMLHttpRequest calls
- GraphQL endpoints
- WebSocket URLs
- hidden routes
- client-side authorization logic
- hardcoded usernames/passwords

Output is capped: only relevant matches with file names / line context are
returned.  Network fetching goes through the shared authorized HTTP
session, so URL safety rules still apply.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .workspace import WorkspaceError, get_workspace_root

MAX_MATCHES_PER_CATEGORY = 12
MAX_REPORT_CHARS = 6000


def _truncate(text: str, limit: int = MAX_REPORT_CHARS) -> str:
    if len(text) > limit:
        return text[:limit] + f"\n... [output truncated at {limit} characters]"
    return text


# ---------------------------------------------------------------------------
# Beautifier (minimal, dependency-free)
# ---------------------------------------------------------------------------

def beautify_javascript(text: str, indent_unit: str = "  ") -> str:
    """Basic JavaScript beautifier: one statement per line with indentation.

    Handles braces, parentheses, and string literals; good enough to make
    minified code searchable without pulling in jsbeautifier.
    """
    if not text:
        return ""
    out: List[str] = []
    depth = 0
    in_string: Optional[str] = None
    escape = False
    i = 0
    n = len(text)
    line = ""
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_string:
            line += ch
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in ("'", '"', "`"):
            in_string = ch
            line += ch
            i += 1
            continue

        if ch == "{":
            out.append(line.rstrip())
            line = ""
            out.append(indent_unit * depth + "{")
            depth += 1
            i += 1
            continue
        if ch == "}":
            out.append(line.rstrip())
            line = ""
            depth = max(0, depth - 1)
            out.append(indent_unit * depth + "}")
            i += 1
            continue
        if ch == ";" and nxt != ";":
            line += ch
            out.append(line.rstrip())
            line = ""
            i += 1
            continue

        line += ch
        i += 1

    if line.strip():
        out.append(line.rstrip())
    return "\n".join(x for x in out if x.strip())


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------

def _collect(text: str, pattern: str, limit: int = MAX_MATCHES_PER_CATEGORY) -> List[str]:
    seen: List[str] = []
    for m in re.finditer(pattern, text, re.IGNORECASE):
        value = m.group(1) if m.groups() else m.group(0)
        value = value.strip().strip("'\"`")
        if value and value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return seen


def extract_javascript_endpoints(text: str) -> List[str]:
    """Extract path-like strings that look like API endpoints."""
    return _collect(
        text,
        r"['\"`]((?:/api|/v\d+|/admin|/auth|/user|/users|/login|/config|/graphql)[A-Za-z0-9_\-/{}:.?&=]*|/[A-Za-z0-9_\-/]{3,60})['\"`]",
    )


def extract_api_base_urls(text: str) -> List[str]:
    """Extract API base URL strings."""
    return _collect(
        text,
        r"['\"`](https?://[A-Za-z0-9_.\-:]+(?::\d+)?(?:/[A-Za-z0-9_\-/]*)?)['\"`]",
    )


def extract_javascript_secrets(text: str) -> List[str]:
    """Extract token/secret-like values."""
    secrets: List[str] = []
    patterns = [
        r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|private[_-]?key|access[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        r"(?i)sk-[A-Za-z0-9]{16,}",
        r"(?i)AKIA[0-9A-Z]{16}",
        r"(?i)eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    ]
    for p in patterns:
        for m in re.finditer(p, text):
            value = m.group(0)[:90]
            if value not in secrets:
                secrets.append(value)
            if len(secrets) >= MAX_MATCHES_PER_CATEGORY:
                return secrets
    return secrets


def extract_hardcoded_credentials(text: str) -> List[str]:
    """Extract hardcoded username/password pairs."""
    found: List[str] = []
    for m in re.finditer(
        r"(?i)(?:username|user|login|email|admin)\s*[:=]\s*['\"]([^'\"]{2,40})['\"]\s*[,;]?\s*(?:password|pass|pwd)\s*[:=]\s*['\"]([^'\"]{2,60})['\"]",
        text,
    ):
        found.append(f"user={m.group(1)!r} pass={m.group(2)!r}")
        if len(found) >= 6:
            break
    # Also standalone password assignments
    if len(found) < 3:
        for m in re.finditer(r"(?i)password\s*[:=]\s*['\"]([^'\"]{2,60})['\"]", text):
            entry = f"password={m.group(1)!r}"
            if entry not in found:
                found.append(entry)
            if len(found) >= 6:
                break
    return found


def extract_source_map_refs(text: str) -> List[str]:
    """Extract sourceMappingURL references."""
    return _collect(text, r"(?:sourceMappingURL|source-map)\s*[=:]\s*['\"]?([^'\"\s;]+\.map['\"]?)")


def extract_fetch_calls(text: str) -> List[str]:
    """Extract fetch() / XMLHttpRequest / axios call targets."""
    found: List[str] = []
    for m in re.finditer(r"\bfetch\s*\(([^)]{2,120})\)", text):
        arg = " ".join(m.group(1).split())[:80]
        entry = f"fetch({arg})"
        if entry not in found:
            found.append(entry)
        if len(found) >= 10:
            return found
    for m in re.finditer(r"\.open\s*\(\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"]([^'\"]{2,120})['\"]", text, re.IGNORECASE):
        found.append(f"XHR {m.group(1)} {m.group(2)!r}")
        if len(found) >= 10:
            return found
    for m in re.finditer(r"(?:axios|\.get|\.post|\.put|\.delete)\s*\(\s*['\"`]([^'\"`]{2,120})['\"`]", text):
        found.append(f"http-call {m.group(1)!r}")
        if len(found) >= 10:
            return found
    return found


def extract_graphql_endpoints(text: str) -> List[str]:
    """Extract GraphQL endpoint references."""
    return _collect(
        text,
        r"['\"`]((?:https?://[^'\"`]+)?/?[A-Za-z0-9_\-/.?&={}]*graphql[A-Za-z0-9_\-/.?&={}]*|/[A-Za-z0-9_\-]*graphql[A-Za-z0-9_\-/?&=]*)['\"`]",
    )


def extract_websocket_urls(text: str) -> List[str]:
    """Extract WebSocket URLs and connection calls."""
    urls = _collect(text, r"(wss?://[A-Za-z0-9_.\-:~/?#\[\]@!$&'()*+,;=%]+)")
    calls = _collect(text, r"(?:new\s+WebSocket|websocket|socket\.io)\s*\(\s*['\"`]([^'\"`]+)['\"`]")
    return (urls + calls)[:MAX_MATCHES_PER_CATEGORY]


def extract_hidden_routes(text: str) -> List[str]:
    """Extract route definitions (express-style) and suspicious paths."""
    routes: List[str] = []
    for m in re.finditer(r"(?:app|router|route)\.(?:get|post|put|delete|use|all)\s*\(\s*['\"`]([^'\"`]{1,100})['\"`]", text, re.IGNORECASE):
        entry = f"{m.group(1)}"
        if entry not in routes:
            routes.append(entry)
        if len(routes) >= MAX_MATCHES_PER_CATEGORY:
            break
    return routes


def extract_client_authorization(text: str) -> List[str]:
    """Find client-side authorization logic (role checks, token gating)."""
    found: List[str] = []
    checks = [
        (r"if\s*\(\s*(isAdmin|is_admin|user\.role|role|permissions?)", "role condition"),
        (r"localStorage\.(getItem|setItem)\s*\(\s*['\"](token|jwt|auth)['\"]", "localStorage token"),
        (r"\.(admin|dashboard|protected)[A-Za-z0-9_]*\s*[=(]", "protected route guard"),
        (r"redirect\s*\(\s*['\"]/login['\"]", "client redirect on auth"),
    ]
    for pattern, label in checks:
        if re.search(pattern, text):
            found.append(label)
    return found[:6]


# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------

def analyze_javascript_text(text: str) -> str:
    """Analyze JavaScript source and return a capped findings report."""
    sections: List[str] = ["# JavaScript Analysis"]
    sections.append(f"Source size: {len(text)} chars, {text.count(chr(10)) + 1} lines")

    def add(label: str, items: List[str]) -> None:
        if items:
            sections.append(f"\n{label}:")
            sections.extend(f"- {i}" for i in items)
        else:
            sections.append(f"\n{label}: (none found)")

    add("Endpoints", extract_javascript_endpoints(text))
    add("API base URLs", extract_api_base_urls(text))
    add("Secrets/tokens", extract_javascript_secrets(text))
    add("Hardcoded credentials", extract_hardcoded_credentials(text))
    add("Source maps", extract_source_map_refs(text))
    add("fetch/XHR calls", extract_fetch_calls(text))
    add("GraphQL endpoints", extract_graphql_endpoints(text))
    add("WebSocket URLs", extract_websocket_urls(text))
    add("Hidden routes", extract_hidden_routes(text))
    add("Client-side authorization", extract_client_authorization(text))

    return _truncate("\n".join(sections))


def search_javascript_text(text: str, pattern: str, max_matches: int = 15) -> str:
    """Search JavaScript text for *pattern* with line context."""
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"Error: invalid regex pattern: {e}"
    lines = text.splitlines()
    matches: List[str] = []
    for idx, line in enumerate(lines, start=1):
        if regex.search(line):
            snippet = line.strip()[:160]
            matches.append(f"line {idx}: {snippet}")
            if len(matches) >= max_matches:
                matches.append(f"... (showing first {max_matches} matches)")
                break
    if not matches:
        return f"No matches for pattern {pattern!r} in the provided JavaScript."
    return f"Matches for {pattern!r}:\n" + "\n".join(matches)


# ---------------------------------------------------------------------------
# File / URL entry points (registered as tools)
# ---------------------------------------------------------------------------

def _resolve_workspace_file(path: str, workspace_root: Optional[str]) -> str:
    root = get_workspace_root(workspace_root)
    full = os.path.abspath(os.path.join(str(root), path))
    root_abs = os.path.abspath(str(root))
    if not (full == root_abs or full.startswith(root_abs + os.sep)):
        raise WorkspaceError(f"Path is outside the workspace: {path}")
    if not os.path.exists(full):
        raise WorkspaceError(f"File not found: {path}")
    return full


def analyze_javascript_file(
    path: str,
    workspace_root: Optional[str] = None,
) -> str:
    """Analyze a JavaScript file inside the workspace."""
    try:
        full = _resolve_workspace_file(path, workspace_root)
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error reading file: {e}"
    report = analyze_javascript_text(text)
    return f"File: {path}\n{report}"


def search_javascript_file(
    path: str,
    pattern: str,
    workspace_root: Optional[str] = None,
) -> str:
    """Search a JavaScript file inside the workspace for *pattern*."""
    try:
        full = _resolve_workspace_file(path, workspace_root)
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error reading file: {e}"
    result = search_javascript_text(text, pattern)
    return f"File: {path}\n{result}"


def analyze_javascript_url(
    url: str,
    max_chars: int = 200000,
) -> str:
    """Fetch a JavaScript file from an authorized target and analyze it.

    The request goes through the shared HTTP session, which applies the
    standard URL safety validation (localhost/private/metadata blocks).
    """
    try:
        from .http_tools import _fetch
    except ImportError as e:  # pragma: no cover - defensive
        return f"Error loading HTTP tools: {e}"

    result = _fetch(
        url,
        method="GET",
        follow_redirects=True,
        timeout=20,
    )
    if not isinstance(result, dict):
        return f"Failed to fetch {url}: {result}"
    status = result.get("status_code")
    if status is None or status >= 400:
        return (
            f"Failed to fetch {url}: status={status} "
            f"error={result.get('error') or 'unknown'}"
        )
    content_type = (result.get("content_type") or "").lower()
    body = result.get("body") or ""
    if "javascript" not in content_type and "text" not in content_type and not body.strip().startswith(("//", "/*", "var ", "const ", "function ", "let ")):
        return (
            f"Fetched {url} but content-type is {content_type or 'unknown'} - "
            f"not JavaScript. Body preview: {body[:200]}"
        )
    report = analyze_javascript_text(body)
    return f"URL: {url} (status {status}, {len(body)} chars)\n{report}"
