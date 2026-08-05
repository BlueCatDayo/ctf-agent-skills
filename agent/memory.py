"""Stage 6 session memory - lightweight evidence store for a single session.

Remembers discovered URLs, cookies (names only - values are never stored),
endpoints, technologies, decoded values, files analyzed, flags, and notes.
Values are deduplicated and the store is capped to bound memory growth.
"""

import re
import threading
from typing import Any, Dict, List, Optional

# Categories understood by the memory store (order used in summaries).
CATEGORIES = [
    "urls",
    "endpoints",
    "cookies",
    "technologies",
    "decoded",
    "files",
    "flags",
    "notes",
]

# Known technology markers for lightweight extraction from tool output.
TECHNOLOGY_MARKERS = [
    "nginx", "apache", "iis", "express", "django", "flask", "laravel",
    "wordpress", "drupal", "joomla", "asp.net", "ruby on rails", "spring",
    "symfony", "bootstrap", "jquery", "react", "vue", "angular", "tomcat",
    "next.js", "httpx", "htmx", "alpine.js", "tailwind css", "node.js",
    "gunicorn", "uvicorn", "caddy", "openresty",
]

FLAG_PATTERN = re.compile(r"flag\{[^}\n]{1,200}\}", re.IGNORECASE)


class SessionMemory:
    """Thread-safe, deduplicated, size-capped session memory."""

    def __init__(self, max_entries: int = 200):
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._data: Dict[str, List[str]] = {c: [] for c in CATEGORIES}

    # ------------------------------------------------------------------
    # Core add/get
    # ------------------------------------------------------------------

    def add(self, category: str, value: str) -> bool:
        """Add a value to a category. Returns True when newly added.

        Values are deduplicated (case-insensitive for most categories) and
        the store is capped at ``max_entries`` total items.
        """
        if not value or not str(value).strip():
            return False
        value = str(value).strip()
        if category not in self._data:
            self._data[category] = []
        with self._lock:
            existing = self._data[category]
            key = value.lower()
            for item in existing:
                if item.lower() == key:
                    return False
            existing.append(value)
            self._trim_locked()
        return True

    def _trim_locked(self) -> None:
        """Trim the store to the configured cap (oldest items first)."""
        total = sum(len(v) for v in self._data.values())
        if total <= self._max_entries:
            return
        overflow = total - self._max_entries
        for category in CATEGORIES:
            if overflow <= 0:
                break
            bucket = self._data[category]
            if len(bucket) > overflow:
                del bucket[:overflow]
                overflow = 0
            else:
                overflow -= len(bucket)
                bucket.clear()

    def get(self, category: str) -> List[str]:
        """Return a copy of the values stored under a category."""
        with self._lock:
            return list(self._data.get(category, []))

    def all(self) -> Dict[str, List[str]]:
        """Return a copy of the entire memory store."""
        with self._lock:
            return {c: list(v) for c, v in self._data.items()}

    def clear(self) -> None:
        """Clear all stored values."""
        with self._lock:
            for c in self._data:
                self._data[c].clear()

    def counts(self) -> Dict[str, int]:
        """Return per-category item counts."""
        with self._lock:
            return {c: len(self._data.get(c, [])) for c in CATEGORIES}

    def total(self) -> int:
        """Return the total number of stored items."""
        with self._lock:
            return sum(len(v) for v in self._data.values())

    # ------------------------------------------------------------------
    # Convenience adders
    # ------------------------------------------------------------------

    def add_url(self, value: str) -> bool:
        return self.add("urls", value)

    def add_endpoint(self, value: str) -> bool:
        return self.add("endpoints", value)

    def add_cookie(self, name: str) -> bool:
        """Store a cookie *name* only - values are never persisted."""
        return self.add("cookies", name)

    def add_technology(self, value: str) -> bool:
        return self.add("technologies", value)

    def add_decoded(self, encoding: str, decoded: str) -> bool:
        label = f"{encoding} -> {decoded[:80]}"
        return self.add("decoded", label)

    def add_file(self, path: str) -> bool:
        return self.add("files", path)

    def add_flag(self, flag: str) -> bool:
        return self.add("flags", flag)

    def add_note(self, text: str) -> bool:
        return self.add("notes", text)

    # ------------------------------------------------------------------
    # Extraction from tool output
    # ------------------------------------------------------------------

    def remember_tool_result(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]],
        output: str,
    ) -> None:
        """Extract lightweight facts from a tool result into memory.

        Extraction is conservative and regex-based:
        - URLs are collected from any output.
        - Endpoints/paths are collected from discovery tool output.
        - Cookie *names* are collected from session/cookie tools.
        - Technologies are collected from inspection/detection tools.
        - Decoded values are collected from decode_data output.
        - Files are collected from file/binary tool arguments.
        - flag{...} patterns are collected from any successful output.
        """
        text = output or ""
        args = arguments or {}

        # Files analyzed (from arguments of file/binary tools).
        if tool_name in (
            "list_files", "read_text_file", "inspect_file", "search_files",
            "calculate_file_hash", "binary_file_info", "binary_strings",
            "binary_readelf", "binary_objdump", "binary_symbols",
            "binary_libraries", "binary_hexdump", "binary_checksec",
            "analyze_binary",
        ):
            for key in ("path", "filename", "file"):
                if args.get(key):
                    self.add_file(str(args[key]))
                    break

        # URLs found anywhere in output.
        for url in re.findall(r"https?://[^\s\"'<>()\[\]]+", text):
            self.add_url(url.rstrip(".,;"))

        # Endpoints / paths from discovery output (lines beginning with a path).
        if tool_name in (
            "enumerate_directories", "discover_api_endpoints",
            "discover_hidden_endpoints", "find_api_endpoints",
            "find_login_page", "find_admin_page", "find_backup_files",
            "read_robots_txt", "read_sitemap_xml", "extract_links_from_page",
        ):
            for line in text.splitlines():
                stripped = line.strip()
                # Lines like "/admin -> status 200" or "/api (200 bytes)"
                m = re.match(r"^(/?[A-Za-z0-9_\-./]+)(?:\s+->|\s+\(|\s+\d)", stripped)
                if m:
                    path = m.group(1).rstrip("/")
                    if path and not path.startswith("http"):
                        self.add_endpoint(path)
                    continue
                m = re.match(r"^/?/?([A-Za-z0-9_\-./]+)$", stripped)
                if m and ("/" in stripped or "." in stripped) and not stripped.startswith("http"):
                    self.add_endpoint(m.group(1))

        # Cookie names from session management tools.
        if tool_name in (
            "manage_http_session", "manage_cookies", "analyze_headers",
            "http_request", "http_get", "http_post", "http_put", "http_delete",
        ):
            for line in text.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*[^*]", line)
                if m:
                    self.add_cookie(m.group(1))

        # Technologies from inspection/detection tools.
        if tool_name in (
            "inspect_webpage", "analyze_headers", "detect_framework",
            "detect_server", "detect_technology_stack", "extract_version_info",
        ):
            lower = text.lower()
            for tech in TECHNOLOGY_MARKERS:
                if tech in lower:
                    self.add_technology(tech)

        # Decoded values.
        if tool_name == "decode_data":
            encoding = str(args.get("encoding", "auto"))
            excerpt = " ".join(text.split())[:100]
            if excerpt and not excerpt.lower().startswith("error"):
                self.add_decoded(encoding, excerpt)

        # Flags found in successful output.
        for flag in FLAG_PATTERN.findall(text):
            self.add_flag(flag)

    # ------------------------------------------------------------------
    # Prompt rendering
    # ------------------------------------------------------------------

    def to_prompt(self, max_chars: int = 2000) -> str:
        """Render the memory as a compact prompt section."""
        with self._lock:
            data = {c: list(v) for c, v in self._data.items()}
        display = {
            "urls": "URLs",
            "endpoints": "Endpoints",
            "cookies": "Cookies",
            "technologies": "Technologies",
            "decoded": "Decoded",
            "files": "Files",
            "flags": "Flags",
            "notes": "Notes",
        }
        lines = ["## Session Memory"]
        rendered = False
        for category in CATEGORIES:
            items = data.get(category, [])
            if not items:
                continue
            label = display.get(category, category.capitalize())
            shown = ", ".join(items[:8])
            if len(items) > 8:
                shown += f" (+{len(items) - 8} more)"
            lines.append(f"{label} ({len(items)}): {shown}")
            rendered = True
        if not rendered:
            lines.append("(no discoveries recorded yet)")
        text = "\n".join(lines)
        if len(text) > max_chars:
            return text[:max_chars] + "\n... [memory truncated]"
        return text

    def summary(self) -> str:
        """Return a one-line summary of the memory contents."""
        counts = self.counts()
        parts = [f"{c}={n}" for c, n in counts.items() if n]
        return "Session memory: " + (", ".join(parts) if parts else "empty")
