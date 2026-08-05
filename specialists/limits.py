"""Stage 7 resource and loop limits (spec 16).

Prevents slow or endless runs by capping:

- maximum specialist calls per challenge
- maximum HTTP requests
- maximum retries (mirrors Stage 6 config)
- maximum command executions
- maximum output size (mirrors Stage 6 config)
- per-tool timeout (mirrors Stage 6 config)
- global challenge timeout
- duplicate-action detection

When a limit is reached, callers should stop issuing new actions and
return the strongest confirmed evidence plus the next recommended action.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

# Tools that perform HTTP traffic.
HTTP_TOOLS = {
    "http_request", "http_get", "http_post", "http_put", "http_delete",
    "inspect_webpage", "compare_http_responses", "manage_cookies",
    "analyze_headers", "read_robots_txt", "read_sitemap_xml",
    "extract_links_from_page", "extract_forms_from_page",
    "extract_javascript_from_page", "extract_html_comments",
    "extract_web_elements", "enumerate_directories",
    "discover_api_endpoints", "discover_hidden_endpoints",
    "find_login_page", "find_admin_page", "find_api_endpoints",
    "find_backup_files", "detect_framework", "detect_server",
    "detect_technology_stack", "extract_emails", "extract_version_info",
    "analyze_javascript_url",
}

# Tools that execute local commands.
COMMAND_TOOLS = {
    "run_ctf_command",
    "pwn_crash_analyze", "pwn_verify_offset", "pwn_session_start",
    "pwn_elf_info", "pwn_find_win_function", "pwn_got_plt",
    "pwn_find_gadgets", "pwn_analyze_ret2win", "pwn_format_string_analysis",
    "analyze_javascript_file",
}

# Tools that only inspect the workspace (cheap, not counted as commands).
FILE_TOOLS = {
    "list_files", "read_text_file", "inspect_file", "search_files",
    "calculate_file_hash",
}


class ResourceLimits:
    """Tracks resource usage per challenge and blocks actions over limits."""

    def __init__(
        self,
        max_specialist_calls: int = 12,
        max_http_requests: int = 40,
        max_command_executions: int = 30,
        max_retries: int = 2,
        max_output_chars: int = 4096,
        per_tool_timeout: int = 30,
        global_timeout_seconds: int = 1800,
        max_duplicate_actions: int = 3,
        duplicate_window: int = 90,
    ):
        self.max_specialist_calls = max_specialist_calls
        self.max_http_requests = max_http_requests
        self.max_command_executions = max_command_executions
        self.max_retries = max_retries
        self.max_output_chars = max_output_chars
        self.per_tool_timeout = per_tool_timeout
        self.global_timeout_seconds = global_timeout_seconds
        self.max_duplicate_actions = max_duplicate_actions
        self.duplicate_window = duplicate_window

        self._started_at: Optional[float] = None
        self._http_count = 0
        self._command_count = 0
        self._specialist_calls = 0
        self._retry_count = 0
        self._tool_times: Dict[str, int] = {}
        self._duplicates: Dict[str, List[float]] = {}
        self._blocked: List[str] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_challenge(self) -> None:
        """Begin a new challenge session (resets per-challenge counters)."""
        self._started_at = time.time()
        self._http_count = 0
        self._command_count = 0
        self._specialist_calls = 0
        self._retry_count = 0
        self._tool_times = {}
        self._duplicates = {}
        self._blocked = []

    def reset(self) -> None:
        """Reset all counters (used by /reset)."""
        self.start_challenge()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_action(self, tool: str, arguments: Optional[Dict[str, Any]] = None) -> None:
        """Record that *tool* was executed (or attempted)."""
        if self._started_at is None:
            self.start_challenge()
        if tool in HTTP_TOOLS:
            self._http_count += 1
        elif tool in COMMAND_TOOLS:
            self._command_count += 1
        self._tool_times[tool] = self._tool_times.get(tool, 0) + 1

        key = self._duplicate_key(tool, arguments)
        now = time.time()
        stamps = [t for t in self._duplicates.get(key, []) if now - t <= self.duplicate_window]
        stamps.append(now)
        self._duplicates[key] = stamps

    def record_specialist_call(self) -> None:
        """Record one explicit specialist execution."""
        self._specialist_calls += 1

    def record_retry(self) -> None:
        """Record one transient-failure retry."""
        self._retry_count += 1

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _duplicate_key(self, tool: str, arguments: Optional[Dict[str, Any]]) -> str:
        if not arguments:
            return tool
        try:
            args = json.dumps(arguments, sort_keys=True, default=str)
        except Exception:
            args = str(arguments)
        return f"{tool}:{args}"

    def check_tool(self, tool: str, arguments: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Return ``(allowed, reason)`` for executing *tool*.

        Blocks actions that exceed a limit or that repeat the same exact
        action too many times within the duplicate window.
        """
        if self._started_at is None:
            return True, "ok"

        # Global challenge timeout
        if self.global_timeout_seconds > 0:
            elapsed = time.time() - self._started_at
            if elapsed > self.global_timeout_seconds:
                return False, (
                    f"Global challenge timeout reached "
                    f"({self.global_timeout_seconds}s). "
                    "Return the strongest confirmed evidence."
                )

        # HTTP request cap
        if tool in HTTP_TOOLS and self._http_count >= self.max_http_requests:
            return False, (
                f"Maximum HTTP requests reached ({self.max_http_requests}). "
                "Stop requesting and analyze existing evidence."
            )

        # Command execution cap
        if tool in COMMAND_TOOLS and self._command_count >= self.max_command_executions:
            return False, (
                f"Maximum command executions reached ({self.max_command_executions}). "
                "Stop executing commands and analyze existing evidence."
            )

        # Duplicate-action detection
        key = self._duplicate_key(tool, arguments)
        now = time.time()
        recent = [t for t in self._duplicates.get(key, []) if now - t <= self.duplicate_window]
        if len(recent) >= self.max_duplicate_actions:
            return False, (
                f"Duplicate action detected: '{key}' executed {len(recent)} times "
                f"in the last {self.duplicate_window}s. Try a different action."
            )

        return True, "ok"

    def check_specialist(self) -> Tuple[bool, str]:
        """Check whether another specialist execution is allowed."""
        if self._specialist_calls >= self.max_specialist_calls:
            return False, (
                f"Maximum specialist calls reached ({self.max_specialist_calls}). "
                "Reuse existing specialist results."
            )
        return True, "ok"

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def limits_reached(self) -> bool:
        """True when any hard limit has been reached."""
        if self.global_timeout_seconds > 0 and self._started_at is not None:
            if time.time() - self._started_at > self.global_timeout_seconds:
                return True
        return (
            self._http_count >= self.max_http_requests
            or self._command_count >= self.max_command_executions
            or self._specialist_calls >= self.max_specialist_calls
        )

    def usage(self) -> Dict[str, Any]:
        """Return a snapshot of current usage counters."""
        elapsed = 0.0
        if self._started_at is not None:
            elapsed = round(time.time() - self._started_at, 1)
        return {
            "http_requests": self._http_count,
            "command_executions": self._command_count,
            "specialist_calls": self._specialist_calls,
            "retries": self._retry_count,
            "elapsed_seconds": elapsed,
            "limits": {
                "max_http_requests": self.max_http_requests,
                "max_command_executions": self.max_command_executions,
                "max_specialist_calls": self.max_specialist_calls,
                "max_retries": self.max_retries,
                "max_output_chars": self.max_output_chars,
                "per_tool_timeout": self.per_tool_timeout,
                "global_timeout_seconds": self.global_timeout_seconds,
                "max_duplicate_actions": self.max_duplicate_actions,
            },
        }

    def summary(self) -> str:
        """One-line human summary of resource usage."""
        u = self.usage()
        return (
            f"Limits: {u['http_requests']}/{u['limits']['max_http_requests']} HTTP, "
            f"{u['command_executions']}/{u['limits']['max_command_executions']} commands, "
            f"{u['specialist_calls']}/{u['limits']['max_specialist_calls']} specialists, "
            f"{u['retries']} retries, {u['elapsed_seconds']}s elapsed"
        )
