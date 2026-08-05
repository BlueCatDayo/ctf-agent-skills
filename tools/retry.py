"""Stage 6 retry logic - transparent retries for transient tool failures.

Transient failures are timeouts and temporary network/server errors (not
permanent validation or security errors).  Retrying these is safe and
improves reliability of autonomous investigation loops.
"""

import re
import time
from typing import Any, Callable, Optional

# Patterns that indicate a *transient* failure worth retrying.
TRANSIENT_ERROR_PATTERNS = [
    r"timed?\s?out",
    r"timeout",
    r"connection\s+(refused|reset|error|aborted|closed)",
    r"econnrefused",
    r"econnreset",
    r"temporar",
    r"network\s+(error|unreachable|issue)",
    r"remote\s+(server|host)\s+(error|unavailable|refused)",
    r"server\s+(error|unavailable|overloaded|busy)",
    r"service\s+unavailable",
    r"bad\s+gateway",
    r"\b503\b",
    r"\b502\b",
    r"\b504\b",
    r"too\s+many\s+redirects",
    r"redirect\s+loop",
    r"retry",
    r"temporary\s+failure",
    r"read\s+timed",
    r"reset\s+by\s+peer",
    r"broken\s+pipe",
    r"ssl\s+error",
    r"name\s+or\s+service\s+not\s+known",
    r"temporarily\s+unavailable",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in TRANSIENT_ERROR_PATTERNS]


def is_transient_failure(result: Any) -> bool:
    """Return True when a tool result represents a transient failure.

    A result is transient when its ``timed_out`` flag is set or its error
    text matches a known temporary-failure pattern (timeouts, connection
    resets, 5xx server errors, redirect loops, ...).
    """
    if result is None:
        return False
    if getattr(result, "timed_out", False):
        return True
    error = getattr(result, "error", None) or ""
    output = getattr(result, "output", None) or ""
    combined = f"{error}\n{output}"
    for pattern in _COMPILED:
        if pattern.search(combined):
            return True
    return False


def execute_with_retry(
    registry: Any,
    name: str,
    arguments: dict,
    workspace_root: Any = None,
    max_retries: int = 2,
    delay: float = 0.5,
    logger: Optional[Callable[[str], None]] = None,
) -> Any:
    """Execute a tool with retries for transient failures.

    The tool is executed at least once.  When the result is a transient
    failure (timeout/network error) and retries remain, the tool is
    re-executed after *delay* seconds.  Non-transient failures and
    successes are returned immediately.

    Parameters
    ----------
    registry:
        The tool registry with an ``execute`` method.
    name:
        Tool name.
    arguments:
        Tool arguments dict.
    workspace_root:
        Workspace root passed through to the registry.
    max_retries:
        Maximum number of retries after the first attempt.
    delay:
        Seconds to wait between retries (0 disables sleeping).
    logger:
        Optional callable for logging retry attempts.

    Returns
    -------
    ToolResult
        The final result (possibly after retries).
    """
    attempt = 0
    while True:
        result = registry.execute(name, arguments, workspace_root=workspace_root)
        if result is None:
            return result
        if result.success or not is_transient_failure(result):
            return result
        if attempt >= max_retries:
            if logger:
                logger(
                    f"[RETRY] {name} still failing after {attempt} retries - giving up."
                )
            return result
        attempt += 1
        if logger:
            logger(f"[RETRY] {name} transient failure (attempt {attempt}/{max_retries}) - retrying.")
        if delay and delay > 0:
            time.sleep(delay)
