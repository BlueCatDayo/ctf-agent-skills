"""Stage 7 optional pwntools integration (spec 9).

Provides a single-session manager for interacting with a challenge:

- launching a local process (inside the configured challenge workspace)
- connecting to a user-provided CTF host and port
- sending lines / receiving output / waiting for prompts
- process timeout handling and clean session termination

pwntools is optional: when it is not installed, the tools return a
friendly error with the install command.  Remote connections are only
allowed for the user-provided authorized host/port; loopback, metadata,
and (by default) private addresses follow the same policy as the HTTP
tools via ``init_pwn_session_from_config``.
"""

from __future__ import annotations

import ipaddress
import shutil
import time
from typing import Any, List, Optional, Tuple

from .workspace import WorkspaceError, get_workspace_root

# Metadata / loopback / private address policy (mirrors http_security.py).
METADATA_BLOCKED = {
    "169.254.169.254", "metadata.google.internal", "metadata",
    "instance-data", "instance-data.ec2.internal",
}
ALWAYS_BLOCKED_NETS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),
]
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]
LOOPBACK_NETS = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]

# Module-level flags set from config (defaults: strict).
_ALLOW_LOCALHOST = False
_ALLOW_PRIVATE = False
_PWN_ENABLED = True

DEFAULT_TIMEOUT = 10
MAX_OUTPUT_CHARS = 4000


def init_pwn_session_from_config(config: Any) -> None:
    """Apply config policy to the pwn session manager."""
    global _ALLOW_LOCALHOST, _ALLOW_PRIVATE, _PWN_ENABLED
    _ALLOW_LOCALHOST = bool(getattr(config, "allow_localhost_targets", False))
    _ALLOW_PRIVATE = bool(getattr(config, "allow_private_targets", False))
    _PWN_ENABLED = bool(getattr(config, "enable_pwntools", False))


def pwntools_available() -> bool:
    """True when pwntools is importable."""
    try:
        import pwn  # noqa: F401
        return True
    except Exception:
        return False


def pwntools_status() -> str:
    if pwntools_available():
        return "pwntools is available (optional integration enabled)."
    return (
        "pwntools is not installed. Install with: pip install pwntools. "
        "Pure-Python helpers (pwn_cyclic, pwn_pack, pwn_crash_analyze) work "
        "without it."
    )


def _validate_remote(host: str, port: int) -> Optional[str]:
    """Validate a remote host/port.  Returns an error string or None."""
    if not host or not isinstance(host, str):
        return "host must be a non-empty string."
    host = host.strip()
    if not 0 < int(port) <= 65535:
        return f"Invalid port: {port}"
    low = host.lower()
    if low in METADATA_BLOCKED:
        return f"Host '{host}' is a known metadata endpoint and is blocked."
    if low == "localhost" or low.endswith(".localhost"):
        if not _ALLOW_LOCALHOST:
            return "Connections to localhost are blocked (set ALLOW_LOCALHOST_TARGETS=true to enable)."
        return None
    try:
        ip = ipaddress.ip_address(low)
    except ValueError:
        return None  # hostname: allowed (user-provided target)
    for net in ALWAYS_BLOCKED_NETS:
        if ip in net:
            return f"Address {host} is link-local/metadata and is blocked."
    if not _ALLOW_LOCALHOST:
        for net in LOOPBACK_NETS:
            if ip in net:
                return "Loopback connections are blocked (set ALLOW_LOCALHOST_TARGETS=true to enable)."
    if not _ALLOW_PRIVATE:
        for net in PRIVATE_NETS:
            if ip in net:
                return (
                    f"Address {host} is private and blocked "
                    "(set ALLOW_PRIVATE_TARGETS=true to enable)."
                )
    return None


class PwnSessionManager:
    """A single active pwntools session (process or remote socket)."""

    def __init__(self):
        self._target = None  # type: Optional[Any]
        self._kind = ""      # "local" | "remote"

    def is_active(self) -> bool:
        return self._target is not None

    def _require_pwntools(self) -> Optional[str]:
        if not _PWN_ENABLED:
            return "pwntools integration is disabled (set ENABLE_PWNTOOLS=true)."
        if not pwntools_available():
            return "pwntools is not installed. Run: pip install pwntools"
        return None

    def start_local(self, command: str, workspace_root: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT) -> str:
        """Launch a local challenge process inside the workspace."""
        err = self._require_pwntools()
        if err:
            return f"Error: {err}"
        if not command.strip():
            return "Error: command must name a binary inside the workspace."

        try:
            root = get_workspace_root(workspace_root)
        except Exception as e:
            return f"Workspace error: {e}"

        parts = command.strip().split()
        target = parts[0]
        args = parts[1:]

        full = target if os_path_abspath(target).startswith(os_path_abspath(str(root))) else None
        if full is None:
            candidate = os_path_join(str(root), target)
            if not os_path_abspath(candidate).startswith(os_path_abspath(str(root)) + os_sep):
                return f"Workspace error: command outside the workspace: {target}"
            full = candidate
        if not os_path_exists(full):
            return f"Workspace error: file not found: {full}"

        from pwn import process  # type: ignore
        try:
            self.close()
            self._target = process([full] + args, timeout=timeout)
            self._kind = "local"
            return f"Started local process: {full} (pid {self._target.pid})"
        except Exception as e:
            self._target = None
            return f"Error launching process: {e}"

    def connect_remote(self, host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> str:
        """Connect to a user-provided authorized CTF host and port."""
        err = self._require_pwntools()
        if err:
            return f"Error: {err}"
        validation = _validate_remote(host, port)
        if validation:
            return f"Error: {validation}"

        from pwn import remote  # type: ignore
        try:
            self.close()
            self._target = remote(host, int(port), timeout=timeout)
            self._kind = "remote"
            return f"Connected to {host}:{port}"
        except Exception as e:
            self._target = None
            return f"Error connecting to {host}:{port}: {e}"

    def send(self, data: str, newline: bool = True) -> str:
        """Send a line to the active session."""
        if not self.is_active():
            return "Error: no active session. Start one with pwn_session_start."
        try:
            if newline:
                self._target.sendline(data)
            else:
                self._target.send(data)
            return f"Sent: {data!r}"
        except Exception as e:
            return f"Error sending: {e}"

    def recv(self, timeout: float = 2.0) -> str:
        """Receive available output from the active session."""
        if not self.is_active():
            return "Error: no active session."
        try:
            self._target.timeout = timeout
            try:
                data = self._target.recvrepeat(timeout)
            except AttributeError:  # pragma: no cover - older pwntools
                data = self._target.recv(timeout=timeout)
            return _truncate_text(data)
        except EOFError:
            return "(session closed by remote)"
        except Exception as e:
            return f"Error receiving: {e}"

    def wait_prompt(self, prompt: str, timeout: float = 10.0) -> str:
        """Wait for *prompt* then return output up to that point."""
        if not self.is_active():
            return "Error: no active session."
        try:
            self._target.timeout = timeout
            data = self._target.recvuntil(prompt.encode("utf-8", errors="replace"), timeout=timeout)
            return _truncate_text(data)
        except EOFError:
            return "(session closed by remote)"
        except Exception as e:
            return f"Error waiting for prompt: {e}"

    def close(self) -> str:
        """Terminate the session cleanly."""
        if not self.is_active():
            return "No active session to close."
        try:
            self._target.close()
            self._target = None
            self._kind = ""
            return "Session closed."
        except Exception as e:
            self._target = None
            return f"Session closed (with error: {e})"

    def status(self) -> str:
        if self.is_active():
            return f"Active {self._kind} session."
        return "No active session."


def _truncate_text(data: Any) -> str:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
    text = text.strip()
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS] + f"\n... [output truncated at {MAX_OUTPUT_CHARS} characters]"
    return text


# os helpers kept local so the module imports on any platform
import os as _os

os_path_abspath = _os.path.abspath
os_path_join = _os.path.join
os_path_exists = _os.path.exists
os_sep = _os.sep


session_manager = PwnSessionManager()
