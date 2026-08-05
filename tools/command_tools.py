"""Restricted command execution tool for CTF analysis."""

import shutil
import subprocess
import re
from typing import Optional

from .workspace import PathTraversalError, WorkspaceError, get_workspace_root, validate_within_workspace

MAX_TOOL_OUTPUT_CHARS = 4096
TOOL_TIMEOUT_SECONDS = 30

# Approved commands for local CTF challenge analysis
ALLOWED_COMMANDS = {
    "file",
    "strings",
    "xxd",
    "hexdump",
    "readelf",
    "objdump",
    "nm",
    "ldd",
    "grep",
    "rg",
    "python",
    "python3",
}

# Shell operators and redirections that must be blocked when they appear
# outside of quoted arguments
BLOCKED_OPERATORS = re.compile(r"(&&|\|\||\||;|>|<|>>|<<)")

# Command substitution / metacharacters that are dangerous even inside quotes
RAW_BLOCKED_META = re.compile(r"(\$\(|`|\n|\r)")

# Blocked argument patterns
BLOCKED_ARG_PATTERNS = [
    re.compile(r"-exec\b"),
    re.compile(r"-delete\b"),
    re.compile(r"--exec\b"),
]

# System paths that must not be accessed
BLOCKED_SYSTEM_PATHS = ["/etc", "/proc", "/sys", "/boot", "/dev", "/root"]


def _strip_quoted_sections(command: str) -> str:
    """Replace quoted sections with empty quotes.

    This lets the unquoted-operator check ignore operators that appear
    inside quoted arguments (e.g. ``;`` inside ``python -c "a;b"``).
    """
    result = re.sub(r'"[^"]*"', '""', command)
    result = re.sub(r"'[^']*'", "''", result)
    return result


def _find_command_path(cmd: str, workspace_root: str) -> Optional[str]:
    """Find the full path of an allowed command, or None if not found."""
    # Check if the command is in the allowlist
    if cmd not in ALLOWED_COMMANDS:
        return None

    # Use shutil.which to find the executable
    full_path = shutil.which(cmd)
    return full_path


def _validate_dangerous_args(args: list[str]) -> Optional[str]:
    """Validate command arguments for dangerous content.

    Checks for path traversal, system path access, and destructive flags.
    Returns an error message if validation fails, or None if valid.
    """
    for arg in args:
        # Block path traversal
        if ".." in arg:
            return f"Blocked argument (path traversal): {arg}"

        # Block absolute paths to system directories
        for blocked_path in BLOCKED_SYSTEM_PATHS:
            if arg.startswith(blocked_path):
                return f"Blocked argument (system path access): {arg}"

        # Block dangerous flag patterns
        for pattern in BLOCKED_ARG_PATTERNS:
            if pattern.search(arg):
                return f"Blocked dangerous argument: {arg}"

        # Block access to environment files
        if arg.startswith(".env") or arg.startswith("~/"):
            return f"Blocked argument (environment/system file access): {arg}"

    return None


def run_ctf_command(
    command: str,
    workspace_root: Optional[str] = None,
    timeout_seconds: int = TOOL_TIMEOUT_SECONDS,
    max_output_chars: int = MAX_TOOL_OUTPUT_CHARS,
) -> str:
    """Run an approved local analysis command inside the workspace.

    Parameters
    ----------
    command:
        The command string to execute (e.g. ``strings challenges/test/sample.bin``).
    workspace_root:
        Override the default workspace root directory.
    timeout_seconds:
        Maximum execution time in seconds.
    max_output_chars:
        Maximum output size for stdout and stderr.

    Returns
    -------
    str
        Structured result with exit code, stdout, stderr, and timeout status.
    """
    try:
        root = get_workspace_root(workspace_root)

        # Strip the command string
        command = command.strip()
        if not command:
            return "Error: No command provided."

        # Check for raw command-substitution metacharacters that are
        # dangerous even inside quoted arguments
        if RAW_BLOCKED_META.search(command):
            return (
                "Error: Shell operators are not allowed. "
                "Commands must be simple, without pipes, redirects, "
                "chaining (&&, ||, ;), or command substitution."
            )

        # Check for unquoted shell operators (pipes, redirects, chaining)
        unquoted = _strip_quoted_sections(command)
        if BLOCKED_OPERATORS.search(unquoted):
            return (
                "Error: Shell operators are not allowed. "
                "Commands must be simple, without pipes, redirects, "
                "chaining (&&, ||, ;), or command substitution."
            )

        # Split into arguments using shlex for proper quoting
        import shlex
        try:
            parts = shlex.split(command)
        except ValueError as e:
            return f"Error: Invalid command syntax - {e}"

        if not parts:
            return "Error: No command provided."

        cmd_name = parts[0]
        cmd_args = parts[1:]

        # Check dangerous arguments before allowlist (security check)
        dangerous = _validate_dangerous_args(cmd_args)
        if dangerous:
            return f"Security error: {dangerous}"

        # Validate command is on the allowlist
        if cmd_name not in ALLOWED_COMMANDS:
            return (
                f"Error: Command '{cmd_name}' is not on the approved allowlist. "
                f"Allowed commands: {', '.join(sorted(ALLOWED_COMMANDS))}. "
                f"Use /tools to see which are available on this system."
            )

        # Find the executable
        cmd_path = _find_command_path(cmd_name, str(root))
        if cmd_path is None:
            return (
                f"Error: Command '{cmd_name}' is not available on this system. "
                f"Install it or choose a different analysis command."
            )

        # Validate arguments (second pass for allowlist-specific checks)
        arg_error = _validate_dangerous_args(cmd_args)
        if arg_error:
            return f"Security error: {arg_error}"

        # Ensure arguments don't escape the workspace
        for arg in cmd_args:
            if arg.startswith("/") or (len(arg) > 1 and arg[1:].startswith(":")):
                # Absolute path — check it's within workspace
                try:
                    validate_within_workspace(arg, root)
                except (PathTraversalError, WorkspaceError) as e:
                    return f"Security error: {e}"

        # Build the command list: executable + arguments
        cmd_list = [cmd_path] + cmd_args

        # Execute without shell=True
        try:
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=str(root),
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return (
                f"Command '{cmd_name}' timed out after {timeout_seconds}s.\n"
                f"Exit code: -1\nStdout: (partial)\nStderr: (none)"
            )
        except FileNotFoundError:
            return (
                f"Error: Command '{cmd_name}' not found on this system. "
                f"It may not be installed or may not be in PATH."
            )

        # Truncate output
        stdout = _truncate(result.stdout, max_output_chars)
        stderr = _truncate(result.stderr, max_output_chars)

        # Build result
        lines = [
            f"Command: {cmd_name}",
            f"Exit code: {result.returncode}",
        ]

        if stdout.strip():
            lines.append(f"Stdout:\n{stdout}")
        if stderr.strip():
            lines.append(f"Stderr:\n{stderr}")
        if not stdout.strip() and not stderr.strip():
            lines.append("No output produced.")

        return "\n".join(lines)

    except PathTraversalError as e:
        return f"Security error: {e}"
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except Exception as e:
        return f"Error executing command: {e}"


def _truncate(text: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Truncate text to *limit* characters."""
    if len(text) > limit:
        return text[:limit] + f"\n... [output truncated at {limit} characters]"
    return text
