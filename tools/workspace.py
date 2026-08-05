"""Workspace path security — restricts all file operations to the authorized CTF workspace."""

import os
from pathlib import Path
from typing import Optional


class WorkspaceError(Exception):
    """Base exception for workspace security violations."""
    pass


class PathTraversalError(WorkspaceError):
    """Raised when a path attempts to escape the authorized workspace."""
    pass


class WorkspaceNotConfiguredError(WorkspaceError):
    """Raised when the workspace directory is not configured or does not exist."""
    pass


# Directories and patterns that must never be accessed outside the workspace
BLOCKED_SYSTEM_PATHS = [
    Path("/etc"),
    Path("/proc"),
    Path("/sys"),
    Path("/boot"),
    Path("/dev"),
    Path("/root"),
    Path("/var/log"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/tmp"),
]

# Hidden file prefixes to ignore during listing
HIDDEN_PREFIXES = (".",)

# Directories to skip during recursive listing
SKIP_DIRS = {".git", ".venv", "__pycache__"}


def get_workspace_root(config_workspace: Optional[str] = None) -> Path:
    """Return the absolute workspace root path.

    Uses the configured CTF_WORKSPACE value, falling back to the
    project-local ``challenges/`` directory.
    """
    if config_workspace:
        root = Path(config_workspace).resolve()
    else:
        project_root = Path(__file__).resolve().parent.parent
        root = (project_root / "challenges").resolve()

    if not root.exists():
        raise WorkspaceNotConfiguredError(
            f"Workspace directory does not exist: {root}"
        )
    if not root.is_dir():
        raise WorkspaceNotConfiguredError(
            f"Workspace path is not a directory: {root}"
        )
    return root


def validate_within_workspace(user_path: str, workspace_root: Path) -> Path:
    """Resolve *user_path* relative to *workspace_root* and ensure it stays inside.

    Raises :exc:`PathTraversalError` if the resolved path escapes the workspace.
    Raises :exc:`WorkspaceError` for other invalid paths.
    """
    if not user_path:
        raise WorkspaceError("Path cannot be empty.")

    # Reject obvious traversal attempts in the raw input
    if ".." in user_path.split("/") or ".." in user_path.split("\\"):
        raise PathTraversalError(
            f"Path traversal ('..') is not allowed: {user_path}"
        )

    # Reject absolute paths that point outside the workspace
    candidate = Path(user_path)
    if candidate.is_absolute():
        # Allow absolute paths only if they are inside the workspace
        try:
            candidate.resolve().relative_to(workspace_root)
        except ValueError:
            raise PathTraversalError(
                f"Absolute path is outside the authorized workspace: {user_path}"
            )
        return candidate.resolve()

    # Resolve relative to workspace root
    resolved = (workspace_root / user_path).resolve()

    # Ensure the resolved path is inside the workspace
    try:
        resolved.relative_to(workspace_root)
    except ValueError:
        raise PathTraversalError(
            f"Path escapes the authorized workspace: {user_path}"
        )

    return resolved


def is_path_blocked(path: Path) -> Optional[str]:
    """Check if a path points to a blocked system location.

    Returns a reason string if blocked, or ``None`` if the path is allowed.
    """
    resolved = path.resolve()
    for blocked in BLOCKED_SYSTEM_PATHS:
        try:
            resolved.relative_to(blocked.resolve())
            return f"Access to system directory is blocked: {blocked}"
        except ValueError:
            continue
    return None


def should_skip_entry(entry_name: str) -> bool:
    """Return True if a directory entry should be skipped during listing."""
    if entry_name in SKIP_DIRS:
        return True
    if entry_name.startswith(HIDDEN_PREFIXES):
        return True
    return False
