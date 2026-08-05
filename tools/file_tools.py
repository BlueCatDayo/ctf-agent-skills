"""Local file analysis tools for CTF challenge inspection."""

import hashlib
import os
import re
import string
from pathlib import Path
from typing import Optional

from .workspace import (
    PathTraversalError,
    WorkspaceError,
    get_workspace_root,
    is_path_blocked,
    should_skip_entry,
    validate_within_workspace,
)

MAX_TOOL_OUTPUT_CHARS = 4096


def _truncate(text: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Truncate text to *limit* characters, appending a notice if truncated."""
    if len(text) > limit:
        return text[:limit] + f"\n... [output truncated at {limit} characters]"
    return text


def list_files(
    path: str = "",
    max_entries: int = 500,
    workspace_root: Optional[str] = None,
) -> str:
    """Recursively list challenge files with relative paths and sizes.

    Parameters
    ----------
    path:
        Relative path within the workspace to start listing from.
    max_entries:
        Maximum number of entries to return.
    workspace_root:
        Override the default workspace root directory.

    Returns
    -------
    str
        A formatted listing of files, or an error message.
    """
    try:
        root = get_workspace_root(workspace_root)
        if not path:
            target = root
        else:
            target = validate_within_workspace(path, root)

        if not target.exists():
            return f"Path not found: {path}"

        if not target.is_dir():
            # Single file — return its info
            size = target.stat().st_size
            rel = target.relative_to(root)
            return f"{rel}  ({size} bytes)"

        entries = []
        for dirpath, dirnames, filenames in os.walk(target):
            # Filter out skipped directories in-place
            dirnames[:] = [
                d for d in dirnames if not should_skip_entry(d)
            ]

            for filename in filenames:
                if should_skip_entry(filename):
                    continue
                full_path = Path(dirpath) / filename
                try:
                    rel_path = full_path.relative_to(root)
                    size = full_path.stat().st_size
                    entries.append(f"{rel_path}  ({size} bytes)")
                except ValueError:
                    continue

                if len(entries) >= max_entries:
                    entries.append(
                        f"... [output limited to {max_entries} entries]"
                    )
                    break

            if len(entries) >= max_entries:
                break

        if not entries:
            return "No files found in the specified directory."

        return "\n".join(entries)

    except PathTraversalError as e:
        return f"Security error: {e}"
    except WorkspaceError as e:
        return f"Workspace error: {e}"


def read_text_file(
    path: str,
    max_chars: int = MAX_TOOL_OUTPUT_CHARS,
    workspace_root: Optional[str] = None,
) -> str:
    """Read a text file safely, detecting binary content.

    Parameters
    ----------
    path:
        Relative path to the file within the workspace.
    max_chars:
        Maximum number of characters to return.
    workspace_root:
        Override the default workspace root directory.

    Returns
    -------
    str
        The file contents, or a clear message for binary/unreadable files.
    """
    try:
        root = get_workspace_root(workspace_root)
        target = validate_within_workspace(path, root)

        if not target.exists():
            return f"File not found: {path}"
        if not target.is_file():
            return f"Path is not a file: {path}"

        # Check size before reading
        file_size = target.stat().st_size
        if file_size > max_chars * 4:
            return (
                f"File too large ({file_size} bytes). "
                f"Use inspect_file for metadata, or read a smaller portion."
            )

        # Read raw bytes first to detect binary content
        raw = target.read_bytes()

        # Check for NUL bytes — indicator of binary content
        if b"\x00" in raw:
            return (
                f"Binary file detected ({len(raw)} bytes). "
                f"Use inspect_file for a detailed report, "
                f"or run `strings` via run_ctf_command to extract readable text."
            )

        # Try to decode as UTF-8, fall back to latin-1
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except UnicodeDecodeError:
                return (
                    f"File contains non-text bytes ({len(raw)} bytes). "
                    f"Use inspect_file for a detailed report."
                )

        return _truncate(text, max_chars)

    except PathTraversalError as e:
        return f"Security error: {e}"
    except WorkspaceError as e:
        return f"Workspace error: {e}"


def inspect_file(
    path: str,
    workspace_root: Optional[str] = None,
) -> str:
    """Inspect a file and report metadata, type, hash, and content preview.

    Parameters
    ----------
    path:
        Relative path to the file within the workspace.
    workspace_root:
        Override the default workspace root directory.

    Returns
    -------
    str
        A structured inspection report.
    """
    try:
        root = get_workspace_root(workspace_root)
        target = validate_within_workspace(path, root)

        if not target.exists():
            return f"File not found: {path}"
        if not target.is_file():
            return f"Path is not a file: {path}"

        stat = target.stat()
        file_size = stat.st_size

        # Determine likely file type from extension and content
        ext = target.suffix.lower()
        mime_hints = {
            ".txt": "Text file",
            ".json": "JSON data",
            ".md": "Markdown document",
            ".py": "Python source",
            ".js": "JavaScript source",
            ".html": "HTML document",
            ".css": "CSS stylesheet",
            ".csv": "CSV data",
            ".xml": "XML data",
            ".yml": "YAML configuration",
            ".yaml": "YAML configuration",
            ".ini": "INI configuration",
            ".cfg": "Configuration file",
            ".log": "Log file",
            ".bin": "Binary file",
            ".exe": "Windows executable",
            ".dll": "Dynamic-link library",
            ".so": "Shared library",
            ".png": "PNG image",
            ".jpg": "JPEG image",
            ".jpeg": "JPEG image",
            ".gif": "GIF image",
            ".pdf": "PDF document",
            ".zip": "ZIP archive",
            ".gz": "Gzip compressed",
            ".tar": "TAR archive",
            ".sqlite": "SQLite database",
            ".db": "Database file",
        }
        file_type = mime_hints.get(ext, "Unknown file type")

        # SHA-256 hash
        sha256 = hashlib.sha256(target.read_bytes()).hexdigest()

        # First bytes in hex
        raw = target.read_bytes()
        first_bytes_hex = raw[:32].hex(" ")

        # Printable strings (sequences of 4+ printable ASCII chars)
        printable_chars = set(string.printable)
        strings_found = []
        current = []
        for byte in raw:
            ch = chr(byte)
            if ch in printable_chars and ch not in "\t\r\n":
                current.append(ch)
            else:
                if len(current) >= 4:
                    strings_found.append("".join(current))
                current = []
        if len(current) >= 4:
            strings_found.append("".join(current))

        # Determine text vs binary
        is_text = b"\x00" not in raw and file_size > 0
        if file_size == 0:
            file_type = "Empty file"

        # Build report
        lines = [
            f"Filename: {target.name}",
            f"Relative path: {target.relative_to(root)}",
            f"File size: {file_size} bytes",
            f"Likely file type: {file_type}",
            f"SHA-256: {sha256}",
            f"First bytes (hex): {first_bytes_hex}",
            f"Text file: {'Yes' if is_text else 'No'}",
        ]

        if strings_found:
            lines.append(f"Printable strings ({len(strings_found)} found):")
            for s in strings_found[:20]:
                lines.append(f"  {s}")
            if len(strings_found) > 20:
                lines.append(f"  ... and {len(strings_found) - 20} more")
        else:
            lines.append("Printable strings: None found")

        return "\n".join(lines)

    except PathTraversalError as e:
        return f"Security error: {e}"
    except WorkspaceError as e:
        return f"Workspace error: {e}"


def search_files(
    pattern: str,
    path: str = "",
    use_regex: bool = False,
    max_matches: int = 200,
    workspace_root: Optional[str] = None,
) -> str:
    """Search text recursively inside the challenge workspace.

    Parameters
    ----------
    pattern:
        The search term or regular expression.
    path:
        Relative path within the workspace to start searching from.
    use_regex:
        If True, treat *pattern* as a regular expression.
    max_matches:
        Maximum number of matching lines to return.
    workspace_root:
        Override the default workspace root directory.

    Returns
    -------
    str
        Matching lines with filenames, or an error message.
    """
    try:
        root = get_workspace_root(workspace_root)
        if not path:
            target_dir = root
        else:
            target_dir = validate_within_workspace(path, root)

        if not target_dir.exists():
            return f"Path not found: {path}"
        if not target_dir.is_dir():
            return f"Path is not a directory: {path}"

        # Compile regex if requested
        if use_regex:
            try:
                regex = re.compile(pattern)
            except re.error as e:
                return f"Invalid regular expression: {e}"
        else:
            regex = None

        matches = []
        for dirpath, dirnames, filenames in os.walk(target_dir):
            dirnames[:] = [d for d in dirnames if not should_skip_entry(d)]

            for filename in filenames:
                if should_skip_entry(filename):
                    continue
                full_path = Path(dirpath) / filename
                try:
                    rel_path = full_path.relative_to(root)
                except ValueError:
                    continue

                # Skip binary files
                try:
                    raw = full_path.read_bytes()
                    if b"\x00" in raw:
                        continue
                    text = raw.decode("utf-8", errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue

                for line_num, line in enumerate(text.splitlines(), start=1):
                    matched = False
                    if regex:
                        if regex.search(line):
                            matched = True
                    else:
                        if pattern in line:
                            matched = True

                    if matched:
                        matches.append(f"{rel_path}:{line_num}: {line}")
                        if len(matches) >= max_matches:
                            break

                if len(matches) >= max_matches:
                    break

            if len(matches) >= max_matches:
                break

        if not matches:
            return f"No matches found for '{pattern}'."

        result = "\n".join(matches)
        if len(matches) >= max_matches:
            result += f"\n... [output limited to {max_matches} matches]"

        return result

    except PathTraversalError as e:
        return f"Security error: {e}"
    except WorkspaceError as e:
        return f"Workspace error: {e}"


def calculate_file_hash(
    path: str,
    algorithm: str = "sha256",
    workspace_root: Optional[str] = None,
) -> str:
    """Calculate a cryptographic hash of a file.

    Supported algorithms: md5, sha1, sha256, sha512.

    Parameters
    ----------
    path:
        Relative path to the file within the workspace.
    algorithm:
        Hash algorithm to use.
    workspace_root:
        Override the default workspace root directory.

    Returns
    -------
    str
        The hexadecimal hash digest, or an error message.
    """
    algorithm = algorithm.lower().strip()
    supported = {"md5", "sha1", "sha256", "sha512"}

    if algorithm not in supported:
        return (
            f"Unsupported algorithm: '{algorithm}'. "
            f"Supported: {', '.join(sorted(supported))}."
        )

    try:
        root = get_workspace_root(workspace_root)
        target = validate_within_workspace(path, root)

        if not target.exists():
            return f"File not found: {path}"
        if not target.is_file():
            return f"Path is not a file: {path}"

        hasher = hashlib.new(algorithm)
        # Read in chunks to handle large files
        with target.open("rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)

        # Format algorithm name with dashes for display
        display_algo = algorithm.upper()
        if display_algo == "SHA1":
            display_algo = "SHA-1"
        elif display_algo == "SHA256":
            display_algo = "SHA-256"
        elif display_algo == "SHA512":
            display_algo = "SHA-512"

        return f"{display_algo} ({path}): {hasher.hexdigest()}"

    except PathTraversalError as e:
        return f"Security error: {e}"
    except WorkspaceError as e:
        return f"Workspace error: {e}"
