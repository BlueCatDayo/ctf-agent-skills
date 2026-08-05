"""Stage 5 binary exploitation helper tools.

Provides safe wrappers around common binary-analysis commands:
file, strings, readelf, objdump, nm, ldd, xxd, hexdump (and checksec when
installed).  Every helper:

- Checks that the underlying command exists and returns a friendly error
  instead of crashing when it is missing.
- Runs commands with ``shell=False`` (no shell metacharacters).
- Works against files inside the configured workspace.

A combined :func:`analyze_binary` runs the standard binary workflow:
file -> checksec (if installed) -> strings -> readelf -> objdump ->
symbols -> interesting strings -> possible vulnerability notes.
"""

import os
import re
import shutil
import subprocess
from typing import List, Optional

from .workspace import get_workspace_root, WorkspaceError

# Commands this module can use; each must be safe read-only analysis.
BINARY_COMMANDS = [
    "file",
    "strings",
    "readelf",
    "objdump",
    "nm",
    "ldd",
    "xxd",
    "hexdump",
    "checksec",
]

MAX_OUTPUT_CHARS = 6000
DEFAULT_TIMEOUT = 30


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    """Truncate *text* to *limit* characters with a notice."""
    if len(text) > limit:
        return text[:limit] + f"\n... [output truncated at {limit} characters]"
    return text


def _command_available(cmd: str) -> bool:
    """Return True if *cmd* is installed and usable on this system."""
    return shutil.which(cmd) is not None


def _resolve_path(path: str, workspace_root: Optional[str]) -> str:
    """Resolve *path* inside the workspace, blocking escapes."""
    root = get_workspace_root(workspace_root)
    full = os.path.abspath(os.path.join(str(root), path))
    root_abs = os.path.abspath(str(root))
    if not (full == root_abs or full.startswith(root_abs + os.sep)):
        raise WorkspaceError(f"Path is outside the workspace: {path}")
    if not os.path.exists(full):
        raise WorkspaceError(f"File not found: {path}")
    return full


def _run(
    cmd: str,
    args: List[str],
    path: str,
    workspace_root: Optional[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Run a whitelisted binary-analysis command safely.

    Returns a friendly formatted output.  Never uses ``shell=True``.
    """
    if cmd not in BINARY_COMMANDS:
        return f"Error: Unsupported binary command '{cmd}'."

    if not _command_available(cmd):
        hint = ""
        if cmd == "checksec":
            hint = " Install pwntools or the checksec script to enable this check."
        return (
            f"Error: '{cmd}' is not available on this system.{hint} "
            f"Use file/strings/readelf/objdump/nm/xxd/hexdump instead."
        )

    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error accessing file: {e}"

    cmd_list = [cmd] + args + [full]
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return f"Command '{cmd}' timed out after {timeout}s."
    except FileNotFoundError:
        return f"Error: '{cmd}' could not be executed (not found in PATH)."
    except OSError as e:
        return f"Error running '{cmd}': {e}"

    output = result.stdout or ""
    if result.stderr:
        output += f"\n(stderr) {_truncate(result.stderr, 2000)}"
    return (
        f"Command: {cmd} {path}\n"
        f"Exit code: {result.returncode}\n"
        f"Output:\n{_truncate(output)}"
    )


# ---------------------------------------------------------------------------
# Individual analysis helpers
# ---------------------------------------------------------------------------

def binary_file_info(
    path: str,
    workspace_root: Optional[str] = None,
) -> str:
    """Run ``file`` on *path* to identify its format and architecture."""
    return _run("file", ["-b"], path, workspace_root)


def binary_strings(
    path: str,
    min_length: int = 4,
    workspace_root: Optional[str] = None,
) -> str:
    """Extract readable strings from *path* (``strings -n <min_length>``)."""
    return _run("strings", ["-n", str(min_length)], path, workspace_root)


def binary_readelf(
    path: str,
    section: str = "headers",
    workspace_root: Optional[str] = None,
) -> str:
    """Inspect ELF headers/sections (``readelf -h/-l/-S/-r/-d``).

    *section*: headers (default), program, sections, relocations, dynamic.
    """
    flag_map = {
        "headers": "-h",
        "program": "-l",
        "sections": "-S",
        "relocations": "-r",
        "dynamic": "-d",
    }
    flag = flag_map.get((section or "headers").lower(), "-h")
    return _run("readelf", [flag], path, workspace_root)


def binary_objdump(
    path: str,
    disassemble: bool = False,
    workspace_root: Optional[str] = None,
) -> str:
    """Inspect an object file: disassembly or headers.

    With ``disassemble=True`` runs ``objdump -d`` (may be large; output is
    truncated).  Otherwise runs ``objdump -f -h`` for format and sections.
    """
    if disassemble:
        return _run("objdump", ["-d"], path, workspace_root)
    return _run("objdump", ["-f", "-h"], path, workspace_root)


def binary_symbols(
    path: str,
    workspace_root: Optional[str] = None,
) -> str:
    """List symbols with ``nm`` (falls back to ``objdump -t`` if missing)."""
    if _command_available("nm"):
        return _run("nm", [], path, workspace_root)
    return _run("objdump", ["-t"], path, workspace_root)


def binary_libraries(
    path: str,
    workspace_root: Optional[str] = None,
) -> str:
    """List linked shared libraries (``ldd``)."""
    return _run("ldd", [], path, workspace_root)


def binary_hexdump(
    path: str,
    length: int = 256,
    workspace_root: Optional[str] = None,
) -> str:
    """Hex dump the first *length* bytes (``xxd`` or ``hexdump -C``)."""
    if _command_available("xxd"):
        return _run("xxd", ["-l", str(length)], path, workspace_root)
    return _run("hexdump", ["-C", "-n", str(length)], path, workspace_root)


def binary_checksec(
    path: str,
    workspace_root: Optional[str] = None,
) -> str:
    """Check security mitigations with ``checksec`` if installed."""
    return _run("checksec", ["--file"], path, workspace_root)


# ---------------------------------------------------------------------------
# Orchestrated analysis
# ---------------------------------------------------------------------------

def analyze_binary(
    path: str,
    workspace_root: Optional[str] = None,
) -> str:
    """Run the full binary analysis workflow for *path*.

    Workflow: file -> checksec (if installed) -> strings -> readelf ->
    objdump -> symbols -> interesting strings -> possible vulnerabilities.
    Each step degrades gracefully when a command is unavailable.
    """
    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error accessing file: {e}"

    sections: List[str] = []

    # 1. file
    sections.append(binary_file_info(path, workspace_root))

    # 2. checksec (optional)
    if _command_available("checksec"):
        sections.append(binary_checksec(path, workspace_root))
    else:
        sections.append("checksec: not available on this system (skipped).")

    # 3. strings (first chunk)
    sections.append(binary_strings(path, 4, workspace_root))

    # 4. readelf headers
    sections.append(binary_readelf(path, "headers", workspace_root))

    # 5. objdump (format + sections, not full disassembly)
    sections.append(binary_objdump(path, disassemble=False, workspace_root=workspace_root))

    # 6. symbols
    sections.append(binary_symbols(path, workspace_root))

    # 7. Interesting strings (flag patterns, dangerous functions, secrets)
    interesting = _interesting_strings(full)
    sections.append(
        f"Interesting strings in {path}:\n" + (interesting or "  (none found)")
    )

    # 8. Possible vulnerability notes (heuristic from strings/symbols)
    notes = _vulnerability_notes(full)
    sections.append(
        f"Possible vulnerability notes:\n" + (notes or "  (no obvious red flags)")
    )

    return "\n\n".join(sections)


def _interesting_strings(full_path: str) -> str:
    """Heuristically find interesting strings: flag patterns, secrets,
    dangerous function names, and known tool banners."""
    try:
        result = subprocess.run(
            ["strings", full_path],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
            shell=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return "  (strings unavailable)"

    text = result.stdout or ""
    patterns = [
        (r"flag\{[^}]+\}", "flag pattern"),
        (r"\{[A-Za-z0-9_\-]{8,}\}", "brace-enclosed token"),
        (r"(?i)password\s*[:=]", "password hint"),
        (r"(?i)secret|private[_ ]?key", "secret/key hint"),
        (r"(?i)admin|root", "privilege hint"),
        (r"system\s*\(|execve?\s*\(|popen\s*\(", "dangerous call"),
        (r"gets\s*\(|strcpy\s*\(|sprintf\s*\(|strcat\s*\(|scanf\s*\(", "unsafe string call"),
        (r"bin/sh", "/bin/sh reference"),
        (r"python|perl|/bin/bash", "interpreter reference"),
        (r"openssl|RSA|AES|SHA", "crypto reference"),
    ]
    found = []
    for pat, label in patterns:
        matches = list(re.findall(pat, text, re.IGNORECASE))
        if matches:
            unique = sorted(set(matches))[:5]
            found.append(f"  [{label}] {', '.join(unique)}")
    return "\n".join(found)


def _vulnerability_notes(full_path: str) -> str:
    """Produce heuristic vulnerability notes from available tool output."""
    notes = []

    # Architecture / protections via readelf when available
    if _command_available("readelf"):
        try:
            r = subprocess.run(
                ["readelf", "-l", full_path],
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT,
                shell=False,
            )
            out = (r.stdout or "").lower()
            if "gnu-stack" in out:
                if "rw" in out and "gnu-stack" in out:
                    notes.append("  - Stack is marked executable (NX may be disabled) — check for shellcode.")
            if "canary" not in out:
                pass
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass

    if _command_available("readelf"):
        try:
            r = subprocess.run(
                ["readelf", "-h", full_path],
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT,
                shell=False,
            )
            out = (r.stdout or "").lower()
            if "type:" in out and "dyn" in out:
                notes.append("  - PIE/position-independent binary detected — ASLR applies to the base.")
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass

    if not notes:
        return ""
    return "\n".join(notes)
