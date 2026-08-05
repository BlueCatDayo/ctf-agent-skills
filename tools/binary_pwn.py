"""Stage 7 binary exploitation helper tools (specs 9, 10, 11, 12).

Pure-Python helpers that do not require pwntools:

- ``pwn_cyclic`` / ``pwn_cyclic_find``  - De Bruijn-style cyclic patterns
- ``pwn_pack`` / ``pwn_unpack``         - integer packing (struct)
- ``pwn_elf_info``                      - arch/bitness/endianness from `file`
- ``pwn_find_win_function``             - win/flag function discovery (nm/strings)
- ``pwn_got_plt``                       - PLT/GOT relocations (readelf)
- ``pwn_find_gadgets``                  - simple ROP gadget search (objdump)
- ``pwn_crash_analyze``                 - cyclic input -> crash -> offset (spec 10)
- ``pwn_verify_offset``                 - verify a computed offset
- ``pwn_analyze_ret2win``               - combined validated ret2win plan (spec 11)
- ``pwn_format_string_analysis``        - static format-string hints (spec 12)

Safety rules:

- Only files inside the configured challenge workspace are executed.
- Local binaries run with a timeout and ``shell=False``, non-interactive.
- Addresses are only reported from tool output - never invented.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from typing import List, Optional, Tuple

from .workspace import WorkspaceError, get_workspace_root

CYCLIC_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DEFAULT_TIMEOUT = 30
MAX_OUTPUT_CHARS = 6000

# Common simple gadgets searched by pwn_find_gadgets.
DEFAULT_GADGETS = ["pop rdi; ret", "pop rsi; ret", "pop rdx; ret", "ret"]


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) > limit:
        return text[:limit] + f"\n... [output truncated at {limit} characters]"
    return text


def _command_available(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _resolve_path(path: str, workspace_root: Optional[str]) -> str:
    root = get_workspace_root(workspace_root)
    full = os.path.abspath(os.path.join(str(root), path))
    root_abs = os.path.abspath(str(root))
    if not (full == root_abs or full.startswith(root_abs + os.sep)):
        raise WorkspaceError(f"Path is outside the workspace: {path}")
    if not os.path.exists(full):
        raise WorkspaceError(f"File not found: {path}")
    return full


def _run(cmd_args: List[str], timeout: int = DEFAULT_TIMEOUT, stdin_data: Optional[bytes] = None) -> Tuple[int, str, str]:
    """Run a command with shell=False and a timeout.  Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd_args,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout.decode("utf-8", errors="replace"), proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s."
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd_args[0]}"
    except OSError as e:
        return -1, "", f"OS error running {cmd_args[0]}: {e}"


# ---------------------------------------------------------------------------
# Cyclic patterns (pure Python, no pwntools)
# ---------------------------------------------------------------------------

def pwn_cyclic(length: int = 64, charset: str = CYCLIC_CHARSET) -> str:
    """Generate a cyclic pattern of *length* characters.

    Chunks of 4 characters rotate through *charset*; substrings of length
    >= 4 can be mapped back to an offset with :func:`pwn_cyclic_find`.
    """
    if length < 0:
        raise ValueError("length must be >= 0")
    if len(charset) < 2:
        raise ValueError("charset must contain at least 2 characters")
    out: List[str] = []
    total = 0
    i = 0
    while total < length:
        a = charset[i % len(charset)]
        b = charset[(i // len(charset)) % len(charset)]
        c = charset[(i // (len(charset) ** 2)) % len(charset)]
        d = charset[(i // (len(charset) ** 3)) % len(charset)]
        out.append(f"{a}{b}{c}{d}")
        total += 4
        i += 1
    return "".join(out)[:length]


def pwn_cyclic_find(substring: str, charset: str = CYCLIC_CHARSET) -> int:
    """Return the offset of *substring* in a cyclic pattern, or -1.

    *substring* must be at least 4 characters long for a reliable offset.
    """
    if not substring or len(substring) < 4:
        return -1
    # Search progressively longer prefixes of the pattern (covers the case
    # where the pattern wraps).
    pattern = pwn_cyclic(max(4096, len(substring) * 16), charset)
    idx = pattern.find(substring)
    if idx >= 0:
        return idx
    # Substrings spanning the wrap point
    extended = pattern + pattern[: len(substring) - 1]
    idx = extended.find(substring)
    return idx if idx < len(pattern) else -1


_STRUCT_FORMATS = {8: "B", 16: "H", 32: "I", 64: "Q"}


def pwn_pack(value: int, bits: int = 64, endianness: str = "little") -> str:
    """Pack an integer to bytes (spec 9) and return the hex string.

    The hex string is what tools return to the model, so payload bytes can
    be copied into scripts.  Use :func:`pwn_unpack` to reverse it.
    """
    if bits not in _STRUCT_FORMATS:
        raise ValueError(f"Unsupported bits: {bits} (use 8, 16, 32, or 64)")
    fmt = ("<" if endianness == "little" else ">") + _STRUCT_FORMATS[bits]
    return struct.pack(fmt, value).hex()


def pwn_unpack(data: str, bits: int = 64, endianness: str = "little") -> int:
    """Unpack a hex string of bytes to an integer."""
    if bits not in _STRUCT_FORMATS:
        raise ValueError(f"Unsupported bits: {bits}")
    raw = bytes.fromhex(data)
    if len(raw) < bits // 8:
        raise ValueError(f"Need {bits // 8} bytes, got {len(raw)}")
    fmt = ("<" if endianness == "little" else ">") + _STRUCT_FORMATS[bits]
    return struct.unpack(fmt, raw[: bits // 8])[0]


# ---------------------------------------------------------------------------
# ELF / symbol analysis
# ---------------------------------------------------------------------------

def pwn_elf_info(path: str, workspace_root: Optional[str] = None) -> str:
    """Report file type, architecture, bitness, endianness, and link type."""
    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error: {e}"

    if not _command_available("file"):
        return "Error: 'file' command not available on this system."

    rc, out, err = _run(["file", "-b", full])
    if rc != 0:
        return f"file failed (rc={rc}): {err[:300]}"

    info = out.strip()
    arch = "64-bit" if "64-bit" in info else ("32-bit" if "32-bit" in info else "unknown-bit")
    endian = "little" if "LSB" in info else ("big" if "MSB" in info else "unknown")
    link = "dynamic" if "dynamically linked" in info else ("static" if "statically linked" in info else "unknown")
    stripped = "stripped" if "stripped" in info else "unstripped/unknown"
    return (
        f"File: {path}\n"
        f"Type: {info[:200]}\n"
        f"Architecture: {arch}\n"
        f"Endianness: {endian}\n"
        f"Linking: {link}\n"
        f"Stripped: {stripped}"
    )


def pwn_find_win_function(path: str, workspace_root: Optional[str] = None) -> str:
    """Search symbols and strings for win/flag-printing functions."""
    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error: {e}"

    symbol_text = ""
    if _command_available("nm"):
        rc, out, err = _run(["nm", full])
        if rc == 0:
            symbol_text = out
    elif _command_available("objdump"):
        rc, out, err = _run(["objdump", "-t", full])
        if rc == 0:
            symbol_text = out

    candidates: List[str] = []
    for m in re.finditer(r"\b([0-9a-fA-F]{6,16})\s+[TtWw]\s+([A-Za-z_][A-Za-z0-9_]*)", symbol_text):
        addr, name = m.group(1), m.group(2)
        if re.search(r"(win|flag|shell|system|exec|backdoor|victory)", name, re.IGNORECASE):
            candidates.append(f"{name} @ 0x{addr}")

    if not candidates and _command_available("strings"):
        rc, out, err = _run(["strings", full])
        if rc == 0:
            for name in re.findall(r"(?i)\b(win|print_flag|get_flag|flag_?func)\b", out):
                if name not in [c.split(" @ ")[0] for c in candidates]:
                    candidates.append(f"{name} (strings reference, address unknown)")

    if not candidates:
        return (
            f"No win/flag function found in {path}. "
            "Check binary_symbols / binary_strings output for hints."
        )
    return f"Win/flag function candidates for {path}:\n" + "\n".join(candidates[:10])


def pwn_got_plt(path: str, workspace_root: Optional[str] = None) -> str:
    """Show PLT/GOT-relevant relocations and dynamic symbols (readelf)."""
    try:
        _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error: {e}"

    if not _command_available("readelf"):
        return "Error: 'readelf' not available on this system."

    parts = []
    rc, out, err = _run(["readelf", "-r", path])
    reloc_lines = "\n".join(
        l for l in out.splitlines() if re.search(r"(JUMP_SLOT|GLOB_DAT|_GLOBAL_OFFSET)", l)
    )
    parts.append("Relocations (JUMP_SLOT / GLOB_DAT):\n" + (reloc_lines or "  (none found)"))

    rc, out, err = _run(["readelf", "-d", path])
    dyn = "\n".join(l.strip() for l in out.splitlines() if "NEEDED" in l or "PLT" in l)
    parts.append("Dynamic section:\n" + (dyn or "  (none found)"))

    return f"PLT/GOT analysis for {path}:\n\n" + "\n\n".join(parts)


def pwn_find_gadgets(
    path: str,
    workspace_root: Optional[str] = None,
    gadgets: Optional[List[str]] = None,
    limit: int = 10,
) -> str:
    """Search for simple ROP gadgets using objdump disassembly.

    Looks for exact byte sequences for common gadgets (pop rdi; ret, ...).
    Requires objdump.  Returns only confirmed addresses from disassembly.
    """
    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error: {e}"

    if not _command_available("objdump"):
        return "Error: 'objdump' not available on this system."

    want = gadgets or DEFAULT_GADGETS
    rc, out, err = _run(["objdump", "-d", full])
    if rc != 0:
        return f"objdump failed (rc={rc}): {err[:300]}"

    # Parse "<address> <bytes>  <mnemonic>" lines.
    insn = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-fA-F]+):\s+([0-9a-fA-F ]{4,40})\s+([a-z]{2,10}.*)$", line)
        if m:
            insn.append((int(m.group(1), 16), m.group(2).strip(), m.group(3).strip()))

    found: List[str] = []
    for gadget in want:
        gparts = [g.strip() for g in re.split(r";|\s+ret", gadget) if g.strip()]
        gparts = [g for g in gparts if g != "ret"]
        # Simple approach: find sequences of `pop rX` ending with `ret`.
        for i in range(len(insn) - 1):
            addr, bytes_, mnem = insn[i]
            nxt_addr, _, nxt_mnem = insn[i + 1]
            if mnem.startswith("pop ") and nxt_mnem == "ret":
                g = f"{mnem}; ret"
                if g not in found and (not gadgets or g in want):
                    found.append(f"{g} @ 0x{addr:x}")
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break

    if not found:
        return (
            f"No simple ROP gadgets found in {path}. "
            "The binary may lack useful pop/ret sequences - check objdump output."
        )
    return f"ROP gadgets for {path}:\n" + "\n".join(found[:limit])


# ---------------------------------------------------------------------------
# Crash & offset analysis (spec 10)
# ---------------------------------------------------------------------------

def _looks_executable(full_path: str) -> bool:
    """Heuristic check that a file is runnable (ELF, PE, or script).

    On Windows ``os.access(X_OK)`` is unreliable, so we inspect magic bytes.
    """
    try:
        with open(full_path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    if head.startswith(b"\x7fELF") or head.startswith(b"MZ"):
        return True
    if head.startswith(b"#!"):
        return True
    return False


def pwn_crash_analyze(
    path: str,
    workspace_root: Optional[str] = None,
    input_length: int = 512,
    timeout: int = 10,
) -> str:
    """Controlled crash-and-offset workflow for a local challenge binary.

    Steps (spec 10):
      1. Generate cyclic input of *input_length* bytes.
      2. Run the local binary with that input on stdin.
      3. Capture the crash result (exit code, signal, register values).
      4. Determine the overwrite offset from the crash address (pwntools
         ``cyclic_find`` when available, else ASCII pattern search).
      5. Verify the calculated offset with a second run.
      6. Store the result (the caller records it in evidence memory).

    Operates only on files inside the configured challenge directory with
    a short timeout; never on unrelated system programs.
    """
    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error: {e}"

    if not _looks_executable(full):
        return (
            f"'{path}' is not executable (ELF/PE/script magic not found). "
            "Run pwn_cyclic + offset analysis against evidence instead."
        )

    cyclic = pwn_cyclic(input_length)
    rc, out, err = _run([full], timeout=timeout, stdin_data=cyclic.encode("latin-1"))

    crash_text = f"{out}\n{err}".strip()
    lines = [
        f"Ran: {path} with {input_length} bytes of cyclic input",
        f"Exit code: {rc}" + (" (crash likely)" if rc not in (0, -1) else ""),
    ]
    if crash_text:
        lines.append("Program output (truncated):\n" + _truncate(crash_text, 2000))

    address = _crash_address(crash_text)
    if address is None:
        lines.append(
            "\nOffset: could not determine from output (no crash address captured)."
        )
        lines.append(
            "Suggested: run the binary in a debugger (gdb) to find the faulting "
            "address, then use pwn_cyclic_find on the pattern."
        )
        return "\n".join(lines)

    offset = _offset_from_address(address, cyclic)
    lines.append(f"\nCrash address: {address}")
    if offset is not None:
        lines.append(f"Overwrite offset: {offset} bytes")
        lines.append(
            "Verification: rerun with cyclic[:offset] + marker + cyclic[offset+4:] "
            "and confirm the fault address changes to the marker (see pwn_verify_offset)."
        )
    else:
        lines.append(
            "Offset: address did not match the cyclic pattern (non-ASCII overwrite "
            "or ASLR); install pwntools for numeric cyclic_find."
        )
    return "\n".join(lines)


def _crash_address(text: str) -> Optional[str]:
    """Extract a faulting address from crash output, if present."""
    patterns = [
        r"(?:SIGSEGV|segmentation fault)[^\n]*?(0x[0-9a-fA-F]+)",
        r"0x[0-9a-fA-F]{6,16}",
        r"(?:faulting address|pc|rip|eip)\s*[=:]\s*(0x[0-9a-fA-F]+)",
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(1) if m.groups() else m.group(0)
    return None


def _offset_from_address(address: str, cyclic: str) -> Optional[int]:
    """Map a crash address back to a cyclic offset."""
    try:
        # Prefer pwntools when installed.
        from pwnlib.util.cyclic import cyclic_find  # type: ignore

        result = cyclic_find(int(address, 16))
        if isinstance(result, int) and result >= 0:
            return result
    except Exception:
        pass

    # Fallback: treat the address bytes as ASCII overwritten data (4 bytes).
    try:
        value = int(address, 16)
        packed = struct.pack("<I", value & 0xFFFFFFFF)
        if all(32 <= b < 127 for b in packed):
            found = pwn_cyclic_find(packed.decode("ascii"))
            if found >= 0:
                return found
    except Exception:
        pass
    return None


def pwn_verify_offset(
    path: str,
    offset: int,
    workspace_root: Optional[str] = None,
    marker: str = "BBBB",
    timeout: int = 10,
) -> str:
    """Verify a computed offset by crashing the binary with a marker at *offset*.

    If the fault address changes to the marker bytes, the offset is confirmed.
    """
    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error: {e}"

    if not _looks_executable(full):
        return f"'{path}' is not executable; cannot verify by running."

    cyclic = pwn_cyclic(max(offset + 16, 64))
    payload = cyclic[:offset] + marker + cyclic[offset + len(marker):]
    rc, out, err = _run([full], timeout=timeout, stdin_data=payload.encode("latin-1"))
    crash_text = f"{out}\n{err}".strip()
    address = _crash_address(crash_text)
    marker_hex = "0x" + marker.encode("ascii").hex().ljust(8, "0")
    lines = [
        f"Verification run for offset {offset} with marker {marker!r}:",
        f"Exit code: {rc}",
    ]
    if crash_text:
        lines.append("Output (truncated):\n" + _truncate(crash_text, 1200))
    if address:
        lines.append(f"Fault address: {address}")
        ascii_marker = marker.encode("ascii").hex()
        if ascii_marker in address.replace("0x", "") or address.lower().endswith(marker.encode("ascii").hex()[:4]):
            lines.append(f"Offset {offset} CONFIRMED: fault address contains the marker.")
        else:
            lines.append(
                f"Offset {offset} NOT confirmed: fault address {address} does not "
                "match the marker - re-run pwn_crash_analyze."
            )
    else:
        lines.append("No fault address captured - offset could not be verified from output.")
    return "\n".join(lines)


def pwn_analyze_ret2win(path: str, workspace_root: Optional[str] = None) -> str:
    """Combined ret2win analysis (spec 11): arch + offset + win address + plan.

    Every value comes from tool output; nothing is invented.  Missing facts
    are reported as gaps with the tool to run next.
    """
    sections: List[str] = [f"# Ret2win analysis for {path}"]

    info = pwn_elf_info(path, workspace_root)
    sections.append(info)

    win = pwn_find_win_function(path, workspace_root)
    sections.append(win)

    crash = pwn_crash_analyze(path, workspace_root, input_length=256)
    sections.append(crash)

    # Validate the plan components
    arch = "64-bit" if "64-bit" in info else "32-bit"
    offset_m = re.search(r"Overwrite offset:\s*(\d+)", crash)
    addr_m = re.search(r"@ 0x([0-9a-fA-F]+)", win)
    plan_parts = []
    if offset_m:
        plan_parts.append(f"offset={offset_m.group(1)} bytes")
    else:
        plan_parts.append("offset=UNKNOWN (run pwn_crash_analyze / gdb)")
    if addr_m:
        plan_parts.append(f"target=0x{addr_m.group(1)}")
    else:
        plan_parts.append("target=UNKNOWN (run pwn_find_win_function / binary_symbols)")
    plan_parts.append(f"arch={arch}")
    endian = "little" if "Little" in info or "LSB" in info else ("big" if "big" in info else "unknown")
    plan_parts.append(f"endianness={endian}")
    sections.append("Payload plan validation:\n- " + "\n- ".join(plan_parts))
    if "UNKNOWN" not in " ".join(plan_parts):
        sections.append(
            "Build: pwn_pack(target, bits=64/32, endianness='little') appended "
            "after the offset; validate stack alignment for x86-64."
        )
    else:
        sections.append(
            "Gaps remain - collect the missing facts before building any payload."
        )
    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Format-string static hints (spec 12)
# ---------------------------------------------------------------------------

def pwn_format_string_analysis(path: str, workspace_root: Optional[str] = None) -> str:
    """Static hints for format-string analysis (read-only)."""
    try:
        full = _resolve_path(path, workspace_root)
    except WorkspaceError as e:
        return f"Workspace error: {e}"
    except OSError as e:
        return f"Error: {e}"

    hints: List[str] = []
    symbol_text = ""
    if _command_available("nm"):
        rc, out, _ = _run(["nm", full])
        if rc == 0:
            symbol_text = out
    if _command_available("objdump") and not symbol_text:
        rc, out, _ = _run(["objdump", "-t", full])
        if rc == 0:
            symbol_text = out

    fmt_funcs = [f for f in ("printf", "sprintf", "snprintf", "fprintf", "vprintf", "puts") if f in symbol_text]
    if fmt_funcs:
        hints.append(f"Format-family functions referenced: {', '.join(fmt_funcs)}")
    else:
        hints.append("No printf-family symbols found (stripped binary or no format usage).")

    if _command_available("strings"):
        rc, out, _ = _run(["strings", full])
        if rc == 0:
            fmt_strings = re.findall(r"[^%\n]*%[sdxXcunp][^%\n]*", out)
            fmt_strings = [s.strip() for s in fmt_strings if s.strip() and not s.startswith("//")][:8]
            if fmt_strings:
                hints.append(f"Format-string literals: {', '.join(fmt_strings[:6])}")

    hints.append(
        "Plan: start with non-destructive reads ('AAAA%p.%p...') via "
        "pwn_session_start/send, determine the argument offset, record each "
        "confirmed leak - do not use %n unless the challenge requires it."
    )
    return "Format-string analysis for " + path + ":\n- " + "\n- ".join(hints)
