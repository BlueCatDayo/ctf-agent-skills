"""Stage 7 binary triage specialist (spec 8).

For a local challenge binary (given in the profile as ``file_path``) this
specialist collects, with read-only commands:

- file type, architecture, bitness, endianness
- static or dynamic linking, stripped/unstripped status
- security protections (checksec / readelf)
- imported functions, exported symbols
- interesting strings
- sections, program headers, linked libraries
- possible input functions, dangerous function usage
- potential win/flag functions

Tools used: file, checksec, strings, readelf, objdump, nm, ldd.  If a
command is unavailable, triage continues with the remaining tools.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "binary", "elf", "pwn", "exploit", "reverse", "readelf", "objdump",
    "nm", "checksec", "strings", "architecture", "stack", "nx", "pie",
    "canary", "relro", "got", "plt", "disassembly", "gdb", "file type",
]

# Functions often used for input in CTF binaries.
INPUT_FUNCTIONS = ["gets", "read", "scanf", "fgets", "getline", "fread"]
# Dangerous functions frequently exploited.
DANGEROUS_FUNCTIONS = ["gets", "strcpy", "strcat", "sprintf", "vsprintf",
                       "scanf", "system", "popen", "execve", "mprotect",
                       "printf", "memcpy"]
# Candidate win/flag function names.
WIN_FUNCTION_HINTS = ["win", "flag", "print_flag", "get_flag", "shell",
                      "victory", "ret2win", "system", "backdoor"]


class BinaryTriageSpecialist(Specialist):
    """Evidence-driven binary triage workflow (spec 8)."""

    name = "binary.triage"
    category = "binary"
    description = "Collect file type, arch, protections, symbols, strings, and danger signals from a binary."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        profile = profile or {}
        file_path = profile.get("file_path") or ""
        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []

        if file_path:
            findings, warnings = self._triage_file(file_path, profile.get("workspace_root"))
            confirmed.extend(findings)
            if warnings:
                rejected.extend(warnings)
        else:
            # Analysis-only mode: parse triage info from existing evidence text.
            parsed = self._parse_evidence(evidence)
            if parsed:
                confirmed.extend(parsed)
            else:
                rejected.append(
                    "No binary analysis evidence found. Provide a file_path in the "
                    "profile or run analyze_binary / binary_file_info first."
                )
            steps.append(
                "Run analyze_binary on the target file (or binary_file_info + "
                "binary_checksec + binary_strings + binary_symbols) to build triage evidence."
            )

        if confirmed:
            steps.append(
                "Use the triage results to choose the next specialist: "
                "buffer overflow / ret2win / format string / ROP analysis."
            )

        next_spec = self._suggest_next(confirmed, evidence)
        return self._result(
            evidence, profile,
            hypothesis="The binary's structure and protections determine the exploitation approach.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist=next_spec,
            summary=f"Triage: {len(confirmed)} finding(s) for {file_path or 'evidence-based mode'}.",
        )

    # ------------------------------------------------------------------
    # Execution path (read-only commands, spec 8)
    # ------------------------------------------------------------------

    def _triage_file(self, file_path: str, workspace_root: Optional[str]) -> List[str]:
        from tools.binary_tools import (
            binary_checksec, binary_file_info, binary_libraries,
            binary_readelf, binary_strings, binary_symbols,
        )

        findings: List[str] = []
        ws = workspace_root
        try:
            info = binary_file_info(file_path, ws)
        except Exception as e:
            info = f"Error: {e}"
        findings.append(self._clean("File type: " + info))

        try:
            checksec = binary_checksec(file_path, ws)
        except Exception as e:
            checksec = f"Error: {e}"
        if "not available" in checksec.lower():
            findings.append("checksec: not available (skipped) - use readelf for protections.")
        else:
            findings.append(self._clean("Protections: " + checksec))

        try:
            strings_out = binary_strings(file_path, 4, ws)
        except Exception as e:
            strings_out = f"Error: {e}"
        interesting = self._interesting(strings_out)
        if interesting:
            findings.append("Interesting strings: " + ", ".join(interesting[:8]))

        try:
            symbols = binary_symbols(file_path, ws)
        except Exception as e:
            symbols = f"Error: {e}"
        funcs = self._function_names(symbols)
        if funcs:
            findings.append(f"Symbols/functions: {', '.join(funcs[:12])}")
        stripped = self._is_stripped(symbols)
        findings.append("Stripped: " + ("yes (few symbol names)" if stripped else "no / unknown"))

        try:
            dynamic = binary_readelf(file_path, "dynamic", ws)
        except Exception as e:
            dynamic = f"Error: {e}"
        libs = self._libc_names(dynamic)
        if libs:
            findings.append(f"Linked libraries: {', '.join(libs[:6])}")

        try:
            libs_out = binary_libraries(file_path, ws)
        except Exception as e:
            libs_out = f"Error: {e}"
        if libs_out and "not available" not in libs_out.lower() and "error" not in libs_out.lower():
            findings.append(self._clean("ldd: " + libs_out[:400]))

        input_funcs = [f for f in INPUT_FUNCTIONS if f in (strings_out + symbols).lower()]
        if input_funcs:
            findings.append(f"Possible input function(s): {', '.join(input_funcs[:6])}")
        dangerous = [f for f in DANGEROUS_FUNCTIONS if f in (strings_out + symbols).lower()]
        if dangerous:
            findings.append(f"Dangerous function usage: {', '.join(dangerous[:8])}")

        win = [f for f in WIN_FUNCTION_HINTS if f in (strings_out + symbols).lower()]
        if win:
            findings.append(f"Potential win/flag function hint(s): {', '.join(win[:6])}")

        # Architecture / endianness from `file` output text.
        arch = self._arch_from_info(info)
        if arch:
            findings.append("Architecture/endianness: " + arch)

        return findings

    # ------------------------------------------------------------------
    # Parsing helpers (also used for evidence-only mode)
    # ------------------------------------------------------------------

    def _parse_evidence(self, evidence: EvidenceSnapshot) -> List[str]:
        text = "\n".join(evidence.outputs_for(
            "binary_file_info", "analyze_binary", "binary_checksec",
            "binary_strings", "binary_symbols", "binary_readelf",
            "binary_libraries",
        ))
        if not text.strip():
            return []
        findings: List[str] = []
        arch = self._arch_from_info(text)
        if arch:
            findings.append("Architecture/endianness: " + arch)
        if "not available" in text.lower():
            findings.append("Some binary commands unavailable on this system (graceful skip).")
        funcs = self._function_names(text)
        if funcs:
            findings.append(f"Symbols/functions seen: {', '.join(funcs[:12])}")
        dangerous = [f for f in DANGEROUS_FUNCTIONS if f in text.lower()]
        if dangerous:
            findings.append(f"Dangerous function usage: {', '.join(dangerous[:8])}")
        win = [f for f in WIN_FUNCTION_HINTS if f in text.lower()]
        if win:
            findings.append(f"Potential win/flag function hint(s): {', '.join(win[:6])}")
        return findings

    def _arch_from_info(self, text: str) -> str:
        m = re.search(r"(32|64)-bit\s+(LSB|MSB)", text, re.IGNORECASE)
        if not m:
            m = re.search(r"(32|64)-bit", text, re.IGNORECASE)
        bits = m.group(1) if m else "?"
        endian = ""
        m2 = re.search(r"(LSB|MSB)", text, re.IGNORECASE)
        if m2:
            endian = " little-endian" if m2.group(1).upper() == "LSB" else " big-endian"
        arch = ""
        for a in ("x86-64", "x86_64", "amd64", "aarch64", "arm", "mips", "riscv", "i386", "i686"):
            if a in text.lower():
                arch = a
                break
        return f"{bits}-bit{endian}{' ' + arch if arch else ''}".strip()

    def _function_names(self, text: str) -> List[str]:
        seen: List[str] = []
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(\)?", text):
            name = m.group(1)
            if name not in seen and not name.startswith(("std::", "__")):
                seen.append(name)
            if len(seen) >= 14:
                break
        return seen

    def _interesting(self, strings_out: str) -> List[str]:
        hits = []
        for p, label in [
            (r"flag\{[^}]+\}", "flag pattern"),
            (r"(?i)password|secret|private[_ ]?key", "secret hint"),
            (r"(?i)admin|root|/bin/sh", "privilege hint"),
        ]:
            m = re.search(p, strings_out)
            if m:
                hits.append(label)
        return hits[:6]

    def _is_stripped(self, symbols_out: str) -> bool:
        # A fully stripped binary has almost no symbol lines from nm.
        lines = [l for l in symbols_out.splitlines() if l.strip() and "symbols unavailable" not in l.lower()]
        return len(lines) < 4

    def _libc_names(self, readelf_dynamic: str) -> List[str]:
        seen: List[str] = []
        for m in re.finditer(r"(libc\.so[^\s,]*|libstdc\+\+[^\s,]*|libm\.so[^\s,]*)", readelf_dynamic):
            name = m.group(1)
            if name not in seen:
                seen.append(name)
            if len(seen) >= 6:
                break
        return seen

    def _clean(self, text: str) -> str:
        text = " ".join(text.split())
        return text[:400]

    def _suggest_next(self, findings: List[str], evidence: EvidenceSnapshot) -> str:
        joined = " ".join(findings).lower()
        if any(f in joined for f in ("gets", "strcpy", "scanf", "buffer")):
            return "binary.buffer_overflow"
        if "printf" in joined or "format" in joined:
            return "binary.format_string"
        if any(f in joined for f in ("win", "flag", "ret2win")):
            return "binary.ret2win"
        if any(f in joined for f in ("system", "libc", "got", "plt", "rop")):
            return "binary.rop_analysis"
        if evidence.has_tool("binary_checksec", "binary_file_info"):
            return "binary.pwntools_runner"
        return ""
