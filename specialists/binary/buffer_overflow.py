"""Stage 7 stack buffer overflow specialist (specs 7, 10, 11).

Analyzes evidence (triage output / crash analysis) for stack overflow
surfaces: unsafe input functions, disabled protections, architecture and
endianness, and crash-derived offsets.  Produces a payload plan only when
architecture, offset, target address, endianness, and payload length are
all known and validated - addresses are never invented.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "buffer overflow", "stack", "gets", "strcpy", "strcat", "scanf",
    "overflow", "offset", "cyclic", "segfault", "canary", "nx", "pie",
    "ret2win", "ret2libc", "smash", "payload", "eip", "rip", "rsp",
    "input length", "read(", "fgets",
]

PROTECTION_HINTS = {
    "canary": ["canary", "stack-protector"],
    "nx": ["nx", "noexec", "non-executable"],
    "pie": ["pie", "position-independent", "aslr"],
    "relro": ["relro"],
    "fortify": ["fortify"],
}


class BufferOverflowSpecialist(Specialist):
    """Evidence-driven stack buffer overflow workflow (specs 7/10/11)."""

    name = "binary.buffer_overflow"
    category = "binary"
    description = "Analyze overflow surfaces, protections, crash offsets, and build a validated payload plan."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text().lower()
        success_text = evidence.successful_output()

        # 1. Unsafe input functions (from triage/symbols/strings)
        input_hits = [f for f in ("gets", "strcpy", "strcat", "sprintf", "scanf", "read(", "fgets") if f in text]
        if input_hits:
            confirmed.append(
                f"Unsafe/input function(s) referenced: {', '.join(input_hits[:6])} - "
                "potential overflow sink."
            )

        # 2. Protections from checksec/readelf evidence
        protections = self._protections(text)
        if protections:
            confirmed.append(f"Security protections observed: {protections}")
            if "NX disabled" in protections:
                confirmed.append("NX disabled - executable stack/shellcode is a candidate (validate first).")
            if "canary: none" in protections or "canary absent" in protections:
                confirmed.append("No stack canary detected - direct return-address overwrite may work.")
        else:
            steps.append("Gather protections first: binary_checksec or analyze_binary.")

        # 3. Architecture / endianness
        arch = self._arch(text)
        if arch:
            confirmed.append(f"Architecture/endianness: {arch}")

        # 4. Crash / offset evidence
        offset = self._offset(text)
        if offset is not None:
            confirmed.append(
                f"Crash-derived overwrite offset: {offset} bytes "
                "(from pwn_crash_analyze / cyclic analysis)."
            )

        # 5. Build payload plan when all required facts are known
        plan = self._payload_plan(arch, offset, success_text)
        if plan:
            confirmed.append(plan)

        steps.append(
            "If the offset is unknown, run pwn_crash_analyze on the local challenge "
            "binary (cyclic input -> crash -> offset) then pwn_verify_offset."
        )
        steps.append(
            "Determine the target: win function (pwn_find_win_function) or libc "
            "address (pwn_got_plt + pwn_find_gadgets)."
        )
        steps.append(
            "Build the payload with pwn_pack using the confirmed offset, target "
            "address, and endianness; validate length and alignment before sending."
        )
        steps.append(
            "Never invent addresses or offsets - every value must come from tool output."
        )

        if not input_hits and offset is None:
            rejected.append(
                "No unsafe input function or crash-offset evidence yet."
            )
            steps.append(
                "Run binary.triage first (or analyze_binary) to identify input "
                "functions and protections."
            )

        next_spec = self._next_specialist(plan, text)
        return self._result(
            evidence, profile,
            hypothesis="A stack buffer overflow may allow controlling the return address.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist=next_spec,
            summary="Buffer overflow: " + (f"offset {offset} confirmed" if offset is not None
                                           else "no offset confirmed yet"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _protections(self, text: str) -> str:
        parts: List[str] = []
        for label, keys in PROTECTION_HINTS.items():
            hits = [k for k in keys if k in text]
            if hits:
                parts.append(f"{label}: present")
        if not parts:
            return ""
        joined = ", ".join(parts)
        if "canary" not in joined and "canary: none" not in text:
            joined += "; canary: none detected"
        if "nx" not in joined:
            joined += "; nx: not mentioned"
        return joined

    def _arch(self, text: str) -> str:
        m = re.search(r"(\d{2})-bit(\s+(LSB|MSB))?", text)
        if not m:
            return ""
        bits = m.group(1)
        endian = " little-endian" if (m.group(3) or "").upper() == "LSB" else (" big-endian" if m.group(3) else "")
        return f"{bits}-bit{endian}"

    def _offset(self, text: str) -> Optional[int]:
        m = re.search(r"offset\s*(?:=|:)?\s*(\d+)", text)
        if m:
            return int(m.group(1))
        # pwn_crash_analyze report format: "Overwrite offset: N bytes"
        m = re.search(r"overwrite offset:\s*(\d+)", text)
        return int(m.group(1)) if m else None

    def _payload_plan(self, arch: str, offset: Optional[int], success_text: str) -> str:
        if offset is None or not arch:
            return ""
        addr = re.search(r"(?:win|flag|target).{0,20}(?:0x[0-9a-fA-F]+)", success_text)
        if not addr:
            return ""
        bits = 64 if "64-bit" in arch else 32
        endian = "little" if "little" in arch else "big"
        return (
            f"Payload plan validated: offset={offset}, arch={bits}-bit {endian}, "
            f"target address {addr.group(0)[-20:]}; "
            "use pwn_pack(value, bits, endianness) to encode."
        )

    def _next_specialist(self, plan: str, text: str) -> str:
        if plan:
            return "binary.pwntools_runner"
        if "system" in text or "libc" in text or "got" in text or "plt" in text:
            return "binary.rop_analysis"
        if "win" in text or "flag" in text:
            return "binary.ret2win"
        return "binary.ret2win"
