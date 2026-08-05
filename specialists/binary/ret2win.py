"""Stage 7 ret2win specialist (spec 11).

Analyzes evidence for ret2win preparation:

- finding win / flag-printing functions
- finding useful symbols
- PLT/GOT entries
- architecture, offset, target address, endianness, calling convention,
  stack alignment
- building a validated payload plan

Payloads are only planned for the current authorized challenge binary.
Addresses are never invented - they must come from tool output.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "ret2win", "win", "flag", "print_flag", "get_flag", "ret", "return",
    "system", "plt", "got", "offset", "padding", "payload", "address",
    "ret2libc", "calling convention", "alignment",
]

ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]{6,16}\b")


class Ret2winSpecialist(Specialist):
    """Evidence-driven ret2win preparation (spec 11)."""

    name = "binary.ret2win"
    category = "binary"
    description = "Find win functions and build a validated ret2win payload plan."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text().lower()
        success_text = evidence.successful_output()

        # 1. Win function identification
        win = self._win_function(success_text)
        if win:
            name, addr = win
            confirmed.append(f"Win/flag function identified: {name} @ {addr}")
        else:
            hints = [h for h in ("win", "flag", "print_flag", "get_flag", "shell", "ret2win") if h in text]
            if hints:
                confirmed.append(
                    f"Win-function hint(s) present but no address confirmed yet: {', '.join(hints[:4])}"
                )

        # 2. Architecture / endianness / offset
        arch = self._arch(text)
        if arch:
            confirmed.append(f"Architecture: {arch}")
        offset = self._offset(text)
        if offset is not None:
            confirmed.append(f"Overwrite offset: {offset} bytes")

        # 3. Useful symbols / PLT-GOT
        if "plt" in text or "got" in text:
            confirmed.append("PLT/GOT references present (see pwn_got_plt for entries).")

        # 4. Calling convention / alignment guidance
        if arch:
            cc = "SysV (rdi, rsi, rdx, rcx, r8, r9)" if "64" in arch else "cdecl (stack)"
            confirmed.append(f"Calling convention: {cc}")
            if "64" in arch:
                confirmed.append(
                    "x86-64 requires 16-byte stack alignment before the call - "
                    "add a bare 'ret' gadget if needed."
                )

        # 5. Payload plan - only when every required fact is confirmed
        plan = self._payload_plan(win, offset, arch)
        if plan:
            confirmed.append(plan)
        else:
            steps.append(
                "Gather the missing facts: pwn_find_win_function (address), "
                "pwn_crash_analyze (offset), pwn_elf_info (arch/endianness)."
            )

        steps.append(
            "Validate before sending: architecture, offset, target address, "
            "endianness, required arguments, and payload length must all come from "
            "tool output - never invent addresses."
        )
        steps.append(
            "Build the payload with pwn_pack(value, bits, endianness); verify the "
            "offset with pwn_verify_offset on the local binary first."
        )

        if not win and offset is None:
            rejected.append("No win function or offset confirmed in evidence yet.")

        next_spec = "binary.rop_analysis" if "ret2libc" in text or "system" in text or "libc" in text else ""
        return self._result(
            evidence, profile,
            hypothesis="The binary likely has a win function reachable by redirecting control flow.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist=next_spec,
            summary="Ret2win: " + (f"{win[0]} @ {win[1]}" if win else "win function not confirmed yet"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _win_function(self, text: str) -> Optional[tuple]:
        """Find (name, address) of a likely win function from nm/strings output.

        The address is normalized to 0x-prefixed lowercase hex.
        """
        # nm -C style lines: "00000000004011a6 T win"
        for m in re.finditer(
            r"\b(0x)?([0-9a-fA-F]{6,16})\s+[TtWw]\s+([A-Za-z_][A-Za-z0-9_]*)",
            text,
        ):
            name = m.group(3)
            if re.search(r"(win|flag|shell|victory|ret2win)", name, re.IGNORECASE):
                addr = int(m.group(2), 16)
                return name, hex(addr)
        for name in ("win", "flag", "print_flag", "get_flag", "shell", "victory", "ret2win"):
            m = re.search(rf"\b(0x[0-9a-fA-F]{{6,16}})\s+\S+\s+{name}\b", text)
            if m:
                return name, m.group(1).lower()
        return None

    def _arch(self, text: str) -> str:
        m = re.search(r"(\d{2})-bit\s*(LSB|MSB)?", text)
        if not m:
            return ""
        bits = m.group(1)
        endian = " little-endian" if m.group(2) == "LSB" else (" big-endian" if m.group(2) else "")
        return f"{bits}-bit{endian}".strip()

    def _offset(self, text: str) -> Optional[int]:
        m = re.search(r"overwrite offset:\s*(\d+)", text)
        if m:
            return int(m.group(1))
        m = re.search(r"offset\s*=\s*(\d+)", text)
        return int(m.group(1)) if m else None

    def _payload_plan(self, win: Optional[tuple], offset: Optional[int], arch: str) -> str:
        if not win or offset is None or not arch:
            return ""
        bits = 64 if "64" in arch else 32
        endian = "little" if "little" in arch else "big"
        addr = win[1] if win[1].startswith("0x") else hex(int(win[1], 16))
        return (
            f"Payload plan: {offset} bytes of padding, then pwn_pack({addr}, "
            f"bits={bits}, endianness='{endian}') -> {win[0]} "
            f"(validate stack alignment for x86-64)."
        )
