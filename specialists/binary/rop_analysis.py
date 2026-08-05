"""Stage 7 ROP analysis specialist (spec 11).

Analyzes evidence for ROP preparation:

- simple ROP gadgets (pop rdi; ret, ret, ...)
- PLT and GOT entries
- libc usage and ret2libc preparation
- function-pointer corruption indicators
- GOT/PLT analysis (imported/exported functions)

All gadget addresses and entries must come from tool output
(pwn_find_gadgets / pwn_got_plt / readelf) - never invented.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "rop", "gadget", "pop rdi", "pop rsi", "ret", "plt", "got", "libc",
    "ret2libc", "system", "/bin/sh", "chain", "return-oriented",
    "function pointer", "vtable", "hook", "got entry", "mprotect",
]

COMMON_GADGETS = ["pop rdi; ret", "pop rsi; ret", "pop rdx; ret",
                  "pop rcx; ret", "ret", "pop rbp; ret", "leave; ret",
                  "pop rax; ret", "syscall; ret"]


class RopAnalysisSpecialist(Specialist):
    """Evidence-driven ROP preparation (spec 11)."""

    name = "binary.rop_analysis"
    category = "binary"
    description = "Find gadgets, PLT/GOT entries, and plan ret2libc chains."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text().lower()
        success_text = evidence.successful_output()

        # 1. Gadgets
        gadgets = self._gadgets(success_text)
        if gadgets:
            confirmed.append(f"ROP gadget(s) confirmed: {', '.join(gadgets[:6])}")
        else:
            steps.append("Run pwn_find_gadgets on the binary to locate simple gadgets.")

        # 2. PLT/GOT entries
        plt_got = self._plt_got(success_text)
        if plt_got:
            confirmed.append(
                f"PLT/GOT symbol(s): {', '.join(plt_got[:8])} - potential ret2plt/ret2got targets."
            )

        # 3. libc usage
        if "libc" in text or any(l in text for l in ("system", "puts", "printf", "strlen")):
            confirmed.append(
                "libc function usage detected - ret2libc candidate (needs a libc "
                "leak: puts@plt / printf@plt)."
            )
            steps.append(
                "Plan a leak: call puts@plt with a GOT entry, receive the address, "
                "then compute the libc base with the user-provided libc file."
            )

        # 4. Function-pointer corruption indicators
        fp_hits = [k for k in ("function pointer", "vtable", "hook", "printf", "atexit", "signal") if k in text]
        if fp_hits:
            confirmed.append(
                f"Function-pointer corruption surface(s): {', '.join(fp_hits[:5])}"
            )

        steps.append(
            "Validate the chain before sending: architecture, offset, gadget "
            "addresses, and argument values must come from tool output."
        )
        steps.append(
            "Prefer 64-bit chains with correct stack alignment (16-byte); include a "
            "bare 'ret' gadget if needed."
        )

        if not gadgets and not plt_got and not fp_hits:
            rejected.append("No ROP gadgets, PLT/GOT entries, or function-pointer surfaces found yet.")
            steps.append(
                "Run pwn_find_gadgets and pwn_got_plt on the local binary, and check "
                "symbols for libc imports (binary_symbols / binary_libraries)."
            )

        next_spec = "binary.pwntools_runner" if gadgets or plt_got else "binary.buffer_overflow"
        return self._result(
            evidence, profile,
            hypothesis="ROP may be needed to control arguments or call libc functions.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist=next_spec,
            summary="ROP analysis: " + (f"{len(gadgets)} gadget(s) confirmed" if gadgets
                                        else "no gadgets confirmed yet"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _gadgets(self, text: str) -> List[str]:
        found: List[str] = []
        for g in COMMON_GADGETS:
            if g in text:
                found.append(g)
        # pwn_find_gadgets report lines: "- pop rdi; ret @ 0x4011a6"
        for m in re.finditer(r"-\s*([A-Za-z0-9_ ;,%]+)\s*@\s*(0x[0-9a-fA-F]+)", text):
            gadget = m.group(1).strip()
            if gadget not in found and gadget in text:
                found.append(f"{gadget} @ {m.group(2)}")
        return found[:10]

    def _plt_got(self, text: str) -> List[str]:
        found: List[str] = []
        for m in re.finditer(r"(?:plt|got)\s*[:#]?\s*([A-Za-z_][A-Za-z0-9_]{2,30})", text):
            name = m.group(1)
            if name not in ("plt", "got", "entry", "entries") and name not in found:
                found.append(name)
            if len(found) >= 10:
                break
        return found
