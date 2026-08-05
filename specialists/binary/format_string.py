"""Stage 7 format-string specialist (spec 12).

Analyzes evidence for uncontrolled format strings:

- printf-family usage with user-controlled data
- literal vs formatted output differences (e.g. %x/%p leaks in responses)
- likely stack offsets
- readable addresses
- writable targets

Starts with non-destructive read checks (%p / %x).  Arbitrary memory
modification (%n) is only recommended when required by the authorized CTF
challenge.  Every confirmed observation is recorded with evidence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "format string", "printf", "sprintf", "snprintf", "fprintf", "vprintf",
    "%x", "%p", "%n", "%s", "format", "leak", "uncontrolled format",
    "user-controlled format", "stack offset",
]

LEAK_MARKERS = [
    "0x7f", "0x55", "0x40", "0x41414141", "0xffff", "0x00007fff",
    "\\x", "segmentation", "stack", "aaaa",
]


class FormatStringSpecialist(Specialist):
    """Evidence-driven format-string workflow (spec 12)."""

    name = "binary.format_string"
    category = "binary"
    description = "Detect uncontrolled format strings and plan non-destructive read checks."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text().lower()
        success_text = evidence.successful_output()

        # 1. printf-family usage
        fmt_funcs = [f for f in ("printf", "sprintf", "snprintf", "fprintf", "vprintf") if f in text]
        if fmt_funcs:
            confirmed.append(
                f"Format-function usage: {', '.join(fmt_funcs[:5])} - check whether "
                "the format string is user-controlled."
            )

        # 2. Format specifiers applied / leaked
        if "%x" in text or "%p" in text or "%n" in text:
            confirmed.append("Format specifier(s) applied in probes (%x / %p / %n).")
        leaks = self._leaks(success_text)
        if leaks:
            confirmed.append(
                f"Memory leak pattern(s) in output: {', '.join(leaks[:5])} - "
                "consistent with formatted read of stack contents."
            )

        # 3. Compare literal vs formatted output (guidance from evidence)
        if evidence.has_tool("pwn_format_string_analysis", "pwn_session_recv"):
            confirmed.append("Format-string probe tool output recorded - compare literal vs formatted echo.")

        steps.append(
            "Start with non-destructive read checks: send 'AAAA%p.%p.%p...' (or "
            "'%x') and observe whether stack values leak."
        )
        steps.append(
            "Determine the argument offset: increment the positional specifier "
            "(%1$p, %2$p, ...) and map which index points at your input."
        )
        steps.append(
            "Only after the read side is confirmed, and only if the authorized "
            "challenge requires it, plan a single targeted %n write - never spray "
            "%n across the stack."
        )
        steps.append(
            "Record each confirmed observation (index, leaked value) as evidence."
        )

        if not fmt_funcs and not leaks:
            rejected.append("No format-function or leak evidence found yet.")
            steps.append(
                "Run binary.triage / pwn_format_string_analysis to check for "
                "printf-family imports and user-controlled format usage."
            )

        next_spec = "binary.ret2win" if "ret2win" in text or "win" in text else "binary.rop_analysis"
        return self._result(
            evidence, profile,
            hypothesis="A user-controlled format string may allow reading or writing memory.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist=next_spec,
            summary="Format string: " + ("leak evidence found" if leaks else "no leak confirmed yet"),
        )

    def _leaks(self, text: str) -> List[str]:
        found: List[str] = []
        for m in re.finditer(r"(0x[0-9a-fA-F]{4,16})", text):
            val = m.group(1)
            if val not in found:
                found.append(val)
            if len(found) >= 5:
                break
        return found
