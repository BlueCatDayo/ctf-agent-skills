"""Stage 7 pwntools runner specialist (spec 9).

Optional pwntools integration.  This specialist reports whether pwntools
is available and recommends safe usage patterns.  Actual process/socket
interaction is performed by the ``pwn_session_*`` tools, which:

- launch local processes only inside the configured challenge workspace;
- connect only to a user-provided authorized CTF host and port;
- apply timeouts and clean session termination.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "pwntools", "pwn", "process", "remote", "sendline", "recvuntil",
    "cyclic", "cyclic_find", "elf", "rop", "pack", "unpack", "offset",
    "exploit", "host", "port", "interactive",
]


class PwntoolsRunnerSpecialist(Specialist):
    """Evidence-driven pwntools usage guidance (spec 9)."""

    name = "binary.pwntools_runner"
    category = "binary"
    description = "Use optional pwntools for process/session interaction, packing, and offsets."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []

        try:
            from tools.pwn_session import pwntools_available, pwntools_status
            available = pwntools_available()
            confirmed.append(pwntools_status())
        except Exception as e:
            available = False
            confirmed.append(f"pwntools check failed: {e}")

        if available:
            confirmed.append(
                "pwntools is available: pwn_session_start (local process or "
                "user-provided remote host:port), pwn_session_send, "
                "pwn_session_recv, pwn_session_close."
            )
            steps.append(
                "For a local binary: pwn_session_start local=challenge_bin, then "
                "send cyclic input and receive the crash output."
            )
            steps.append(
                "For a remote challenge: pwn_session_start remote host=... port=... "
                "ONLY with the user-provided authorized host and port."
            )
        else:
            rejected.append(
                "pwntools is not installed - the pwn_* helpers (cyclic, pack, "
                "unpack, crash offset) still work in pure Python; install with "
                "'pip install pwntools' for process/socket automation."
            )
            steps.append(
                "Use pwn_cyclic / pwn_cyclic_find / pwn_crash_analyze (pure Python) "
                "for offset discovery without pwntools."
            )

        steps.append(
            "Always apply timeouts and close the session after use (pwn_session_close)."
        )
        steps.append(
            "Never connect to arbitrary targets - only the user-provided authorized "
            "CTF host and port."
        )

        return self._result(
            evidence, profile,
            hypothesis="Automating interaction with the challenge binary/remote may speed up exploitation.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist="binary.buffer_overflow",
            summary="pwntools: " + ("available" if available else "not installed (pure-Python helpers work)"),
        )
