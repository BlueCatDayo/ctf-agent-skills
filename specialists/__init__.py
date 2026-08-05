"""Stage 7 - CTF Specialist Knowledge.

Modular, evidence-driven specialist workflows for medium/hard Web
Exploitation and Binary Exploitation challenges.

A specialist is a deterministic analysis module for one technique
(SQL injection, ret2win, format strings, ...).  Specialists:

- Inspect available evidence (tool results) and decide whether the
  technique is relevant.
- Never declare a vulnerability without repeatable evidence.
- Recommend only low-risk, read-only verification steps.
- Return structured results (Stage 7 spec 15).
- Stop as soon as a flag is confirmed in successful tool output.

The package layout mirrors the Stage 7 spec section 13::

    specialists/
        base.py            # SpecialistResult + Specialist base + evidence view
        limits.py          # loop/resource limits (spec 16)
        router.py          # specialist selection router (spec 13)
        web/               # web exploitation specialists
        binary/            # binary exploitation specialists
"""

from .base import EvidenceSnapshot, Specialist, SpecialistResult, make_items
from .limits import ResourceLimits
from .router import RankedSpecialist, SpecialistRouter

__all__ = [
    "EvidenceSnapshot",
    "Specialist",
    "SpecialistResult",
    "ResourceLimits",
    "RankedSpecialist",
    "SpecialistRouter",
    "make_items",
]
