"""Stage 7 race-condition challenge specialist.

Identifies race-condition challenge patterns: state-changing endpoints
that lack per-request session binding, coupon/balance/order logic, and
single-use actions.  Recommends careful concurrent testing only when the
user provided the authorized target.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "race", "concurrent", "parallel", "coupon", "balance", "discount",
    "checkout", "order", "single use", "redeem", "voucher", "gift",
    "free", "transfer", "claim", "same request", "simultaneous",
]


class RaceConditionSpecialist(Specialist):
    """Evidence-driven race-condition pattern analysis."""

    name = "web.race_condition"
    category = "web"
    description = "Spot race-condition patterns in state-changing endpoints."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text().lower()

        pattern_hits = [s for s in SIGNALS if s in text and len(s) > 3]
        if pattern_hits:
            confirmed.append(
                f"Race-prone feature signal(s): {', '.join(pattern_hits[:6])} - "
                "likely a state-changing (non-idempotent) endpoint."
            )

        if evidence.has_tool("http_post"):
            confirmed.append("POST endpoints observed - candidates for concurrent duplicate testing.")

        steps.append(
            "Only test on the user-provided authorized target; send a small number "
            "of concurrent identical requests (2-5) for a single-use action and "
            "compare how many succeed."
        )
        steps.append(
            "Record status codes and state changes for each response; a race is "
            "only confirmed when tool output shows the state mutated more times "
            "than allowed."
        )
        steps.append(
            "Do not perform load-testing / flooding; keep concurrency minimal and "
            "bounded by the resource limits."
        )

        if not pattern_hits:
            rejected.append(
                "No race-prone feature signals (coupon/balance/claim/order logic) in evidence yet."
            )
            steps.append(
                "Look for single-use or state-mutating endpoints in the application "
                "description, forms, and JavaScript first."
            )

        return self._result(
            evidence, profile,
            hypothesis="A state-changing endpoint may be vulnerable to a race condition.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist="web.authentication",
            summary="Race condition: " + ("pattern signals found" if pattern_hits else "none yet"),
        )
