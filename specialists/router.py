"""Stage 7 specialist router (spec 13).

Selects specialists based on challenge category, file type, page content,
error messages, parameters, imported binary functions, security
protections, and existing evidence.  Never runs every specialist blindly:
only specialists scoring at or above a threshold are suggested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from .base import EvidenceSnapshot, Specialist


@dataclass
class RankedSpecialist:
    """A specialist plus its relevance score and reason."""

    specialist: Specialist
    score: float
    reason: str

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.specialist.name} (score {self.score:.2f}: {self.reason})"


class SpecialistRouter:
    """Registry of specialists with deterministic relevance selection."""

    def __init__(
        self,
        min_score: float = 0.25,
        max_suggestions: int = 3,
    ):
        self.min_score = min_score
        self.max_suggestions = max_suggestions
        self._specialists: Dict[str, Specialist] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, specialist: Specialist) -> None:
        """Register a specialist instance by name."""
        self._specialists[specialist.name] = specialist

    def register_many(self, specialists: Sequence[Specialist]) -> None:
        """Register multiple specialists."""
        for s in specialists:
            self.register(s)

    def all(self) -> List[Specialist]:
        """All registered specialists."""
        return list(self._specialists.values())

    def get(self, name: str) -> Optional[Specialist]:
        """Get a specialist by name."""
        return self._specialists.get(name)

    def unregister(self, name: str) -> None:
        """Remove a specialist by name."""
        self._specialists.pop(name, None)

    # ------------------------------------------------------------------
    # Selection (spec 13)
    # ------------------------------------------------------------------

    def select(
        self,
        evidence: EvidenceSnapshot,
        profile: Optional[Dict[str, Any]] = None,
        used: Optional[Sequence[str]] = None,
    ) -> List[RankedSpecialist]:
        """Rank specialists by relevance to the evidence + profile.

        Parameters
        ----------
        evidence:
            Snapshot of current tool results.
        profile:
            Optional dict with challenge signals, e.g.
            ``{"challenge_type": "web", "file_path": "...", "page_content": "..."}``.
        used:
            Specialist names already attempted; they are ranked last.

        Returns
        -------
        List[RankedSpecialist]
            Specialists above ``min_score``, sorted by score descending,
            capped at ``max_suggestions``.
        """
        used_set = set(used or [])
        ranked: List[RankedSpecialist] = []
        for s in self._specialists.values():
            score = s.score(evidence, profile)
            if score < self.min_score:
                continue
            reason = self._reason(s, score)
            if s.name in used_set:
                score -= 0.5  # de-prioritize already-attempted specialists
                if score < self.min_score:
                    continue
                reason = f"already attempted; {reason}"
            ranked.append(RankedSpecialist(specialist=s, score=round(score, 3), reason=reason))

        ranked.sort(key=lambda r: (r.score, r.specialist.name), reverse=True)
        return ranked[: self.max_suggestions]

    def suggest_next(
        self,
        evidence: EvidenceSnapshot,
        profile: Optional[Dict[str, Any]] = None,
        used: Optional[Sequence[str]] = None,
    ) -> Optional[RankedSpecialist]:
        """Return the single best next specialist, or None."""
        selected = self.select(evidence, profile, used=used)
        return selected[0] if selected else None

    def _reason(self, specialist: Specialist, score: float) -> str:
        """Human-readable selection reason."""
        hits = [s for s in specialist.signals if s]
        if score >= 0.6:
            return "strong evidence signals"
        if score >= 0.4:
            return "multiple matching signals"
        return "category match / weak signals"

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def list_specialists(self) -> str:
        """Render all registered specialists grouped by category."""
        web = [s for s in self._specialists.values() if s.category == "web"]
        binary = [s for s in self._specialists.values() if s.category == "binary"]
        lines = ["Registered specialists:", "-" * 50]
        lines.append(f"Web ({len(web)}):")
        for s in sorted(web, key=lambda x: x.name):
            lines.append(f"  {s.name:42s} - {s.description[:60]}")
        lines.append(f"Binary ({len(binary)}):")
        for s in sorted(binary, key=lambda x: x.name):
            lines.append(f"  {s.name:42s} - {s.description[:60]}")
        return "\n".join(lines)
