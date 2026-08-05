"""Stage 7 specialist framework - structured results and base classes.

Spec 15 (Evidence and Confirmation Rules):

- Every specialist returns a structured :class:`SpecialistResult`.
- A flag is confirmed only when it appears directly in a successful
  tool result (file read, program output, HTTP response, decoded data,
  database output from an authorized challenge, or another tool result).
- Specialists never reconstruct or guess a partial flag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Same flag pattern as the Stage 6 evidence log.
FLAG_PATTERN = re.compile(r"flag\{[^}\n]{1,200}\}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Evidence view
# ---------------------------------------------------------------------------

class EvidenceSnapshot:
    """Read-only view over recorded tool results for specialist analysis.

    Each item is expected to expose: ``tool``, ``output``, ``success``,
    and optionally ``arguments``.  Specialists only ever derive confirmed
    observations from successful tool output.
    """

    def __init__(self, items: Optional[Sequence[Any]] = None):
        self._items = list(items or [])

    def items(self) -> List[Any]:
        """Return a copy of all items."""
        return list(self._items)

    def successful(self) -> List[Any]:
        """Return only successful tool results."""
        return [i for i in self._items if getattr(i, "success", False)]

    def all_output(self) -> str:
        """Concatenated output of all items (including failures)."""
        return "\n".join(
            str(getattr(i, "output", "") or "") for i in self._items
        )

    def successful_output(self) -> str:
        """Concatenated output of successful items only."""
        return "\n".join(
            str(getattr(i, "output", "") or "") for i in self.successful()
        )

    def has_tool(self, *names: str) -> bool:
        """True when any of *names* was used as a tool."""
        used = {getattr(i, "tool", "") for i in self._items}
        return any(n in used for n in names)

    def outputs_for(self, *names: str) -> List[str]:
        """Outputs of items whose tool name is in *names*."""
        return [
            str(getattr(i, "output", "") or "")
            for i in self._items
            if getattr(i, "tool", "") in names
        ]

    def flags(self) -> List[str]:
        """Deduplicated flags found in successful tool output."""
        seen: List[str] = []
        for item in self.successful():
            m = FLAG_PATTERN.search(str(getattr(item, "output", "") or ""))
            if m and m.group(0) not in seen:
                seen.append(m.group(0))
        return seen

    def flag_status(self) -> Tuple[str, Optional[str]]:
        """Return (status, flag_value) following Stage 6 semantics."""
        confirmed = self.flags()
        if confirmed:
            return "confirmed", confirmed[0]
        return "not_confirmed", None

    def text(self) -> str:
        """Full signal text (tool names + outputs + arguments) for scoring."""
        parts: List[str] = []
        for item in self._items:
            parts.append(getattr(item, "tool", ""))
            args = getattr(item, "arguments", None)
            if isinstance(args, dict):
                parts.append(str(args))
            out = str(getattr(item, "output", "") or "")[:2000]
            if out:
                parts.append(out)
        return "\n".join(parts)


def make_items(records: List[Dict[str, Any]]) -> List[Any]:
    """Build lightweight evidence items from plain dicts.

    Used by tests and callers that do not have real evidence log items::

        make_items([
            {"tool": "http_post", "output": "SQL syntax error", "success": True},
        ])
    """
    items: List[Any] = []
    for r in records:
        items.append(
            type(
                "E",
                (),
                {
                    "tool": r.get("tool", ""),
                    "output": r.get("output", ""),
                    "success": bool(r.get("success", True)),
                    "arguments": r.get("arguments", {}) or {},
                },
            )()
        )
    return items


# ---------------------------------------------------------------------------
# Structured result (spec 15)
# ---------------------------------------------------------------------------

@dataclass
class SpecialistResult:
    """Structured result returned by every specialist.

    Attributes
    ----------
    specialist:
        Specialist identifier (e.g. ``web.sql_injection``).
    hypothesis:
        The hypothesis this specialist investigated.
    tools_used:
        Tools whose results were inspected.
    confirmed_observations:
        Evidence-backed observations (each traceable to tool output).
    rejected_hypotheses:
        Hypotheses that the evidence did not support.
    raw_evidence:
        Short excerpts of the exact tool output behind the findings.
    flag_status:
        ``"confirmed"`` or ``"not_confirmed"``.
    flag_value:
        The confirmed flag value, or None.
    suggested_next_specialist:
        Identifier of the specialist to try next, or "".
    recommended_steps:
        Low-risk, read-only verification steps for the agent loop.
    relevance:
        Router relevance score in [0, 1].
    summary:
        One-line human summary.
    """

    specialist: str
    hypothesis: str
    tools_used: List[str] = field(default_factory=list)
    confirmed_observations: List[str] = field(default_factory=list)
    rejected_hypotheses: List[str] = field(default_factory=list)
    raw_evidence: List[str] = field(default_factory=list)
    flag_status: str = "not_confirmed"
    flag_value: Optional[str] = None
    suggested_next_specialist: str = ""
    recommended_steps: List[str] = field(default_factory=list)
    relevance: float = 0.0
    summary: str = ""

    def to_report(self) -> str:
        """Render the structured result as a readable report."""
        lines = [
            f"### Specialist: {self.specialist}",
            f"Hypothesis: {self.hypothesis}",
            f"Relevance: {self.relevance:.0%}",
            "",
            "Confirmed observations:",
        ]
        if self.confirmed_observations:
            lines.extend(f"- {o}" for o in self.confirmed_observations)
        else:
            lines.append("- (none yet - evidence does not support this technique)")

        lines.append("")
        lines.append("Rejected hypotheses:")
        if self.rejected_hypotheses:
            lines.extend(f"- {h}" for h in self.rejected_hypotheses)
        else:
            lines.append("- (none)")

        if self.raw_evidence:
            lines.append("")
            lines.append("Important raw evidence:")
            lines.extend(f"- {e[:300]}" for e in self.raw_evidence[:5])

        lines.append("")
        lines.append(f"Flag status: {self.flag_status}")
        if self.flag_value:
            lines.append(f"Flag value: `{self.flag_value}`")

        if self.recommended_steps:
            lines.append("")
            lines.append("Recommended low-risk verification steps:")
            lines.extend(f"- {s}" for s in self.recommended_steps[:8])

        if self.suggested_next_specialist:
            lines.append("")
            lines.append(f"Suggested next specialist: {self.suggested_next_specialist}")

        if self.summary:
            lines.append("")
            lines.append(f"Summary: {self.summary}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Base specialist
# ---------------------------------------------------------------------------

class Specialist:
    """Base class for all Stage 7 specialists.

    Subclasses set :attr:`name`, :attr:`category`, :attr:`description` and
    :attr:`signals`, then implement :meth:`run`.  Relevance scoring is
    deterministic keyword scoring over the evidence text plus the challenge
    profile.
    """

    name = "base"
    category = "web"          # "web" | "binary"
    description = ""
    signals: List[str] = []   # relevance keywords (lower-case matching)

    def __init__(self, min_score: float = 0.0):
        self.min_score = min_score

    # ------------------------------------------------------------------
    # Relevance
    # ------------------------------------------------------------------

    def score(
        self,
        evidence: EvidenceSnapshot,
        profile: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Return relevance in [0, 1].

        Scoring combines keyword hits in the evidence text with a small
        bonus when the specialist category matches the detected challenge
        type.  Pure keyword scoring keeps selection deterministic.
        """
        if not self.signals:
            return 0.0
        profile = profile or {}
        text = evidence.text().lower()
        profile_text = " ".join(str(v) for v in profile.values()).lower()
        haystack = f"{text}\n{profile_text}"
        hits = sum(1 for s in self.signals if s.lower() in haystack)
        cat_bonus = 0.15 if profile.get("challenge_type") == self.category else 0.0
        ratio = hits / max(len(self.signals), 1)
        return round(min(1.0, ratio * 0.85 + cat_bonus), 3)

    def relevant(
        self,
        evidence: EvidenceSnapshot,
        profile: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """True when the specialist is relevant enough to consider."""
        return self.score(evidence, profile) >= self.min_score

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(
        self,
        evidence: EvidenceSnapshot,
        profile: Optional[Dict[str, Any]] = None,
    ) -> SpecialistResult:
        """Analyze evidence and return a structured result.

        Subclasses implement this.  The default returns an empty result so
        an unregistered specialist never crashes the router.
        """
        status, value = evidence.flag_status()
        return SpecialistResult(
            specialist=self.name,
            hypothesis=self.description,
            flag_status=status,
            flag_value=value,
            relevance=self.score(evidence, profile),
            summary="Specialist is not implemented.",
        )

    # ------------------------------------------------------------------
    # Helpers for subclasses
    # ------------------------------------------------------------------

    def _evidence_excerpts(self, evidence: EvidenceSnapshot, limit: int = 4) -> List[str]:
        """Short excerpts of successful tool output for raw evidence."""
        excerpts: List[str] = []
        for item in evidence.successful():
            out = " ".join(str(getattr(item, "output", "") or "").split())
            if not out:
                continue
            excerpts.append(f"[{getattr(item, 'tool', '')}] {out[:200]}")
            if len(excerpts) >= limit:
                break
        return excerpts

    def _result(
        self,
        evidence: EvidenceSnapshot,
        profile: Optional[Dict[str, Any]],
        hypothesis: str,
        confirmed: List[str],
        rejected: List[str],
        steps: List[str],
        next_specialist: str = "",
        summary: str = "",
        raw_evidence: Optional[List[str]] = None,
    ) -> SpecialistResult:
        """Build a SpecialistResult with consistent flag handling."""
        status, value = evidence.flag_status()
        return SpecialistResult(
            specialist=self.name,
            hypothesis=hypothesis,
            tools_used=sorted({getattr(i, "tool", "") for i in evidence.items()}),
            confirmed_observations=confirmed,
            rejected_hypotheses=rejected,
            raw_evidence=raw_evidence if raw_evidence is not None else self._evidence_excerpts(evidence),
            flag_status=status,
            flag_value=value,
            suggested_next_specialist=next_specialist,
            recommended_steps=steps,
            relevance=self.score(evidence, profile),
            summary=summary or "; ".join(confirmed[:2]),
        )


def find_substrings(text: str, patterns: List[str], flags: int = re.IGNORECASE) -> List[str]:
    """Return deduplicated case-insensitive matches of *patterns* in *text*."""
    low = text.lower()
    found: List[str] = []
    for p in patterns:
        if p.lower() in low and p not in found:
            found.append(p)
    return found


def regex_matches(text: str, pattern: str, limit: int = 6) -> List[str]:
    """Return deduplicated regex matches (used to pull tokens from output)."""
    seen: List[str] = []
    for m in re.finditer(pattern, text, re.IGNORECASE):
        value = m.group(0)
        if value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return seen
