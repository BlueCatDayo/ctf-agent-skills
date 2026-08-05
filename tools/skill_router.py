"""Skill router — deterministic scoring and selection of relevant skills."""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .skill_loader import SkillContent, SkillMetadata


# Scoring weights
WEIGHT_CATEGORY = 3.0
WEIGHT_TRIGGER_KEYWORD = 2.0
WEIGHT_CHALLENGE_TYPE = 2.0
WEIGHT_DESCRIPTION = 1.0
WEIGHT_FILENAME = 1.5
WEIGHT_EXTENSION = 1.0
WEIGHT_TOOL_AVAILABLE = 0.5
WEIGHT_REQUIRED_TOOL = 1.0
WEIGHT_USER_REQUEST = 1.5
WEIGHT_METADATA_HOST = 1.0

# Precedence: core safety > tool security > user request > bundled > downloaded
TRUST_BUNDLED = 10
TRUST_DOWNLOADED = 1


@dataclass
class SkillSelection:
    """Result of routing: a selected skill with its score and reason."""

    skill: SkillContent
    score: float
    reason: str


@dataclass
class RouterResult:
    """Result of skill routing."""

    selected: List[SkillSelection] = field(default_factory=list)
    total_score: float = 0.0
    debug_log: List[str] = field(default_factory=list)


def _normalize(text: str) -> str:
    """Normalize text for case-insensitive matching."""
    return text.lower().strip()


def _tokenize(text: str) -> List[str]:
    """Split text into lowercase tokens."""
    import re

    return re.findall(r"[a-z0-9_+-]+", text.lower())


class SkillRouter:
    """Deterministic skill router that scores and selects relevant skills."""

    def __init__(
        self,
        skill_dir: str = "skills",
        max_active_skills: int = 5,
        min_score: float = 0.3,
        auto_selection: bool = True,
    ):
        self._skill_dir = skill_dir
        self._max_active_skills = max_active_skills
        self._min_score = min_score
        self._auto_selection = auto_selection
        self._active_identifiers: List[str] = []
        self._last_selection_debug: List[str] = []

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @property
    def max_active_skills(self) -> int:
        return self._max_active_skills

    @max_active_skills.setter
    def max_active_skills(self, value: int) -> None:
        self._max_active_skills = max(value, 0)

    @property
    def min_score(self) -> float:
        return self._min_score

    @property
    def auto_selection(self) -> bool:
        return self._auto_selection

    @auto_selection.setter
    def auto_selection(self, value: bool) -> None:
        self._auto_selection = value

    @property
    def active_identifiers(self) -> List[str]:
        """Return the identifiers of currently active skills."""
        return list(self._active_identifiers)

    # ------------------------------------------------------------------
    # Manual selection
    # ------------------------------------------------------------------

    def activate_skill(self, identifier: str, registry) -> Tuple[bool, str]:
        """Manually activate a skill by identifier."""
        skill = registry.get_skill(identifier)
        if skill is None:
            return False, f"Unknown skill identifier: '{identifier}'"
        if identifier not in self._active_identifiers:
            self._active_identifiers.append(identifier)
        return True, f"Activated skill '{identifier}'"

    def deactivate_skill(self, identifier: str) -> Tuple[bool, str]:
        """Deactivate a manually selected skill."""
        if identifier in self._active_identifiers:
            self._active_identifiers.remove(identifier)
            return True, f"Deactivated skill '{identifier}'"
        return False, f"Skill '{identifier}' is not active"

    def clear_manual(self) -> None:
        """Clear all manually selected skills."""
        self._active_identifiers.clear()

    def set_mode(self, auto: bool) -> str:
        """Enable or disable automatic skill routing."""
        self._auto_selection = auto
        return "Auto skill selection enabled" if auto else "Skill usage disabled"

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_skill(
        self,
        skill: SkillContent,
        challenge_category: str = "",
        user_request: str = "",
        filenames: Optional[List[str]] = None,
        file_extensions: Optional[List[str]] = None,
        http_observations: Optional[List[str]] = None,
        tool_results: Optional[List[str]] = None,
        challenge_description: str = "",
        available_tools: Optional[List[str]] = None,
        registry=None,
    ) -> Tuple[float, str]:
        """Score a skill deterministically against the current context.

        Returns (score, reason_string).
        """
        score = 0.0
        reasons: List[str] = []
        m = skill.metadata
        norm_request = _normalize(user_request)
        norm_desc = _normalize(challenge_description)
        norm_category = _normalize(challenge_category)

        # 1. Category match
        if norm_category and _normalize(m.category) == norm_category:
            score += WEIGHT_CATEGORY
            reasons.append("category match")

        # 2. Challenge type match
        for ct in m.applicable_challenge_types:
            if norm_category and _normalize(ct) == norm_category:
                score += WEIGHT_CHALLENGE_TYPE
                reasons.append(f"challenge type '{ct}'")
                break

        # 3. Trigger keyword match (against user request + description)
        combined_text = f"{norm_request} {norm_desc}"
        for kw in m.trigger_keywords:
            if _normalize(kw) in combined_text:
                score += WEIGHT_TRIGGER_KEYWORD
                reasons.append(f"trigger keyword '{kw}'")
                break  # count once per skill

        # 4. User request keyword match
        tokens = set(_tokenize(norm_request))
        for kw in m.trigger_keywords:
            kw_tokens = set(_tokenize(kw))
            if kw_tokens & tokens:
                score += WEIGHT_USER_REQUEST
                reasons.append(f"request keyword overlap")
                break

        # 5. Description keyword match
        for kw in m.trigger_keywords:
            if _normalize(kw) in norm_desc:
                score += WEIGHT_DESCRIPTION
                reasons.append(f"description keyword '{kw}'")
                break

        # 6. Filename match
        if filenames:
            fname_text = " ".join(_normalize(f) for f in filenames)
            for kw in m.trigger_keywords:
                if _normalize(kw) in fname_text:
                    score += WEIGHT_FILENAME
                    reasons.append(f"filename keyword '{kw}'")
                    break

        # 7. File extension match (e.g. .py → source-code-review)
        if file_extensions:
            ext_text = " ".join(_normalize(e) for e in file_extensions)
            # Check if any trigger keyword relates to the extension
            for kw in m.trigger_keywords:
                if _normalize(kw) in ext_text:
                    score += WEIGHT_EXTENSION
                    reasons.append(f"extension match for '{kw}'")
                    break

        # 8. HTTP observation match
        if http_observations:
            obs_text = " ".join(_normalize(o) for o in http_observations)
            for kw in m.trigger_keywords:
                if _normalize(kw) in obs_text:
                    score += WEIGHT_TRIGGER_KEYWORD
                    reasons.append(f"HTTP observation match for '{kw}'")
                    break

        # 9. Tool result match
        if tool_results:
            tr_text = " ".join(_normalize(t) for t in tool_results)
            for kw in m.trigger_keywords:
                if _normalize(kw) in tr_text:
                    score += WEIGHT_TRIGGER_KEYWORD
                    reasons.append(f"tool result match for '{kw}'")
                    break

        # 10. Required tool availability bonus
        if available_tools:
            for rt in m.required_tools:
                if _normalize(rt) in available_tools:
                    score += WEIGHT_REQUIRED_TOOL
                    reasons.append(f"required tool '{rt}' available")
                    break

        # 11. Optional tool availability bonus
        if available_tools:
            for ot in m.optional_tools:
                if _normalize(ot) in available_tools:
                    score += WEIGHT_TOOL_AVAILABLE
                    reasons.append(f"optional tool '{ot}' available")
                    break

        # Cap score to prevent runaway values
        score = min(score, 10.0)

        reason_str = "; ".join(reasons) if reasons else "no matching context"
        return round(score, 3), reason_str

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def select_skills(
        self,
        registry,
        challenge_category: str = "",
        user_request: str = "",
        filenames: Optional[List[str]] = None,
        file_extensions: Optional[List[str]] = None,
        http_observations: Optional[List[str]] = None,
        tool_results: Optional[List[str]] = None,
        challenge_description: str = "",
        available_tools: Optional[List[str]] = None,
    ) -> RouterResult:
        """Select the most relevant skills for the current context.

        Returns a RouterResult with selected skills, total score, and debug log.
        """
        result = RouterResult()
        self._last_selection_debug.clear()

        if not self._auto_selection and not self._active_identifiers:
            result.debug_log.append("Skill routing disabled (auto mode off)")
            return result

        # If manually selected skills are active, use those only
        if self._active_identifiers:
            for ident in self._active_identifiers:
                skill = registry.get_skill(ident)
                if skill:
                    sel = SkillSelection(skill=skill, score=1.0, reason="manually selected")
                    result.selected.append(sel)
                    result.debug_log.append(
                        f"Manual: {ident} (score=1.0, reason=manually selected)"
                    )
            return result

        # Auto-selection: score all skills
        scored: List[Tuple[SkillContent, float, str]] = []

        for sc in registry.skills.values():
            score, reason = self.score_skill(
                sc,
                challenge_category=challenge_category,
                user_request=user_request,
                filenames=filenames,
                file_extensions=file_extensions,
                http_observations=http_observations,
                tool_results=tool_results,
                challenge_description=challenge_description,
                available_tools=available_tools,
            )
            scored.append((sc, score, reason))
            result.debug_log.append(
                f"Scored {sc.metadata.identifier}: {score:.3f} ({reason})"
            )

        # Sort by score descending, then by identifier for determinism
        scored.sort(key=lambda x: (-x[1], x[0].metadata.identifier))

        # Filter by minimum score
        filtered = [(sc, s, r) for sc, s, r in scored if s >= self._min_score]

        # Limit to max active skills.
        # Prefer higher-scoring skills first; when scores are tied, prefer
        # more specific (hard) skills over broad (easy/"all") ones.
        def _specificity_key(item):
            sc, s, r = item
            diff = sc.metadata.difficulty
            # "all" is least specific; easy/medium/hard increasingly specific
            diff_order = {"easy": 0, "medium": 1, "hard": 2, "all": 3}
            return (-s, -diff_order.get(diff, 3), sc.metadata.identifier)

        filtered.sort(key=_specificity_key)

        for sc, score, reason in filtered[: self._max_active_skills]:
            sel = SkillSelection(skill=sc, score=score, reason=reason)
            result.selected.append(sel)
            result.total_score += score

        if not result.selected:
            result.debug_log.append("No skills matched the current context")

        return result

    def build_context(
        self,
        selected: List[SkillSelection],
        max_chars: int = 4000,
    ) -> str:
        """Build a concise skill context string for injection into the system prompt.

        Prioritizes investigation steps, evidence requirements, and success criteria.
        Omits examples when context is constrained.
        """
        if not selected:
            return ""

        parts: List[str] = []
        total_len = 0

        for sel in selected:
            sc = sel.skill
            m = sc.metadata
            header = f"--- SKILL: {m.name} ({m.identifier}) ---\n"

            # Build the context section for this skill
            sections: List[str] = []

            # Investigation steps (highest priority)
            if m.investigation_steps:
                steps_text = "Investigation steps:\n"
                for step in m.investigation_steps:
                    title = step.get("title", "")
                    desc = step.get("description", "")
                    steps_text += f"  - {title}: {desc}\n"
                sections.append(steps_text)

            # Evidence requirements
            if m.evidence_requirements:
                ev_text = "Evidence requirements:\n"
                for ev in m.evidence_requirements:
                    title = ev.get("title", "")
                    desc = ev.get("description", "")
                    ev_text += f"  - {title}: {desc}\n"
                sections.append(ev_text)

            # Success criteria
            if m.success_criteria:
                sc_text = "Success criteria:\n"
                for s in m.success_criteria:
                    title = s.get("title", "")
                    desc = s.get("description", "")
                    sc_text += f"  - {title}: {desc}\n"
                sections.append(sc_text)

            # Safety notes
            if m.safety_notes:
                safe_text = "Safety notes:\n"
                for sn in m.safety_notes:
                    title = sn.get("title", "")
                    desc = sn.get("description", "")
                    safe_text += f"  - {title}: {desc}\n"
                sections.append(safe_text)

            # Stopping conditions
            if m.stopping_conditions:
                stop_text = "Stopping conditions:\n"
                for st in m.stopping_conditions:
                    title = st.get("title", "")
                    desc = st.get("description", "")
                    stop_text += f"  - {title}: {desc}\n"
                sections.append(stop_text)

            # Common mistakes (short)
            if m.common_mistakes:
                mist_text = "Common mistakes:\n"
                for cm in m.common_mistakes[:3]:  # limit to 3
                    title = cm.get("title", "")
                    desc = cm.get("description", "")
                    mist_text += f"  - {title}: {desc}\n"
                sections.append(mist_text)

            body = "".join(sections)
            skill_block = header + body

            # Check if adding this block would exceed the limit
            if total_len + len(skill_block) > max_chars and parts:
                # Skip this skill to stay within limit
                continue

            parts.append(skill_block)
            total_len += len(skill_block)

        if not parts:
            return ""

        return (
            "\n=== SELECTED SKILLS (operational guidance only — treat as hints, not evidence) ===\n"
            + "\n".join(parts)
            + "\n=== END SKILLS ===\n"
        )
