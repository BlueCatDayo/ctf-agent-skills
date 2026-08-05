"""Stage 4 tests: skill router (scoring, selection, context limits, modes)."""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tools.skill_registry import SkillRegistry
from tools.skill_router import SkillRouter

FIXTURES = Path(__file__).parent / "fixtures" / "skills"
VALID = FIXTURES / "valid"


@pytest.fixture
def registry():
    reg = SkillRegistry(str(VALID))
    reg.load_all()
    return reg


class TestScoring:
    def test_category_match_boost(self, registry):
        router = SkillRouter()
        skill = registry.get_skill("test-sql-injection")
        score, reason = router.score_skill(
            skill, challenge_category="web", user_request="sql injection in login"
        )
        assert score >= 5.0
        assert "category match" in reason

    def test_trigger_keyword_match(self, registry):
        router = SkillRouter()
        skill = registry.get_skill("test-sql-injection")
        score, _ = router.score_skill(
            skill, user_request="help me with sql database query injection"
        )
        assert score > 0

    def test_no_match_zero_score(self, registry):
        router = SkillRouter()
        skill = registry.get_skill("test-common-skill")
        score, reason = router.score_skill(
            skill, user_request="nothing related here at all xyz123"
        )
        assert score == 0.0
        assert "no matching context" in reason

    def test_binary_skill_prefers_binary_context(self, registry):
        router = SkillRouter()
        skill = registry.get_skill("test-buffer-overflow")
        score_bin, _ = router.score_skill(
            skill, challenge_category="binary", user_request="stack overflow in binary"
        )
        score_web, _ = router.score_skill(
            skill, challenge_category="web", user_request="login form"
        )
        assert score_bin > score_web

    def test_required_tool_availability_bonus(self, registry):
        router = SkillRouter()
        skill = registry.get_skill("test-sql-injection")
        score_with, _ = router.score_skill(
            skill, user_request="sql injection", available_tools=["http_request", "inspect_webpage"]
        )
        score_without, _ = router.score_skill(
            skill, user_request="sql injection", available_tools=[]
        )
        assert score_with > score_without

    def test_score_capped(self, registry):
        router = SkillRouter()
        skill = registry.get_skill("test-sql-injection")
        score, _ = router.score_skill(
            skill,
            challenge_category="web",
            user_request="sql injection database query",
            filenames=["login.sql"],
            file_extensions=[".sql"],
            http_observations=["database error"],
            tool_results=["sql syntax error"],
            available_tools=["http_request", "compare_http_responses"],
        )
        assert score <= 10.0


class TestSelection:
    def test_selects_relevant_skills(self, registry):
        router = SkillRouter(min_score=0.0)
        result = router.select_skills(
            registry, challenge_category="web", user_request="sql injection login form"
        )
        selected = [s.skill.metadata.identifier for s in result.selected]
        assert "test-sql-injection" in selected

    def test_respects_max_active_skills(self, registry):
        router = SkillRouter(max_active_skills=2, min_score=0.0)
        result = router.select_skills(
            registry, challenge_category="web", user_request="sql injection"
        )
        assert len(result.selected) <= 2

    def test_respects_min_score(self, registry):
        router = SkillRouter(min_score=100.0)
        result = router.select_skills(
            registry, challenge_category="web", user_request="sql injection"
        )
        assert result.selected == []

    def test_deterministic_selection(self, registry):
        r1 = SkillRouter(min_score=0.0)
        r2 = SkillRouter(min_score=0.0)
        a = r1.select_skills(registry, challenge_category="binary", user_request="overflow").selected
        b = r2.select_skills(registry, challenge_category="binary", user_request="overflow").selected
        assert [s.skill.metadata.identifier for s in a] == [s.skill.metadata.identifier for s in b]

    def test_disabled_mode_returns_empty(self, registry):
        router = SkillRouter(auto_selection=False)
        result = router.select_skills(
            registry, challenge_category="web", user_request="sql injection"
        )
        assert result.selected == []

    def test_manual_selection_takes_precedence(self, registry):
        router = SkillRouter()
        router.activate_skill("test-common-skill", registry)
        result = router.select_skills(
            registry, challenge_category="binary", user_request="completely unrelated"
        )
        selected = [s.skill.metadata.identifier for s in result.selected]
        assert selected == ["test-common-skill"]

    def test_no_skills_matching(self, registry):
        router = SkillRouter(min_score=0.01)
        result = router.select_skills(
            registry, user_request="zzz qqq nothing here"
        )
        # No skill should reach the minimum threshold.
        selected = [s.skill.metadata.identifier for s in result.selected]
        assert selected == []


class TestManualControl:
    def test_activate_unknown_skill(self, registry):
        router = SkillRouter()
        ok, msg = router.activate_skill("nope", registry)
        assert ok is False
        assert "Unknown" in msg

    def test_activate_and_deactivate(self, registry):
        router = SkillRouter()
        ok, msg = router.activate_skill("test-sql-injection", registry)
        assert ok is True
        assert "test-sql-injection" in router.active_identifiers
        ok, msg = router.deactivate_skill("test-sql-injection")
        assert ok is True
        assert router.active_identifiers == []

    def test_clear_manual(self, registry):
        router = SkillRouter()
        router.activate_skill("test-sql-injection", registry)
        router.activate_skill("test-common-skill", registry)
        router.clear_manual()
        assert router.active_identifiers == []

    def test_set_mode(self, registry):
        router = SkillRouter()
        msg = router.set_mode(False)
        assert router.auto_selection is False
        assert "disabled" in msg
        msg = router.set_mode(True)
        assert router.auto_selection is True


class TestBuildContext:
    def test_empty_selection(self, registry):
        router = SkillRouter()
        assert router.build_context([]) == ""

    def test_builds_context_with_steps(self, registry):
        router = SkillRouter()
        skill = registry.get_skill("test-sql-injection")
        from tools.skill_router import SkillSelection
        sel = SkillSelection(skill=skill, score=5.0, reason="test")
        context = router.build_context([sel])
        assert "SELECTED SKILLS" in context
        assert "test-sql-injection" in context
        assert "Investigation steps" in context
        assert "Evidence requirements" in context
        assert "Success criteria" in context

    def test_context_respects_max_chars(self, registry):
        router = SkillRouter()
        from tools.skill_router import SkillSelection
        a = SkillSelection(skill=registry.get_skill("test-sql-injection"), score=5.0, reason="a")
        b = SkillSelection(skill=registry.get_skill("test-buffer-overflow"), score=4.0, reason="b")
        # With a tiny budget only the first skill block fits (first is always
        # included so the context is never empty), the second is dropped.
        context = router.build_context([a, b], max_chars=100)
        assert "test-sql-injection" in context
        assert "test-buffer-overflow" not in context
        # With a large budget both fit.
        context_big = router.build_context([a, b], max_chars=4000)
        assert "test-buffer-overflow" in context_big

    def test_context_omits_skill_over_limit(self, registry):
        router = SkillRouter()
        from tools.skill_router import SkillSelection
        a = SkillSelection(skill=registry.get_skill("test-sql-injection"), score=5.0, reason="a")
        b = SkillSelection(skill=registry.get_skill("test-common-skill"), score=4.0, reason="b")
        context = router.build_context([a, b], max_chars=500)
        # At least one skill must appear
        assert "test-sql-injection" in context or "test-common-skill" in context


class TestSecurity:
    def test_malicious_instructions_do_not_bypass_validation(self, registry):
        """A skill attempting to override safety rules is still just content."""
        skill = registry.get_skill("malicious-skill")
        assert skill is not None
        assert skill.metadata.identifier == "malicious-skill"
        # The system prompt guardrails remain in prompts.py and are never
        # replaced by skill content — skills are injected only as hints.
        from agent.prompts import get_system_prompt
        prompt = get_system_prompt()
        # Core safety text must always be present in the prompt template.
        assert "authorized" in prompt
        assert "Do not reveal API keys" in prompt

    def test_downloaded_skills_cannot_override_core_safety(self):
        """Simulate a downloaded skill attempting to change provider settings."""
        import tempfile
        from pathlib import Path as P
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = P(tmp) / "downloaded"
            tmp_p.mkdir()
            (tmp_p / "evil.md").write_text(
                """---
name: Evil
identifier: evil
category: web
description: changes settings
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - evil
required_tools: []
optional_tools: []
prerequisites: []
investigation_steps:
  - title: x
    description: x
evidence_requirements:
  - title: x
    description: x
success_criteria:
  - title: x
    description: x
stopping_conditions:
  - title: x
    description: x
safety_notes: []
common_mistakes: []
version: 1.0.0
---
# Evil
""", encoding="utf-8")
            reg = SkillRegistry(str(tmp_p))
            result = reg.load_all()
            assert result.loaded_count == 1
            # The skill is just data — it cannot change config or tools.
            # Verify the registry exposes no mutation API for config/tools.
            assert not hasattr(reg, "set_config")
            assert not hasattr(reg, "modify_tools")
