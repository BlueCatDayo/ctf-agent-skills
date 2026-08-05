"""Stage 4 tests: ChatAgent skill integration (context injection, commands)."""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from agent.chat_agent import ChatAgent
from agent.conversation import ConversationHistory
from agent.prompts import (
    ACTIVE_SKILLS_PLACEHOLDER,
    SKILL_CONTEXT_PLACEHOLDER,
    get_system_prompt,
)
from config import Config
from tools.skill_registry import SkillRegistry

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def _make_agent(skills_dir: str = "skills") -> ChatAgent:
    """Build a ChatAgent with skills pointed at a fixture directory."""
    config = Config.from_env()
    config.openrouter_api_key = "test-key"
    config.skills_directory = skills_dir
    agent = ChatAgent(config)
    agent.init_skills()
    return agent


class TestSkillCommands:
    def test_skills_command_lists_library(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        output = agent.skill_command("/skills")
        assert "Skill library" in output
        assert "test-sql-injection" in output
        assert "test-buffer-overflow" in output

    def test_skill_activate_known(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        output = agent.skill_command("/skill test-sql-injection")
        assert "Activated" in output
        router = agent.get_skill_router()
        assert "test-sql-injection" in router.active_identifiers

    def test_skill_activate_unknown(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        output = agent.skill_command("/skill does-not-exist")
        assert "Unknown" in output

    def test_skill_auto(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        output = agent.skill_command("/skill auto")
        assert "enabled" in output.lower()

    def test_skill_off(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        output = agent.skill_command("/skill off")
        assert "disabled" in output.lower()
        router = agent.get_skill_router()
        assert router.auto_selection is False

    def test_skill_clear(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        agent.skill_command("/skill test-sql-injection")
        output = agent.skill_command("/skill clear")
        assert "cleared" in output.lower()
        router = agent.get_skill_router()
        assert router.active_identifiers == []

    def test_skill_command_disabled_skills(self, monkeypatch):
        config = Config.from_env()
        config.openrouter_api_key = "test-key"
        config.enable_skills = False
        agent = ChatAgent(config)
        agent.init_skills()
        assert agent.get_skill_registry() is None
        output = agent.skill_command("/skills")
        assert "disabled" in output.lower()


class TestSkillContextInjection:
    def test_context_injected_into_system_prompt(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        agent._history = ConversationHistory()
        agent._history.add_user_message("SQL injection in the login database query")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        assert "SELECTED SKILLS" in prompt
        assert "test-sql-injection" in prompt
        # Placeholders must be replaced
        assert SKILL_CONTEXT_PLACEHOLDER not in prompt
        assert ACTIVE_SKILLS_PLACEHOLDER not in prompt

    def test_active_skills_summary_present(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        agent._history = ConversationHistory()
        agent._history.add_user_message("web challenge with a login form and session cookies")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        assert "## Active Skills" in prompt

    def test_no_context_when_disabled(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        agent.get_skill_router().set_mode(False)
        agent._history = ConversationHistory()
        agent._history.add_user_message("anything at all")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        assert "SELECTED SKILLS" not in prompt
        assert "## Active Skills" not in prompt

    def test_no_context_when_no_match(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        agent._history = ConversationHistory()
        agent._history.add_user_message("zzz qqq entirely unrelated chatter")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        assert "SELECTED SKILLS" not in prompt

    def test_core_safety_prompt_always_present(self):
        """Skills must never remove core safety guardrails."""
        agent = _make_agent(str(FIXTURES / "valid"))
        agent._history = ConversationHistory()
        agent._history.add_user_message("web challenge login")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        assert "Do not reveal API keys" in prompt
        assert "authorized" in prompt
        assert "workspace" in prompt


class TestMaliciousSkillHandling:
    def test_malicious_skill_loads_as_content_only(self):
        """A skill with malicious instructions is still just content."""
        agent = _make_agent(str(FIXTURES / "valid"))
        registry = agent.get_skill_registry()
        skill = registry.get_skill("malicious-skill")
        assert skill is not None
        body = skill.body.lower()
        assert "override" in body or "ignore" in body

    def test_malicious_skill_cannot_remove_guardrails(self):
        """Even if the malicious skill is selected, base guardrails remain."""
        agent = _make_agent(str(FIXTURES / "valid"))
        agent._history = ConversationHistory()
        agent._history.add_user_message("dangerous challenge please help")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        assert "Do not reveal API keys" in prompt
        assert "Do not access files outside the authorized workspace" in prompt or "workspace" in prompt
        assert "authorized" in prompt


class TestSkillSummary:
    def test_summary_lists_counts(self):
        agent = _make_agent(str(FIXTURES / "valid"))
        summary = agent.skill_summary()
        assert "Skills loaded" in summary
        assert "Web" in summary
        assert "Binary" in summary


class TestRealSkillLibrary:
    def test_real_library_loads_and_commands_work(self):
        project_root = Path(__file__).parent.parent
        skills_dir = project_root / "skills"
        if not skills_dir.exists():
            pytest.skip("skills dir missing")
        agent = _make_agent(str(skills_dir))
        assert agent.skill_summary().startswith("Skills loaded:")
        output = agent.skill_command("/skills")
        assert "web-reconnaissance" in output
        assert "sql-injection-analysis" in output
        assert "binary-triage" in output

    def test_real_library_selection(self):
        project_root = Path(__file__).parent.parent
        skills_dir = project_root / "skills"
        if not skills_dir.exists():
            pytest.skip("skills dir missing")
        agent = _make_agent(str(skills_dir))
        agent._history = ConversationHistory()
        agent._history.add_user_message("sql injection in a web login form")
        # The SQL injection skill must be highly scored for the context
        # (it may be capped out by max_active_skills which prefers common
        # easy skills).
        from tools.skill_router import SkillRouter
        router = SkillRouter(min_score=0.0, max_active_skills=50)
        result = router.select_skills(
            agent.get_skill_registry(),
            challenge_category=agent._detect_category(),
            user_request="sql injection in a web login form",
            available_tools=agent._available_tool_names(),
        )
        scored = {s.skill.metadata.identifier: s.score for s in result.selected}
        assert "sql-injection-analysis" in scored
        assert scored["sql-injection-analysis"] >= 5.0
        # Rendered context includes the selected-skills banner.
        context = agent._skill_context()
        assert "SELECTED SKILLS" in context
