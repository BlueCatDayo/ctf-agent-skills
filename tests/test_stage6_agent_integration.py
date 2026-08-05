"""Stage 6 integration tests: ChatAgent autonomous reasoning.

Uses a fake provider and a small tool registry to exercise the full loop:
plan generation, automatic tool selection, retries, evidence recording,
memory updates, progress evaluation, structured reports, and commands.
"""

import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.chat_agent import ChatAgent
from agent.prompts import (
    CHALLENGE_PROFILE_PLACEHOLDER,
    EVIDENCE_LOG_PLACEHOLDER,
    INVESTIGATION_PLAN_PLACEHOLDER,
    SESSION_MEMORY_PLACEHOLDER,
)
from config import Config
from tools.registry import ToolRegistry


def make_registry() -> ToolRegistry:
    """A small registry with web + binary + decode tools."""
    reg = ToolRegistry()
    schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "path": {"type": "string"},
            "data": {"type": "string"},
            "encoding": {"type": "string"},
        },
        "required": [],
    }

    def http_get(url):
        return f"Status: 200 URL: {url} flag{'{stage6_test_only}'}"

    def binary_strings(path):
        return f"strings of {path}: hello flag{'{stage6_bin_only}'}"

    def decode_data(data, encoding="auto"):
        return f"decoded {encoding}: {data.upper()}"

    reg.register(name="http_get", func=http_get, description="GET", parameters=schema, category="web")
    reg.register(name="binary_strings", func=binary_strings, description="strings", parameters=schema, category="binary")
    reg.register(name="decode_data", func=decode_data, description="decode", parameters=schema, category="data")
    return reg


class FakeProvider:
    """Scripted provider: tool call on first call, final text afterwards."""

    def __init__(self, tool_call, final_text="Analysis complete."):
        self.tool_call = tool_call
        self.final_text = final_text
        self.calls = []
        self.received_messages = []

    def chat_with_tools(self, messages, tools=None):
        self.calls.append(len(tools or []))
        self.received_messages.append(messages)
        if not self.tool_call:
            return self.final_text, []
        tc, self.tool_call = self.tool_call, None
        return "", [tc]


def make_agent() -> ChatAgent:
    config = Config.from_env()
    config.openrouter_api_key = "test-key"
    config.tool_retry_delay = 0
    config.max_agent_steps = 5
    agent = ChatAgent(config)
    agent.set_tool_registry(make_registry())
    return agent


class TestInvestigationStart(unittest.TestCase):
    def test_start_investigation_detects_type_and_plans(self):
        agent = make_agent()
        agent.start_investigation("binary pwn buffer overflow readelf objdump")
        self.assertEqual(agent._challenge_type, "binary")
        self.assertGreater(len(agent._plan), 0)
        self.assertTrue(agent._planner.steps())

    def test_start_investigation_web(self):
        agent = make_agent()
        agent.start_investigation("sql injection in the web login form with cookies")
        self.assertEqual(agent._challenge_type, "web")

    def test_no_investigation_when_disabled(self):
        agent = make_agent()
        agent.config.enable_autonomous_mode = False
        agent.start_investigation("web challenge")
        self.assertEqual(agent._challenge_type, "")

    def test_memory_note_added(self):
        agent = make_agent()
        agent.start_investigation("crypto xor cipher base64")
        notes = agent._memory.get("notes")
        self.assertTrue(any("crypto" in n for n in notes))


class TestPromptInjection(unittest.TestCase):
    def _agent_with_history(self, message):
        from agent.conversation import ConversationHistory
        agent = make_agent()
        agent._history = ConversationHistory()
        agent.start_investigation(message)
        agent._history.add_user_message(message)
        return agent

    def test_placeholders_replaced_in_system_prompt(self):
        agent = self._agent_with_history("web challenge with login")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        self.assertNotIn(CHALLENGE_PROFILE_PLACEHOLDER, prompt)
        self.assertNotIn(INVESTIGATION_PLAN_PLACEHOLDER, prompt)
        self.assertNotIn(SESSION_MEMORY_PLACEHOLDER, prompt)
        self.assertNotIn(EVIDENCE_LOG_PLACEHOLDER, prompt)
        self.assertIn("Challenge Profile", prompt)
        self.assertIn("Investigation Plan", prompt)
        self.assertIn("Session Memory", prompt)
        self.assertIn("Evidence Log", prompt)

    def test_placeholders_cleared_when_disabled(self):
        from agent.conversation import ConversationHistory
        agent = make_agent()
        agent.config.enable_autonomous_mode = False
        agent._history = ConversationHistory()
        agent._history.add_user_message("hi")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        for placeholder in (
            CHALLENGE_PROFILE_PLACEHOLDER, INVESTIGATION_PLAN_PLACEHOLDER,
            SESSION_MEMORY_PLACEHOLDER, EVIDENCE_LOG_PLACEHOLDER,
        ):
            self.assertNotIn(placeholder, prompt)

    def test_skill_placeholders_still_work(self):
        agent = self._agent_with_history("web login")
        messages = agent._messages_with_system_prompt(agent._history.get_messages())
        prompt = messages[0]["content"]
        # Stage 4 safety phrases remain.
        self.assertIn("Do not reveal API keys", prompt)
        self.assertIn("authorized", prompt)
        self.assertIn("workspace", prompt)


class TestAgentLoop(unittest.TestCase):
    def test_full_loop_records_evidence_and_reports(self):
        agent = make_agent()
        agent.provider = FakeProvider(
            tool_call={"name": "http_get", "arguments": {"url": "http://t.local/"}, "id": "c1"}
        )
        out = agent.send_message("web challenge at http://t.local/")
        self.assertIn("## Investigation Report", out)
        self.assertIn("### Confirmed Findings", out)
        self.assertIn("### Evidence", out)
        self.assertIn("### Flag Status", out)
        self.assertIn("### Recommended Next Step", out)
        self.assertIn("flag{stage6_test_only}", out)
        self.assertTrue(agent._evidence.has_flag())
        self.assertEqual(agent._evidence.flag_status()[0], "Confirmed")

    def test_evidence_and_memory_populated(self):
        agent = make_agent()
        agent.provider = FakeProvider(
            tool_call={"name": "binary_strings", "arguments": {"path": "test/sample.bin"}, "id": "c1"}
        )
        agent.send_message("binary analysis of sample.bin")
        self.assertEqual(len(agent._evidence.items()), 1)
        self.assertIn("test/sample.bin", agent._memory.get("files"))
        self.assertIn("flag{stage6_bin_only}", agent._memory.get("flags"))
        self.assertIn("binary_strings", agent._planner.used_tools())

    def test_decode_evidence(self):
        agent = make_agent()
        agent.provider = FakeProvider(
            tool_call={"name": "decode_data", "arguments": {"data": "SGk=", "encoding": "base64"}, "id": "c1"}
        )
        agent.send_message("decode this base64")
        decoded = agent._memory.get("decoded")
        self.assertTrue(any("base64" in d for d in decoded))

    def test_structured_report_uses_next_step(self):
        agent = make_agent()
        agent.provider = FakeProvider(
            tool_call={"name": "http_get", "arguments": {"url": "http://t.local/"}, "id": "c1"}
        )
        out = agent.send_message("web challenge")
        self.assertIn("Recommended Next Step", out)

    def test_no_report_without_evidence(self):
        agent = make_agent()
        agent.provider = FakeProvider(tool_call=None)
        out = agent.send_message("just a normal question")
        self.assertNotIn("## Investigation Report", out)


class TestAutomaticToolSelection(unittest.TestCase):
    def test_recommended_tools_first_in_definitions(self):
        agent = make_agent()
        agent.start_investigation("web sql injection login")
        defs = agent._ordered_tool_definitions()
        names = [d["function"]["name"] for d in defs]
        # http_get is in the first web workflow step, so it must be first.
        self.assertEqual(names[0], "http_get")
        # All tools still present.
        self.assertIn("binary_strings", names)
        self.assertIn("decode_data", names)

    def test_no_reordering_when_disabled(self):
        agent = make_agent()
        agent.config.enable_autonomous_mode = False
        defs = agent._ordered_tool_definitions()
        names = [d["function"]["name"] for d in defs]
        self.assertEqual(len(names), 3)


class TestRetryIntegration(unittest.TestCase):
    def test_transient_failure_retried(self):
        agent = make_agent()
        agent.config.max_tool_retries = 2

        state = {"n": 0}

        def flaky_http_get(url):
            state["n"] += 1
            if state["n"] == 1:
                raise TimeoutError("simulated timeout")
            return "recovered: 200"

        reg = make_registry()
        reg.register(
            name="http_get", func=flaky_http_get, description="get",
            parameters={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
            required=["url"], category="web",
        )
        agent._tool_registry = reg
        agent.provider = FakeProvider(
            tool_call={"name": "http_get", "arguments": {"url": "u"}, "id": "c1"}
        )
        out = agent.send_message("web recon")
        self.assertIn("recovered: 200", out)
        self.assertEqual(state["n"], 2)
        # Only the successful result is recorded as evidence.
        self.assertEqual(len(agent._evidence.items()), 1)
        self.assertTrue(agent._evidence.items()[0].success)


class TestStage6Commands(unittest.TestCase):
    def test_plan_command(self):
        agent = make_agent()
        agent.start_investigation("binary pwn")
        out = agent.stage6_command("/plan")
        self.assertIn("Investigation Plan", out)
        self.assertIn("binary_strings", out)

    def test_memory_command(self):
        agent = make_agent()
        agent._memory.add_url("http://x/")
        out = agent.stage6_command("/memory")
        self.assertIn("URLs", out)
        self.assertIn("http://x/", out)

    def test_evidence_command(self):
        agent = make_agent()
        agent._evidence.record("http_get", {"url": "u"}, type(
            "R", (), {"success": True, "output": "ok", "error": None,
                      "truncated": False, "timed_out": False})())
        out = agent.stage6_command("/evidence")
        self.assertIn("Evidence Log", out)
        self.assertIn("http_get", out)

    def test_status_command(self):
        agent = make_agent()
        agent.start_investigation("crypto cipher")
        out = agent.stage6_command("/status")
        self.assertIn("Challenge type", out)
        self.assertIn("crypto", out)
        self.assertIn("Flag status", out)

    def test_unknown_command(self):
        agent = make_agent()
        out = agent.stage6_command("/bogus")
        self.assertIn("Unknown", out)


class TestReset(unittest.TestCase):
    def test_reset_clears_stage6_state(self):
        agent = make_agent()
        agent.start_investigation("web challenge")
        agent._memory.add_url("http://x/")
        agent._evidence.record("http_get", {}, type(
            "R", (), {"success": True, "output": "flag{a}", "error": None,
                      "truncated": False, "timed_out": False})())
        agent.reset_conversation()
        self.assertEqual(agent._memory.total(), 0)
        self.assertFalse(agent._evidence.has_items())
        self.assertEqual(agent._planner.steps(), [])
        self.assertEqual(agent._challenge_type, "")


class TestPromptSections(unittest.TestCase):
    def test_challenge_profile_prompt(self):
        agent = make_agent()
        agent.start_investigation("binary exploit")
        text = agent._challenge_profile_prompt()
        self.assertIn("binary", text)
        self.assertIn("confidence", text)

    def test_memory_prompt_disabled(self):
        agent = make_agent()
        agent.config.enable_session_memory = False
        text = agent._memory_prompt()
        self.assertIn("disabled", text)

    def test_plan_prompt(self):
        agent = make_agent()
        agent.start_investigation("web")
        text = agent._planner.to_prompt()
        self.assertIn("## Investigation Plan", text)


if __name__ == "__main__":
    unittest.main()
