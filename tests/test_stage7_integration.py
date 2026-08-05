"""Stage 7 integration tests: ChatAgent specialists + resource limits in the loop.

Uses a fake provider and small registry to exercise:
- specialist router suggestions in the agent loop
- resource-limit enforcement before tool execution
- duplicate-action blocking recorded as evidence
- /specialists and /limits commands
- structured specialist report section in final responses
- reset clearing specialist state
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.chat_agent import ChatAgent
from config import Config
from tools.registry import ToolRegistry


def make_registry() -> ToolRegistry:
    reg = ToolRegistry()
    schema = {
        "type": "object",
        "properties": {"url": {"type": "string"}, "data": {"type": "string"}},
        "required": [],
    }

    def http_get(url):
        return f"Status: 200 URL: {url} body"

    def http_post(url, data=""):
        return f"POST {url} data={data}"

    reg.register(name="http_get", func=http_get, description="GET", parameters=schema, category="web")
    reg.register(name="http_post", func=http_post, description="POST", parameters=schema, category="web")
    return reg


class FakeProvider:
    """Scripted provider for agent-loop tests."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def chat_with_tools(self, messages, tools=None):
        self.calls += 1
        if not self.script:
            return "Analysis complete.", []
        step = self.script.pop(0)
        if step is None:
            return "Analysis complete.", []
        return "", [step]


def tool_call(name, arguments, tool_id="t1"):
    return {"name": name, "arguments": arguments, "id": tool_id}


def make_agent() -> ChatAgent:
    config = Config.from_env()
    config.openrouter_api_key = "test-key"
    config.tool_retry_delay = 0
    config.max_agent_steps = 6
    config.max_duplicate_actions = 1
    agent = ChatAgent(config)
    agent.set_tool_registry(make_registry())
    return agent


class TestSpecialistCommand(unittest.TestCase):
    def test_specialists_list_command(self):
        agent = make_agent()
        out = agent.stage7_command("/specialists")
        self.assertIn("Specialist Recommendations", out)
        self.assertIn("web.sql_injection", out)

    def test_run_specific_specialist(self):
        agent = make_agent()
        agent.start_investigation("sql injection in login form")
        # seed evidence
        agent._evidence.record_finding("http_post", "You have an error in your SQL syntax near 'x'")
        out = agent.stage7_command("/specialists web.sql_injection")
        self.assertIn("Specialist: web.sql_injection", out)
        self.assertIn("Confirmed observations", out)

    def test_unknown_specialist(self):
        agent = make_agent()
        out = agent.stage7_command("/specialists web.nope")
        self.assertIn("Unknown specialist", out)

    def test_specialist_call_limit(self):
        agent = make_agent()
        agent._limits.max_specialist_calls = 1
        agent._limits.record_specialist_call()
        out = agent.stage7_command("/specialists web.sql_injection")
        self.assertIn("Maximum specialist calls", out)


class TestLimitsCommand(unittest.TestCase):
    def test_limits_command(self):
        agent = make_agent()
        out = agent.stage7_command("/limits")
        self.assertIn("Resource Limits", out)
        self.assertIn("max_http_requests", out)

    def test_limits_usage_tracks_tools(self):
        agent = make_agent()
        agent._limits.record_action("http_get", {"url": "x"})
        self.assertEqual(agent._limits.usage()["http_requests"], 1)


class TestLimitsInLoop(unittest.TestCase):
    def test_duplicate_actions_blocked_in_loop(self):
        agent = make_agent()
        # Two identical http_get calls; the second must be blocked by the
        # duplicate-action limit (max_duplicate_actions=1).
        script = [
            tool_call("http_get", {"url": "http://x/"}, "t1"),
            tool_call("http_get", {"url": "http://x/"}, "t2"),
            None,
        ]
        provider = FakeProvider(script)
        agent.provider = provider
        response = agent.send_message("web challenge")
        self.assertIn("Analysis complete.", response)
        # The blocked action must be recorded as failed evidence
        failed = [i for i in agent._evidence.items() if not i.success]
        self.assertTrue(failed)
        self.assertIn("Duplicate action", failed[0].error)

    def test_http_limit_blocks_request_in_loop(self):
        agent = make_agent()
        agent._limits.max_http_requests = 0
        script = [tool_call("http_get", {"url": "http://x/"}, "t1"), None]
        provider = FakeProvider(script)
        agent.provider = provider
        agent.send_message("web challenge")
        failed = [i for i in agent._evidence.items() if not i.success]
        self.assertTrue(failed)
        self.assertIn("Maximum HTTP requests", failed[0].error)

    def test_normal_tool_flow_not_blocked(self):
        agent = make_agent()
        script = [
            tool_call("http_get", {"url": "http://x/1"}, "t1"),
            None,
        ]
        provider = FakeProvider(script)
        agent.provider = provider
        response = agent.send_message("web challenge")
        self.assertIn("Analysis complete.", response)
        ok = [i for i in agent._evidence.items() if i.success]
        self.assertTrue(ok)
        self.assertFalse([i for i in agent._evidence.items() if not i.success])


class TestFinalReport(unittest.TestCase):
    def test_specialist_section_in_final_response(self):
        agent = make_agent()
        agent.start_investigation("sql injection login")
        agent._evidence.record_finding("http_post", "SQL syntax error near '1'")
        agent._update_specialist_recommendations()
        final = agent._finalize_response("done")
        self.assertIn("Specialist Guidance", final)
        self.assertIn("web.sql_injection", final)
        self.assertIn("Investigation Report", final)

    def test_specialist_section_stops_when_flag_confirmed(self):
        agent = make_agent()
        agent.start_investigation("web challenge")
        agent._evidence.record_finding("http_get", "flag{stage7_loop_flag}")
        agent._update_specialist_recommendations()
        final = agent._finalize_response("done")
        self.assertIn("Flag confirmed", final)
        self.assertIn("stage7_loop_flag", final)

    def test_no_specialist_section_when_disabled(self):
        agent = make_agent()
        agent.config.enable_specialists = False
        agent.start_investigation("sql injection login")
        agent._evidence.record_finding("http_post", "SQL syntax error")
        final = agent._finalize_response("done")
        self.assertNotIn("Specialist Guidance", final)


class TestReset(unittest.TestCase):
    def test_reset_clears_specialist_state(self):
        agent = make_agent()
        agent._limits.record_action("http_get", {"url": "x"})
        agent._used_specialists.append("web.sql_injection")
        agent.reset_conversation()
        self.assertEqual(agent._used_specialists, [])
        self.assertEqual(agent._specialist_recommendations, [])
        self.assertFalse(agent._limits.usage()["http_requests"])


class TestStartInvestigation(unittest.TestCase):
    def test_specialists_registered_on_start(self):
        agent = make_agent()
        agent.start_investigation("binary pwn buffer overflow")
        self.assertGreaterEqual(len(agent._specialist_router.all()), 17)

    def test_recommendations_seeded(self):
        agent = make_agent()
        agent._evidence.record_finding("http_post", "SQL syntax error near '1'")
        agent.start_investigation("sql injection in login")
        self.assertTrue(agent._specialist_recommendations)
        self.assertEqual(agent._specialist_recommendations[0].specialist.name, "web.sql_injection")


if __name__ == "__main__":
    unittest.main()
