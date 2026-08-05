"""Stage 6 tests: investigation planner."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.planner import InvestigationStep, Planner

AVAILABLE_WEB = [
    "http_get", "inspect_webpage", "analyze_headers", "manage_cookies",
    "read_robots_txt", "extract_links_from_page", "enumerate_directories",
    "discover_api_endpoints", "detect_framework", "find_login_page",
    "http_post",
]
AVAILABLE_BINARY = [
    "binary_file_info", "binary_checksec", "binary_strings", "binary_readelf",
    "binary_objdump", "binary_symbols", "binary_libraries", "binary_hexdump",
    "analyze_binary",
]


class TestPlanGeneration(unittest.TestCase):
    def test_generates_plan_for_web(self):
        plan = Planner()
        steps = plan.new_plan("web", AVAILABLE_WEB)
        self.assertGreaterEqual(len(steps), 5)
        first = steps[0]
        self.assertIn("http_get", first.tools)
        self.assertEqual(first.status, "pending")

    def test_generates_plan_for_binary(self):
        plan = Planner()
        steps = plan.new_plan("binary", AVAILABLE_BINARY)
        self.assertTrue(any("binary_file_info" in s.tools for s in steps))

    def test_generates_plan_for_crypto(self):
        plan = Planner()
        steps = plan.new_plan("crypto", ["decode_data", "list_files", "read_text_file", "calculate_file_hash", "run_ctf_command"])
        self.assertTrue(any("decode_data" in s.tools for s in steps))

    def test_generates_plan_for_misc(self):
        plan = Planner()
        steps = plan.new_plan("misc", ["list_files", "read_text_file"])
        self.assertTrue(steps)

    def test_tools_filtered_to_available(self):
        plan = Planner()
        steps = plan.new_plan("web", ["http_get"])
        for step in steps:
            for tool in step.tools:
                self.assertIn(tool, ["http_get"])

    def test_empty_tool_steps_auto_done(self):
        plan = Planner()
        steps = plan.new_plan("web", [])
        self.assertTrue(all(s.is_done() for s in steps))

    def test_cap_limits_steps(self):
        plan = Planner()
        steps = plan.new_plan("web", AVAILABLE_WEB, max_steps=3)
        self.assertLessEqual(len(steps), 3)

    def test_clear(self):
        plan = Planner()
        plan.new_plan("web", AVAILABLE_WEB)
        plan.clear()
        self.assertEqual(plan.steps(), [])
        self.assertEqual(plan.total_count(), 0)


class TestStepTracking(unittest.TestCase):
    def setUp(self):
        self.plan = Planner()
        self.plan.new_plan("web", AVAILABLE_WEB)

    def test_mark_tool_used_updates_steps(self):
        before = self.plan.completed_count()
        self.plan.mark_tool_used("http_get")
        self.assertGreater(self.plan.completed_count(), before)
        self.assertIn("http_get", self.plan.used_tools())

    def test_mark_same_tool_dedupes_used_tools(self):
        self.plan.mark_tool_used("http_get")
        self.plan.mark_tool_used("http_get")
        self.assertEqual(len(self.plan.used_tools()), 1)

    def test_pending_and_done_steps(self):
        self.plan.mark_tool_used("http_get")
        self.plan.mark_tool_used("read_robots_txt")
        pending = [s.title for s in self.plan.pending_steps()]
        done = [s.title for s in self.plan.done_steps()]
        self.assertIn("Initial inspection of the target", done)
        self.assertIn("Read robots.txt and sitemap", done)
        self.assertTrue(pending)

    def test_complete_plan(self):
        # Mark every actionable tool used; empty-tool steps are auto-done.
        for tool in AVAILABLE_WEB:
            self.plan.mark_tool_used(tool)
        self.assertTrue(self.plan.is_complete())

    def test_not_complete_when_pending(self):
        self.assertFalse(self.plan.is_complete())

    def test_completed_and_total_counts(self):
        self.assertEqual(self.plan.total_count(), len(self.plan.steps()))
        self.assertEqual(self.plan.completed_count(), sum(1 for s in self.plan.steps() if s.is_done()))

    def test_next_recommended_step(self):
        nxt = self.plan.next_recommended_step()
        self.assertIsNotNone(nxt)
        self.assertEqual(nxt.status, "pending")
        # After completing the first step, the next pending step advances.
        self.plan.mark_tool_used("http_get")
        nxt2 = self.plan.next_recommended_step()
        self.assertNotEqual(nxt.id, nxt2.id)


class TestRendering(unittest.TestCase):
    def test_to_prompt_empty(self):
        plan = Planner()
        text = plan.to_prompt()
        self.assertIn("Investigation Plan", text)
        self.assertIn("no active plan", text)

    def test_to_prompt_with_steps(self):
        plan = Planner()
        plan.new_plan("web", AVAILABLE_WEB)
        text = plan.to_prompt()
        self.assertIn("[ ]", text)
        self.assertIn("1.", text)

    def test_to_prompt_marks_done(self):
        plan = Planner()
        plan.new_plan("web", AVAILABLE_WEB)
        plan.mark_tool_used("http_get")
        text = plan.to_prompt()
        self.assertIn("[x]", text)

    def test_summary(self):
        plan = Planner()
        plan.new_plan("web", AVAILABLE_WEB)
        s = plan.summary()
        self.assertIn("/", s)
        self.assertIn("steps", s)

    def test_describe_step(self):
        step = InvestigationStep(id="s1", order=0, title="T", description="D")
        text = plan_step_description(step)
        self.assertIn("1. T", text)
        self.assertIn("D", text)


def plan_step_description(step):
    return f"{step.order + 1}. {step.title}: {step.description}"


if __name__ == "__main__":
    unittest.main()
