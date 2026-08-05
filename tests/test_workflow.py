"""Stage 6 tests: workflow manager (challenge type detection + workflows)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.evidence import EvidenceLog
from agent.planner import Planner
from agent.workflow import CHALLENGE_TYPES, WorkflowManager


class TestChallengeTypeDetection(unittest.TestCase):
    def setUp(self):
        self.wf = WorkflowManager()

    def test_web_detection(self):
        ctype, conf, reasons = self.wf.detect_challenge_type(
            user_request="SQL injection in the web login form with cookies and session"
        )
        self.assertEqual(ctype, "web")
        self.assertGreaterEqual(conf, 0.5)
        self.assertTrue(reasons)

    def test_binary_detection(self):
        ctype, _, _ = self.wf.detect_challenge_type(
            user_request="pwn buffer overflow binary exploit readelf objdump"
        )
        self.assertEqual(ctype, "binary")

    def test_crypto_detection(self):
        ctype, _, _ = self.wf.detect_challenge_type(
            user_request="decode this base64 xor cipher aes hash"
        )
        self.assertEqual(ctype, "crypto")

    def test_forensics_detection(self):
        ctype, _, _ = self.wf.detect_challenge_type(
            user_request="analyze this pcap memory dump forensics stego image"
        )
        self.assertEqual(ctype, "forensics")

    def test_misc_detection(self):
        ctype, _, _ = self.wf.detect_challenge_type(
            user_request="misc puzzle riddle"
        )
        self.assertEqual(ctype, "misc")

    def test_no_signals_defaults_to_misc(self):
        ctype, conf, reasons = self.wf.detect_challenge_type(
            user_request="zzz qqq completely unrelated"
        )
        self.assertEqual(ctype, "misc")
        self.assertEqual(conf, 0.0)
        self.assertEqual(reasons, [])

    def test_filename_extensions(self):
        ctype, _, _ = self.wf.detect_challenge_type(
            user_request="look at these files",
            filenames=["sample.bin"],
        )
        self.assertEqual(ctype, "binary")

    def test_observations_signals(self):
        ctype, _, _ = self.wf.detect_challenge_type(
            user_request="what is this?",
            observations=["the server responded with x-powered-by: express"],
        )
        self.assertEqual(ctype, "web")

    def test_web_wins_tie(self):
        ctype, _, _ = self.wf.detect_challenge_type(
            user_request="http login page with a binary file upload"
        )
        self.assertEqual(ctype, "web")

    def test_all_types_supported(self):
        for t in CHALLENGE_TYPES:
            workflow = self.wf.workflow_for(t)
            self.assertTrue(workflow, f"empty workflow for {t}")
            self.assertTrue(all("title" in s and "tools" in s for s in workflow))


class TestWorkflows(unittest.TestCase):
    def setUp(self):
        self.wf = WorkflowManager()

    def test_web_workflow_steps(self):
        steps = self.wf.workflow_for("web")
        titles = [s["title"] for s in steps]
        self.assertIn("Initial inspection of the target", titles)
        self.assertIn("Discover endpoints and hidden files", titles)
        self.assertIn("Targeted parameter and payload testing", titles)
        # Web workflow should reference web tools.
        all_tools = [t for s in steps for t in s["tools"]]
        self.assertIn("inspect_webpage", all_tools)
        self.assertIn("enumerate_directories", all_tools)

    def test_binary_workflow_steps(self):
        steps = self.wf.workflow_for("binary")
        all_tools = [t for s in steps for t in s["tools"]]
        self.assertIn("binary_file_info", all_tools)
        self.assertIn("binary_checksec", all_tools)
        self.assertIn("binary_strings", all_tools)

    def test_crypto_workflow_includes_decoders(self):
        steps = self.wf.workflow_for("crypto")
        all_tools = [t for s in steps for t in s["tools"]]
        self.assertIn("decode_data", all_tools)
        self.assertIn("calculate_file_hash", all_tools)

    def test_unknown_type_falls_back(self):
        steps = self.wf.workflow_for("nonsense")
        self.assertTrue(steps)

    def test_workflow_title(self):
        self.assertIn("Web", self.wf.workflow_title("web"))
        self.assertIn("Binary", self.wf.workflow_title("binary"))


class TestRecommendedTools(unittest.TestCase):
    def setUp(self):
        self.wf = WorkflowManager()

    def test_recommended_skips_used(self):
        rec = self.wf.recommended_tools(
            "web",
            used_tools=["http_get"],
            available_tools=["http_get", "inspect_webpage", "analyze_headers",
                             "read_robots_txt"],
            limit=10,
        )
        self.assertNotIn("http_get", rec)
        self.assertIn("inspect_webpage", rec)

    def test_recommended_skips_unavailable(self):
        rec = self.wf.recommended_tools(
            "web",
            available_tools=["http_get"],
            limit=10,
        )
        self.assertTrue(all(t in {"http_get"} for t in rec))

    def test_recommended_limit(self):
        rec = self.wf.recommended_tools(
            "web",
            available_tools=["http_get", "inspect_webpage", "analyze_headers",
                             "manage_cookies", "read_robots_txt",
                             "extract_forms_from_page", "enumerate_directories"],
            limit=3,
        )
        self.assertLessEqual(len(rec), 3)


class TestProgressEvaluation(unittest.TestCase):
    def setUp(self):
        self.wf = WorkflowManager()

    def _plan(self, ctype="web", available=None):
        plan = Planner()
        plan.new_plan(ctype, available or [
            "http_get", "inspect_webpage", "analyze_headers", "manage_cookies",
            "read_robots_txt", "enumerate_directories",
        ])
        return plan

    def test_flag_confirmed_stops(self):
        plan = self._plan()
        log = EvidenceLog()
        log.record("http_get", {}, type(
            "R", (), {"success": True, "output": "flag{abc}", "error": None,
                      "truncated": False, "timed_out": False})())
        progress = self.wf.evaluate_progress(plan, log)
        self.assertFalse(progress["more_investigation_required"])
        self.assertEqual(progress["flag_status"], "confirmed")
        self.assertIn("Flag confirmed", progress["reason"])

    def test_plan_complete_stops(self):
        plan = self._plan()
        # Use every tool so all steps are addressed.
        for tool in plan.used_tools() + ["http_get", "inspect_webpage",
                                          "analyze_headers", "manage_cookies",
                                          "read_robots_txt", "enumerate_directories"]:
            plan.mark_tool_used(tool)
        log = EvidenceLog()
        progress = self.wf.evaluate_progress(plan, log)
        self.assertFalse(progress["more_investigation_required"])
        self.assertEqual(progress["flag_status"], "none")

    def test_more_investigation_when_steps_remain(self):
        plan = self._plan()
        log = EvidenceLog()
        progress = self.wf.evaluate_progress(plan, log)
        self.assertTrue(progress["more_investigation_required"])
        self.assertGreater(progress["total_steps"], 0)

    def test_no_plan(self):
        log = EvidenceLog()
        progress = self.wf.evaluate_progress(None, log)
        self.assertTrue(progress["more_investigation_required"])
        self.assertEqual(progress["completed_steps"], 0)


if __name__ == "__main__":
    unittest.main()
