"""Stage 6 tests: evidence log and structured report."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.evidence import EvidenceLog, format_structured_report
from tools.registry import ToolResult


def ok_result(output="result", **kwargs):
    """Build a successful ToolResult."""
    defaults = {
        "success": True, "tool": "t", "output": output, "error": None,
        "truncated": False, "timed_out": False,
    }
    defaults.update(kwargs)
    return ToolResult(**defaults)


def fail_result(error="boom", **kwargs):
    """Build a failed ToolResult."""
    defaults = {
        "success": False, "tool": "t", "output": "", "error": error,
        "truncated": False, "timed_out": False,
    }
    defaults.update(kwargs)
    return ToolResult(**defaults)


class TestEvidenceRecording(unittest.TestCase):
    def test_record_success(self):
        log = EvidenceLog()
        item = log.record("http_get", {"url": "http://x/"}, ok_result("hello"))
        self.assertEqual(item.tool, "http_get")
        self.assertTrue(item.success)
        self.assertIn("hello", item.output)
        self.assertTrue(log.has_items())

    def test_record_failure(self):
        log = EvidenceLog()
        item = log.record("http_get", {"url": "http://x/"}, fail_result("timeout"))
        self.assertFalse(item.success)
        self.assertIsNone(item.flag)

    def test_arguments_serialized(self):
        log = EvidenceLog()
        item = log.record("decode_data", {"data": "SGk=", "encoding": "base64"}, ok_result("Hi"))
        self.assertIn("base64", item.arguments)
        self.assertIn("SGk=", item.arguments)

    def test_string_arguments_accepted(self):
        log = EvidenceLog()
        item = log.record("run_ctf_command", '{"command": "file x"}', ok_result("out"))
        self.assertIn("file x", item.arguments)

    def test_cap_limits_entries(self):
        log = EvidenceLog(max_entries=5)
        for i in range(10):
            log.record("t", {"i": i}, ok_result(str(i)))
        self.assertEqual(len(log.items()), 5)

    def test_clear(self):
        log = EvidenceLog()
        log.record("t", {}, ok_result("x"))
        log.clear()
        self.assertFalse(log.has_items())

    def test_successful_and_failed_items(self):
        log = EvidenceLog()
        log.record("a", {}, ok_result("ok"))
        log.record("b", {}, fail_result("err"))
        self.assertEqual(len(log.successful_items()), 1)
        self.assertEqual(len(log.failed_items()), 1)


class TestFlagHandling(unittest.TestCase):
    def test_flag_detected_in_success(self):
        log = EvidenceLog()
        item = log.record("search_files", {}, ok_result("the flag is flag{stage6_test_only}"))
        self.assertEqual(item.flag, "flag{stage6_test_only}")
        self.assertTrue(log.has_flag())
        status, value = log.flag_status()
        self.assertEqual(status, "Confirmed")
        self.assertEqual(value, "flag{stage6_test_only}")

    def test_flag_in_failure_is_candidate_only(self):
        log = EvidenceLog()
        # A timed-out tool may return partial output containing a flag pattern.
        log.record(
            "http_get", {},
            fail_result(error="timeout", output="partial content flag{partial}"),
        )
        self.assertFalse(log.has_flag())
        status, value = log.flag_status()
        self.assertEqual(status, "Not Confirmed")
        self.assertEqual(log.candidate_flags(), ["flag{partial}"])

    def test_no_flag(self):
        log = EvidenceLog()
        log.record("t", {}, ok_result("no flag here"))
        status, value = log.flag_status()
        self.assertEqual(status, "Not Confirmed")
        self.assertIsNone(value)

    def test_flags_in_output_deduped(self):
        log = EvidenceLog()
        log.record("a", {}, ok_result("flag{one}"))
        log.record("b", {}, ok_result("flag{one} again"))
        self.assertEqual(log.flags_in_output(), ["flag{one}"])


class TestConfirmedFindings(unittest.TestCase):
    def test_findings_from_successful_outputs(self):
        log = EvidenceLog()
        log.record("http_get", {"url": "u"}, ok_result("Status 200, admin panel"))
        findings = log.confirmed_findings()
        self.assertEqual(len(findings), 1)
        self.assertIn("http_get", findings[0])
        self.assertIn("admin panel", findings[0])

    def test_findings_skip_failures(self):
        log = EvidenceLog()
        log.record("a", {}, fail_result("error"))
        log.record("b", {}, ok_result("real result"))
        findings = log.confirmed_findings()
        self.assertEqual(len(findings), 1)
        self.assertIn("real result", findings[0])

    def test_findings_include_flag(self):
        log = EvidenceLog()
        log.record("search_files", {}, ok_result("flag{abc}"))
        findings = log.confirmed_findings()
        self.assertIn("flag{abc}", findings[0])

    def test_findings_limit(self):
        log = EvidenceLog()
        for i in range(15):
            log.record("t", {"i": i}, ok_result(f"result {i}"))
        self.assertEqual(len(log.confirmed_findings(limit=3)), 3)

    def test_empty_findings(self):
        log = EvidenceLog()
        self.assertEqual(log.confirmed_findings(), [])


class TestRendering(unittest.TestCase):
    def test_to_prompt_empty(self):
        log = EvidenceLog()
        text = log.to_prompt()
        self.assertIn("Evidence Log", text)
        self.assertIn("no tool results", text)

    def test_to_prompt_with_items(self):
        log = EvidenceLog()
        log.record("http_get", {"url": "http://x/"}, ok_result("body"))
        text = log.to_prompt()
        self.assertIn("[ok] http_get", text)

    def test_report_lines_recent_only(self):
        log = EvidenceLog()
        for i in range(10):
            log.record("t", {"i": i}, ok_result(str(i)))
        lines = log.report_lines(limit=3)
        self.assertEqual(len(lines), 3)

    def test_summary(self):
        log = EvidenceLog()
        log.record("a", {}, ok_result("ok"))
        log.record("b", {}, ok_result("flag{x}"))
        s = log.summary()
        self.assertIn("2 results", s)
        self.assertIn("1 flag", s)

    def test_record_finding_helper(self):
        log = EvidenceLog()
        item = log.record_finding("http_get", "admin panel found")
        self.assertTrue(item.success)
        self.assertIn("admin panel found", item.output)


class TestStructuredReport(unittest.TestCase):
    def test_full_report_sections(self):
        report = format_structured_report(
            confirmed_findings=["[http_get] admin panel"],
            evidence_lines=["- [ok] http_get(...)"],
            flag_status="Confirmed",
            flag_value="flag{abc}",
            next_step="Test the login form.",
        )
        self.assertIn("## Investigation Report", report)
        self.assertIn("### Confirmed Findings", report)
        self.assertIn("### Evidence", report)
        self.assertIn("### Flag Status", report)
        self.assertIn("### Recommended Next Step", report)
        self.assertIn("flag{abc}", report)
        self.assertIn("Test the login form.", report)

    def test_report_empty_findings(self):
        report = format_structured_report([], [], "Not Confirmed", None, "Continue.")
        self.assertIn("(no confirmed findings yet)", report)
        self.assertIn("- Not Confirmed", report)

    def test_report_no_flag_value(self):
        report = format_structured_report([], [], "Not Confirmed", None, "Next")
        self.assertNotIn("`", report)


if __name__ == "__main__":
    unittest.main()
