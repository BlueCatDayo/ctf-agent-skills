"""Stage 7 resource limits tests (spec 16)."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from specialists.limits import ResourceLimits


class TestResourceLimits(unittest.TestCase):
    def setUp(self):
        self.limits = ResourceLimits(
            max_specialist_calls=2,
            max_http_requests=3,
            max_command_executions=2,
            max_duplicate_actions=2,
            duplicate_window=60,
            global_timeout_seconds=0,  # disabled for most tests
        )
        self.limits.start_challenge()

    def test_http_request_cap(self):
        for i in range(3):
            allowed, _ = self.limits.check_tool("http_get", {"url": f"x{i}"})
            self.assertTrue(allowed)
            self.limits.record_action("http_get", {"url": f"x{i}"})
        allowed, reason = self.limits.check_tool("http_get", {"url": "y"})
        self.assertFalse(allowed)
        self.assertIn("Maximum HTTP requests", reason)

    def test_command_execution_cap(self):
        for _ in range(2):
            self.limits.record_action("run_ctf_command", {"command": "file x"})
        allowed, reason = self.limits.check_tool("run_ctf_command", {"command": "strings y"})
        self.assertFalse(allowed)
        self.assertIn("Maximum command executions", reason)

    def test_specialist_call_cap(self):
        self.assertTrue(self.limits.check_specialist()[0])
        self.limits.record_specialist_call()
        self.limits.record_specialist_call()
        allowed, reason = self.limits.check_specialist()
        self.assertFalse(allowed)
        self.assertIn("Maximum specialist calls", reason)

    def test_duplicate_action_detection(self):
        args = {"url": "http://x/page", "method": "GET"}
        for _ in range(2):
            self.limits.record_action("http_get", args)
        allowed, reason = self.limits.check_tool("http_get", args)
        self.assertFalse(allowed)
        self.assertIn("Duplicate action", reason)

    def test_different_args_not_duplicates(self):
        self.limits.record_action("http_get", {"url": "a"})
        self.limits.record_action("http_get", {"url": "b"})
        allowed, _ = self.limits.check_tool("http_get", {"url": "c"})
        self.assertTrue(allowed)

    def test_global_timeout(self):
        limits = ResourceLimits(global_timeout_seconds=1)
        limits.start_challenge()
        time.sleep(1.1)
        allowed, reason = limits.check_tool("http_get")
        self.assertFalse(allowed)
        self.assertIn("timeout", reason)

    def test_limits_reached_flag(self):
        self.assertFalse(self.limits.limits_reached())
        for _ in range(3):
            self.limits.record_action("http_get", {"url": "x"})
        self.assertTrue(self.limits.limits_reached())

    def test_reset_clears_counters(self):
        for _ in range(3):
            self.limits.record_action("http_get", {"url": "x"})
        self.limits.reset()
        self.assertFalse(self.limits.limits_reached())
        allowed, _ = self.limits.check_tool("http_get", {"url": "x"})
        self.assertTrue(allowed)

    def test_usage_summary(self):
        self.limits.record_action("http_get", {"url": "x"})
        usage = self.limits.usage()
        self.assertEqual(usage["http_requests"], 1)
        summary = self.limits.summary()
        self.assertIn("HTTP", summary)

    def test_file_tools_not_counted_as_commands(self):
        for _ in range(5):
            self.limits.record_action("read_text_file", {"path": "a.txt"})
        allowed, _ = self.limits.check_tool("run_ctf_command", {"command": "file x"})
        self.assertTrue(allowed)


if __name__ == "__main__":
    unittest.main()
