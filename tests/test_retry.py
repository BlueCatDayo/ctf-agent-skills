"""Stage 6 tests: retry logic for transient tool failures."""

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.registry import ToolResult
from tools.retry import execute_with_retry, is_transient_failure


def result(**kwargs):
    """Build a ToolResult with defaults."""
    defaults = {
        "success": True,
        "tool": "t",
        "output": "",
        "error": None,
        "truncated": False,
        "timed_out": False,
    }
    defaults.update(kwargs)
    return ToolResult(**defaults)


class TestIsTransientFailure(unittest.TestCase):
    def test_timed_out_flag_is_transient(self):
        r = result(success=False, timed_out=True)
        self.assertTrue(is_transient_failure(r))

    def test_timeout_error_text(self):
        r = result(success=False, error="Request timed out after 30s")
        self.assertTrue(is_transient_failure(r))

    def test_connection_reset(self):
        r = result(success=False, error="Connection reset by peer")
        self.assertTrue(is_transient_failure(r))

    def test_connection_refused(self):
        r = result(success=False, error="Connection refused")
        self.assertTrue(is_transient_failure(r))

    def test_econnrefused(self):
        r = result(success=False, error="[Errno 111] ECONNREFUSED")
        self.assertTrue(is_transient_failure(r))

    def test_503_service_unavailable(self):
        r = result(success=False, error="503 Service Unavailable")
        self.assertTrue(is_transient_failure(r))

    def test_502_bad_gateway(self):
        r = result(success=False, error="502 Bad Gateway")
        self.assertTrue(is_transient_failure(r))

    def test_temporary_network_error(self):
        r = result(success=False, error="temporary network error")
        self.assertTrue(is_transient_failure(r))

    def test_too_many_redirects(self):
        r = result(success=False, error="too many redirects")
        self.assertTrue(is_transient_failure(r))

    def test_permanent_error_not_transient(self):
        r = result(success=False, error="Invalid base64 input data")
        self.assertFalse(is_transient_failure(r))

    def test_security_error_not_transient(self):
        r = result(success=False, error="Workspace security error: path outside workspace")
        self.assertFalse(is_transient_failure(r))

    def test_validation_error_not_transient(self):
        r = result(success=False, error="Missing required argument: url")
        self.assertFalse(is_transient_failure(r))

    def test_success_not_transient(self):
        self.assertFalse(is_transient_failure(result(success=True)))

    def test_none_result(self):
        self.assertFalse(is_transient_failure(None))


class FakeRegistry:
    """Registry stub that returns a scripted sequence of results."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def execute(self, name, arguments, workspace_root=None):
        self.calls.append((name, arguments))
        return self._results.pop(0)


class TestExecuteWithRetry(unittest.TestCase):
    def test_success_no_retry(self):
        r = FakeRegistry([result(success=True, output="ok")])
        out = execute_with_retry(r, "t", {}, max_retries=3, delay=0)
        self.assertTrue(out.success)
        self.assertEqual(len(r.calls), 1)

    def test_retries_then_succeeds(self):
        r = FakeRegistry([
            result(success=False, timed_out=True),
            result(success=True, output="recovered"),
        ])
        out = execute_with_retry(r, "t", {}, max_retries=2, delay=0)
        self.assertTrue(out.success)
        self.assertEqual(len(r.calls), 2)

    def test_retries_then_gives_up(self):
        failures = [
            result(success=False, timed_out=True),
            result(success=False, timed_out=True),
            result(success=False, timed_out=True),
        ]
        r = FakeRegistry(failures)
        out = execute_with_retry(r, "t", {}, max_retries=2, delay=0)
        self.assertFalse(out.success)
        self.assertEqual(len(r.calls), 3)  # 1 attempt + 2 retries

    def test_permanent_error_no_retry(self):
        r = FakeRegistry([result(success=False, error="Invalid input")])
        out = execute_with_retry(r, "t", {}, max_retries=3, delay=0)
        self.assertFalse(out.success)
        self.assertEqual(len(r.calls), 1)

    def test_workspace_root_passed_through(self):
        seen = {}
        def execute(name, arguments, workspace_root=None):
            seen["root"] = workspace_root
            return result(success=True)
        reg = Mock()
        reg.execute.side_effect = execute
        execute_with_retry(reg, "t", {}, workspace_root="/tmp/ws", delay=0)
        self.assertEqual(seen["root"], "/tmp/ws")

    def test_logger_reports_retries(self):
        logs = []
        r = FakeRegistry([
            result(success=False, timed_out=True),
            result(success=True),
        ])
        execute_with_retry(r, "t", {}, max_retries=2, delay=0, logger=logs.append)
        self.assertTrue(any("RETRY" in log for log in logs))

    def test_delay_sleeps_between_attempts(self):
        r = FakeRegistry([
            result(success=False, timed_out=True),
            result(success=True),
        ])
        with patch("tools.retry.time.sleep") as mock_sleep:
            execute_with_retry(r, "t", {}, max_retries=2, delay=1.5)
        mock_sleep.assert_called_once_with(1.5)

    def test_zero_delay_does_not_sleep(self):
        r = FakeRegistry([
            result(success=False, timed_out=True),
            result(success=True),
        ])
        with patch("tools.retry.time.sleep") as mock_sleep:
            execute_with_retry(r, "t", {}, max_retries=2, delay=0)
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
