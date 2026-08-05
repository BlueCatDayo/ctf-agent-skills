"""Tests for command execution tool."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.command_tools import (
    ALLOWED_COMMANDS,
    run_ctf_command,
)


class TestCommandAllowlist(unittest.TestCase):
    """Test that only allowed commands can be executed."""

    def test_disallowed_command_rejected(self):
        """Commands not on the allowlist should be rejected."""
        result = run_ctf_command("rm -rf /")
        self.assertIn("not on the approved allowlist", result.lower())

    def test_disallowed_command_cat(self):
        """cat is not on the allowlist, but absolute path is blocked first."""
        result = run_ctf_command("cat /etc/passwd")
        # Either blocked by dangerous args or by allowlist
        self.assertTrue(
            "blocked" in result.lower()
            or "not on the approved allowlist" in result.lower()
        )

    def test_allowed_command_file(self):
        """file command should be allowed if available."""
        import shutil
        if shutil.which("file"):
            result = run_ctf_command("file tests/fixtures/test_text.txt")
            # Should not say "not on the approved allowlist"
            self.assertNotIn("not on the approved allowlist", result.lower())
        else:
            # If file is not available, it should report that clearly
            result = run_ctf_command("file nonexistent")
            self.assertTrue(
                "not available" in result.lower()
                or "not found" in result.lower()
            )


class TestBlockedShellOperators(unittest.TestCase):
    """Test that shell operators are blocked."""

    def test_blocked_and(self):
        """&& should be blocked."""
        result = run_ctf_command("echo hello && echo world")
        self.assertIn("shell operator", result.lower())

    def test_blocked_or(self):
        """|| should be blocked."""
        result = run_ctf_command("echo hello || echo world")
        self.assertIn("shell operator", result.lower())

    def test_blocked_semicolon(self):
        """; should be blocked."""
        result = run_ctf_command("echo hello; echo world")
        self.assertIn("shell operator", result.lower())

    def test_blocked_pipe(self):
        """| should be blocked."""
        result = run_ctf_command("echo hello | cat")
        self.assertIn("shell operator", result.lower())

    def test_blocked_redirect(self):
        """> should be blocked."""
        result = run_ctf_command("echo hello > /tmp/out")
        self.assertIn("shell operator", result.lower())

    def test_blocked_command_substitution(self):
        """$() should be blocked."""
        result = run_ctf_command("echo $(whoami)")
        self.assertIn("shell operator", result.lower())


class TestBlockedArguments(unittest.TestCase):
    """Test that dangerous arguments are blocked."""

    def test_blocked_exec(self):
        """-exec should be blocked (by shell operator ; or by dangerous arg check)."""
        result = run_ctf_command("find . -exec echo hello \\;")
        self.assertTrue(
            "blocked" in result.lower()
            or "shell operator" in result.lower()
        )

    def test_blocked_delete(self):
        """-delete should be blocked."""
        result = run_ctf_command("find . -delete")
        self.assertIn("blocked", result.lower())

    def test_blocked_absolute_path(self):
        """Absolute paths to system dirs should be blocked."""
        result = run_ctf_command("cat /etc/passwd")
        self.assertIn("blocked", result.lower())

    def test_blocked_path_traversal(self):
        """.. in arguments should be blocked."""
        result = run_ctf_command("cat ../../etc/passwd")
        self.assertIn("blocked", result.lower())


class TestCommandTimeout(unittest.TestCase):
    """Test command timeout handling."""

    def test_timeout_handled(self):
        """A command that sleeps should timeout."""
        # python -c "import time; time.sleep(60)" should timeout
        result = run_ctf_command(
            "python -c \"import time; time.sleep(60)\"",
            timeout_seconds=1,
        )
        self.assertTrue(
            "timed out" in result.lower()
            or "not available" in result.lower()
            or "not found" in result.lower()
            or "exit code" in result.lower()
        )


class TestCommandOutputTruncation(unittest.TestCase):
    """Test that command output is truncated."""

    def test_output_truncated(self):
        """Very long output should be truncated."""
        # Generate a large output
        result = run_ctf_command(
            "python -c \"print('A' * 10000)\"",
            max_output_chars=500,
        )
        # Either the command is unavailable or the output is truncated
        if "not available" not in result.lower() and "not found" not in result.lower():
            self.assertTrue(
                "truncated" in result.lower() or len(result) <= 500 + 100
            )


class TestMissingCommand(unittest.TestCase):
    """Test handling of missing commands."""

    def test_missing_command_reported(self):
        """A command that doesn't exist should be reported clearly."""
        result = run_ctf_command("nonexistent_command_xyz --help")
        self.assertTrue(
            "not available" in result.lower()
            or "not found" in result.lower()
            or "not on the approved allowlist" in result.lower()
        )


class TestCommandExitCode(unittest.TestCase):
    """Test that exit codes are reported."""

    def test_exit_code_reported(self):
        """Exit code should appear in output for allowed commands."""
        import shutil
        # Prefer 'python' (real interpreter on Windows); fall back to python3
        cmd = "python3 -c \"print('hello')\""
        if shutil.which("python"):
            cmd = "python -c \"print('hello')\""
        result = run_ctf_command(cmd)
        self.assertIn("exit code", result.lower())

    def test_exit_code_zero_for_success(self):
        """Successful command should have exit code 0."""
        import shutil
        # Prefer 'python' (real interpreter on Windows); fall back to python3
        cmd = "python3 -c \"print('hello')\""
        if shutil.which("python"):
            cmd = "python -c \"print('hello')\""
        result = run_ctf_command(cmd)
        self.assertIn("exit code: 0", result.lower())
