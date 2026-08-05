"""Tests for Stage 5 binary tools with graceful unavailability handling."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import binary_tools
from tools.workspace import WorkspaceError


class TestCommandAvailability(unittest.TestCase):
    def test_unsupported_command_rejected(self):
        out = binary_tools._run("rm", ["-rf"], "x", None)
        self.assertIn("Error", out)
        self.assertIn("Unsupported", out)

    def test_missing_command_friendly_error(self):
        with patch.object(binary_tools, "_command_available", return_value=False):
            out = binary_tools.binary_file_info("test.bin", "/tmp")
        self.assertIn("not available", out.lower())
        self.assertIn("file", out.lower())

    def test_checksec_missing_hint(self):
        with patch.object(binary_tools, "_command_available", return_value=False):
            out = binary_tools.binary_checksec("test.bin", "/tmp")
        self.assertIn("not available", out.lower())
        self.assertIn("checksec", out.lower())


class TestPathResolution(unittest.TestCase):
    def test_path_outside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(WorkspaceError):
                binary_tools._resolve_path("../outside.txt", tmp)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(WorkspaceError):
                binary_tools._resolve_path("nope.bin", tmp)

    def test_valid_path_resolves(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sample.bin")
            with open(target, "wb") as f:
                f.write(b"hello")
            resolved = binary_tools._resolve_path("sample.bin", tmp)
            self.assertTrue(os.path.exists(resolved))
            self.assertEqual(os.path.basename(resolved), "sample.bin")


class TestRunFunction(unittest.TestCase):
    def test_run_uses_shell_false_and_argv(self):
        """The subprocess call must use a list argv and shell=False."""
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sample.bin")
            with open(target, "wb") as f:
                f.write(b"data")
            with patch.object(
                binary_tools,
                "_command_available",
                return_value=True,
            ), patch(
                "tools.binary_tools.subprocess.run"
            ) as mock_run:
                mock_run.return_value.stdout = "ok output"
                mock_run.return_value.stderr = ""
                mock_run.return_value.returncode = 0
                out = binary_tools.binary_strings("sample.bin", 4, tmp)
            args = mock_run.call_args[0][0]
            self.assertIsInstance(args, list)
            self.assertEqual(args[0], "strings")
            self.assertFalse(mock_run.call_args.kwargs.get("shell", True))
            self.assertIn("ok output", out)

    def test_run_timeout(self):
        import subprocess as _sp
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sample.bin")
            with open(target, "wb") as f:
                f.write(b"data")
            with patch.object(
                binary_tools,
                "_command_available",
                return_value=True,
            ), patch(
                "tools.binary_tools.subprocess.run",
                side_effect=_sp.TimeoutExpired("strings", 30),
            ):
                out = binary_tools.binary_file_info("sample.bin", tmp)
        self.assertIn("timed out", out.lower())


class subprocess_timeout(Exception):
    pass


def _raise_timeout(*args, **kwargs):
    raise __import__("subprocess").TimeoutExpired("strings", 30)


class TestIndividualHelpers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = os.path.join(self.tmp.name, "sample.bin")
        with open(self.target, "wb") as f:
            f.write(b"ELF fake data with a flag{stage5_test_only} inside")

    def _patch_available(self):
        return patch.object(binary_tools, "_command_available", return_value=True)

    def _patch_run(self, stdout="out", stderr="", code=0):
        return patch(
            "tools.binary_tools.subprocess.run",
            return_value=type(
                "R", (), {"stdout": stdout, "stderr": stderr, "returncode": code}
            )(),
        )

    def test_binary_file_info(self):
        with self._patch_available(), self._patch_run("ELF 64-bit LSB"):
            out = binary_tools.binary_file_info("sample.bin", self.tmp.name)
        self.assertIn("ELF 64-bit LSB", out)

    def test_binary_strings_min_length_passed(self):
        with self._patch_available(), self._patch_run("strings here"):
            with patch("tools.binary_tools.subprocess.run") as m:
                m.return_value.stdout = "strings here"
                m.return_value.stderr = ""
                m.return_value.returncode = 0
                binary_tools.binary_strings("sample.bin", 6, self.tmp.name)
                args = m.call_args[0][0]
        self.assertIn("-n", args)
        self.assertIn("6", args)

    def test_binary_readelf_section_map(self):
        with self._patch_available(), self._patch_run("readelf out"):
            with patch("tools.binary_tools.subprocess.run") as m:
                m.return_value.stdout = "readelf out"
                m.return_value.stderr = ""
                m.return_value.returncode = 0
                binary_tools.binary_readelf("sample.bin", "sections", self.tmp.name)
                args = m.call_args[0][0]
        self.assertIn("-S", args)

    def test_binary_symbols_falls_back_to_objdump(self):
        with patch.object(binary_tools, "_command_available", side_effect=lambda c: c != "nm"):
            with patch("tools.binary_tools.subprocess.run") as m:
                m.return_value.stdout = "symbols"
                m.return_value.stderr = ""
                m.return_value.returncode = 0
                out = binary_tools.binary_symbols("sample.bin", self.tmp.name)
                args = m.call_args[0][0]
        self.assertEqual(args[0], "objdump")
        self.assertIn("symbols", out)

    def test_binary_hexdump_uses_xxd_when_available(self):
        with self._patch_available():
            with patch("tools.binary_tools.subprocess.run") as m:
                m.return_value.stdout = "00000000: 48 65 6c 6c 6f"
                m.return_value.stderr = ""
                m.return_value.returncode = 0
                binary_tools.binary_hexdump("sample.bin", 16, self.tmp.name)
                args = m.call_args[0][0]
        self.assertEqual(args[0], "xxd")

    def test_binary_hexdump_falls_back_to_hexdump(self):
        with patch.object(binary_tools, "_command_available", side_effect=lambda c: c != "xxd"):
            with patch("tools.binary_tools.subprocess.run") as m:
                m.return_value.stdout = "00000000  48 65 6c 6c 6f"
                m.return_value.stderr = ""
                m.return_value.returncode = 0
                binary_tools.binary_hexdump("sample.bin", 16, self.tmp.name)
                args = m.call_args[0][0]
        self.assertEqual(args[0], "hexdump")


class TestAnalyzeBinary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = os.path.join(self.tmp.name, "sample.bin")
        with open(self.target, "wb") as f:
            f.write(b"ELF fake with flag{stage5_test_only} and gets(")

    def test_analyze_binary_runs_workflow(self):
        with patch.object(binary_tools, "_command_available", return_value=True):
            with patch("tools.binary_tools.subprocess.run") as m:
                m.return_value.stdout = "fake tool output"
                m.return_value.stderr = ""
                m.return_value.returncode = 0
                out = binary_tools.analyze_binary("sample.bin", self.tmp.name)
        self.assertIn("file", out)
        self.assertIn("strings", out)
        self.assertIn("readelf", out)
        self.assertIn("objdump", out)
        self.assertIn("nm", out)
        self.assertIn("Interesting strings", out)

    def test_analyze_binary_checksec_skipped_when_missing(self):
        with patch.object(binary_tools, "_command_available", side_effect=lambda c: c != "checksec"):
            with patch("tools.binary_tools.subprocess.run") as m:
                m.return_value.stdout = "fake"
                m.return_value.stderr = ""
                m.return_value.returncode = 0
                out = binary_tools.analyze_binary("sample.bin", self.tmp.name)
        self.assertIn("checksec: not available", out)

    def test_analyze_binary_missing_file(self):
        out = binary_tools.analyze_binary("does_not_exist.bin", self.tmp.name)
        self.assertIn("Workspace error", out)

    def test_interesting_strings_finds_flag(self):
        with patch("tools.binary_tools.subprocess.run") as m:
            m.return_value.stdout = "some text flag{stage5_test_only} end"
            m.return_value.stderr = ""
            m.return_value.returncode = 0
            out = binary_tools._interesting_strings(self.target)
        self.assertIn("flag pattern", out)
        self.assertIn("stage5_test_only", out)


class TestMissingWorkspaceError(unittest.TestCase):
    def test_workspace_root_none_uses_default(self):
        # Default workspace is "challenges"; sample doesn't exist there.
        out = binary_tools.binary_file_info("no_such_file_anywhere.bin")
        self.assertIn("Workspace error", out)


if __name__ == "__main__":
    unittest.main()
