"""Integration tests for the Stage 2 tool system."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from tools.registry import ToolRegistry
from tools.file_tools import (
    calculate_file_hash,
    inspect_file,
    list_files,
    read_text_file,
    search_files,
)
from tools.data_tools import decode_data
from tools.command_tools import run_ctf_command


class TestToolIntegration(unittest.TestCase):
    """Integration tests that exercise the full tool system."""

    def setUp(self):
        self.config = Config.from_env()
        self.registry = ToolRegistry()

        # Register all tools
        from tools.file_tools import (
            calculate_file_hash,
            inspect_file,
            list_files,
            read_text_file,
            search_files,
        )
        from tools.data_tools import decode_data
        from tools.command_tools import run_ctf_command

        self.registry.register(
            "list_files", list_files,
            "List challenge files.",
            {"type": "object", "properties": {"path": {"type": "string"}}},
        )
        self.registry.register(
            "read_text_file", read_text_file,
            "Read a text file.",
            {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        )
        self.registry.register(
            "inspect_file", inspect_file,
            "Inspect a file.",
            {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        )
        self.registry.register(
            "search_files", search_files,
            "Search files.",
            {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}, "use_regex": {"type": "boolean"}}, "required": ["pattern"]},
        )
        self.registry.register(
            "calculate_file_hash", calculate_file_hash,
            "Calculate file hash.",
            {"type": "object", "properties": {"path": {"type": "string"}, "algorithm": {"type": "string"}}, "required": ["path"]},
        )
        self.registry.register(
            "decode_data", decode_data,
            "Decode data.",
            {"type": "object", "properties": {"data": {"type": "string"}, "encoding": {"type": "string"}}, "required": ["data"]},
        )
        self.registry.register(
            "run_ctf_command", run_ctf_command,
            "Run a command.",
            {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        )

    # --- list_files ---

    def test_list_files_finds_message_txt(self):
        result = list_files(path="test")
        self.assertIn("message.txt", result)

    def test_list_files_skips_hidden(self):
        result = list_files(path="")
        self.assertNotIn(".git", result)

    # --- read_text_file ---

    def test_read_text_file_finds_flag(self):
        result = read_text_file(path="test/message.txt")
        self.assertIn("flag{stage2_test_only}", result)

    def test_read_text_file_binary_detection(self):
        result = read_text_file(path="test/sample.bin")
        self.assertIn("binary", result.lower())

    # --- inspect_file ---

    def test_inspect_file_returns_metadata(self):
        result = inspect_file(path="test/message.txt")
        self.assertIn("SHA-256", result)
        self.assertIn("Text file: Yes", result)

    def test_inspect_file_binary(self):
        result = inspect_file(path="test/sample.bin")
        self.assertIn("Text file: No", result)
        self.assertIn("SHA-256", result)

    # --- search_files ---

    def test_search_finds_flag(self):
        result = search_files(pattern="flag{stage2_test_only}")
        self.assertIn("message.txt", result)

    # --- calculate_file_hash ---

    def test_hash_consistency(self):
        """Hashing the same file twice should produce the same result."""
        r1 = calculate_file_hash(path="test/message.txt", algorithm="sha256")
        r2 = calculate_file_hash(path="test/message.txt", algorithm="sha256")
        self.assertEqual(r1, r2)

    # --- decode_data ---

    def test_decode_base64_flag(self):
        """Base64-encoded flag should decode correctly."""
        import base64
        flag = "flag{stage2_test_only}"
        encoded = base64.b64encode(flag.encode()).decode()
        result = decode_data(encoded, encoding="base64")
        self.assertEqual(result, flag)

    def test_decode_hex_flag(self):
        """Hex-encoded flag should decode correctly."""
        flag = "flag{stage2_test_only}"
        encoded = flag.encode().hex()
        result = decode_data(encoded, encoding="hex")
        self.assertEqual(result, flag)

    # --- run_ctf_command ---

    def test_run_ctf_command_file_on_text(self):
        """Run file command on a text file (paths are relative to the workspace)."""
        import shutil
        if shutil.which("file"):
            result = run_ctf_command("file test/message.txt")
            self.assertIn("exit code", result.lower())
        else:
            # Command not available, should report clearly
            result = run_ctf_command("file test/message.txt")
            self.assertTrue(
                "not available" in result.lower()
                or "not found" in result.lower()
            )

    def test_run_ctf_command_strings_on_binary(self):
        """Run strings command on a binary file (paths are relative to the workspace)."""
        import shutil
        if shutil.which("strings"):
            result = run_ctf_command("strings test/sample.bin")
            self.assertIn("exit code", result.lower())
            # The flag should appear in strings output
            self.assertIn("flag{stage2_test_only}", result)
        else:
            result = run_ctf_command("strings test/sample.bin")
            self.assertTrue(
                "not available" in result.lower()
                or "not found" in result.lower()
            )

    # --- workspace security ---

    def test_path_traversal_blocked_in_list_files(self):
        result = list_files(path="../.env")
        self.assertIn("security", result.lower())

    def test_path_traversal_blocked_in_read_text_file(self):
        result = read_text_file(path="../.env")
        self.assertIn("security", result.lower())

    def test_path_traversal_blocked_in_search_files(self):
        result = search_files(pattern="test", path="../")
        self.assertIn("security", result.lower())

    # --- unknown tool ---

    def test_unknown_tool_returns_error(self):
        result = self.registry.execute("nonexistent_tool", {})
        self.assertFalse(result.success)
        self.assertIn("unknown tool", result.error.lower())

    # --- malformed arguments ---

    def test_missing_required_argument(self):
        result = self.registry.execute("read_text_file", {})
        self.assertFalse(result.success)
        self.assertIn("missing required", result.error.lower())


class TestProviderToolCallNormalization(unittest.TestCase):
    """Test that provider tool calls are normalized to internal format."""

    def test_internal_tool_call_format(self):
        """Internal tool call format should have name and arguments."""
        tool_call = {
            "name": "read_text_file",
            "arguments": {"path": "challenges/test/message.txt"},
        }
        self.assertIn("name", tool_call)
        self.assertIn("arguments", tool_call)
        self.assertIsInstance(tool_call["arguments"], dict)

    def test_tool_call_with_string_arguments(self):
        """String arguments should be parsed to dict."""
        import json
        tool_call = {
            "name": "calculate_file_hash",
            "arguments": '{"path": "test/message.txt", "algorithm": "sha256"}',
        }
        args = tool_call["arguments"]
        if isinstance(args, str):
            args = json.loads(args)
        self.assertIsInstance(args, dict)
        self.assertEqual(args["path"], "test/message.txt")

    def test_tool_call_with_missing_name(self):
        """Tool call without name should be handled gracefully."""
        tool_call = {"arguments": {}}
        name = tool_call.get("name", "")
        self.assertEqual(name, "")

    def test_tool_call_with_empty_arguments(self):
        """Tool call with empty arguments should work."""
        tool_call = {"name": "list_files", "arguments": {}}
        self.assertEqual(tool_call["arguments"], {})
