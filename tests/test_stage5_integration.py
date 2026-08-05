"""Stage 5 integration tests: registry wiring, prompt, and tool count."""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from tools.registry import ToolRegistry


def build_registry() -> ToolRegistry:
    """Build the real tool registry from main.py."""
    import main
    return main._build_tool_registry(Config.from_env())


STAGE5_TOOLS = [
    "http_get",
    "http_post",
    "http_put",
    "http_delete",
    "manage_cookies",
    "analyze_headers",
    "read_robots_txt",
    "read_sitemap_xml",
    "extract_links_from_page",
    "extract_forms_from_page",
    "extract_javascript_from_page",
    "extract_html_comments",
    "enumerate_directories",
    "discover_api_endpoints",
    "discover_hidden_endpoints",
    "binary_file_info",
    "binary_strings",
    "binary_readelf",
    "binary_objdump",
    "binary_symbols",
    "binary_libraries",
    "binary_hexdump",
    "binary_checksec",
    "analyze_binary",
    "find_login_page",
    "find_admin_page",
    "find_api_endpoints",
    "find_backup_files",
    "detect_framework",
    "detect_server",
    "detect_technology_stack",
    "extract_emails",
    "extract_version_info",
]


class TestStage5Registry(unittest.TestCase):
    def test_all_stage5_tools_registered(self):
        reg = build_registry()
        names = {t["name"] for t in reg.list_tools()}
        for name in STAGE5_TOOLS:
            self.assertIn(name, names, f"missing tool: {name}")

    def test_original_tools_preserved(self):
        reg = build_registry()
        names = {t["name"] for t in reg.list_tools()}
        for name in (
            "list_files", "read_text_file", "inspect_file", "search_files",
            "calculate_file_hash", "decode_data", "run_ctf_command",
            "http_request", "inspect_webpage", "extract_web_elements",
            "compare_http_responses", "manage_http_session",
        ):
            self.assertIn(name, names)

    def test_tool_categories(self):
        reg = build_registry()
        tools = {t["name"]: t for t in reg.list_tools()}
        self.assertEqual(tools["binary_file_info"]["category"], "binary")
        self.assertEqual(tools["http_get"]["category"], "web")
        self.assertEqual(tools["decode_data"]["category"], "data")

    def test_execute_decode_data_extended_octal(self):
        reg = build_registry()
        result = reg.execute("decode_data", {"data": "110 145 154 154 157", "encoding": "octal"})
        self.assertTrue(result.success)
        self.assertIn("Hello", result.output)

    def test_execute_decode_data_jwt(self):
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"flag": "fake_flag"}).encode()).rstrip(b"=").decode()
        result = build_registry().execute("decode_data", {"data": f"{header}.{payload}.", "encoding": "jwt"})
        self.assertTrue(result.success)
        self.assertIn("fake_flag", result.output)

    def test_binary_tools_graceful_without_command(self):
        reg = build_registry()
        with patch("tools.binary_tools._command_available", return_value=False):
            result = reg.execute("binary_file_info", {"path": "test/nonexistent.bin"})
        self.assertIn("not available", result.output.lower())


class TestStage5Prompt(unittest.TestCase):
    def test_prompt_has_ctf_rules(self):
        from agent.prompts import SYSTEM_PROMPT
        for phrase in (
            "experienced CTF player",
            "NEVER hallucinate a flag",
            "Think step by step",
            "Evidence",
            "Confirmed findings",
            "authorized",
            "workspace",
            "Do not reveal API keys",
            "Do not access files outside the authorized workspace",
        ):
            self.assertIn(phrase, SYSTEM_PROMPT, f"missing phrase: {phrase}")

    def test_prompt_has_placeholders(self):
        from agent.prompts import (
            ACTIVE_SKILLS_PLACEHOLDER,
            SKILL_CONTEXT_PLACEHOLDER,
            SYSTEM_PROMPT,
        )
        self.assertIn(ACTIVE_SKILLS_PLACEHOLDER, SYSTEM_PROMPT)
        self.assertIn(SKILL_CONTEXT_PLACEHOLDER, SYSTEM_PROMPT)

    def test_prompt_mentions_new_tool_families(self):
        from agent.prompts import SYSTEM_PROMPT
        for phrase in (
            "analyze_headers",
            "read_robots_txt",
            "discover_api_endpoints",
            "binary_checksec",
            "analyze_binary",
            "find_login_page",
            "octal",
            "JWT",
        ):
            self.assertIn(phrase, SYSTEM_PROMPT, f"missing phrase: {phrase}")


class TestStage5Workflows(unittest.TestCase):
    def test_prompt_has_web_workflow(self):
        from agent.prompts import SYSTEM_PROMPT
        self.assertIn("Web Workflow", SYSTEM_PROMPT)

    def test_prompt_has_binary_workflow(self):
        from agent.prompts import SYSTEM_PROMPT
        self.assertIn("Binary Workflow", SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
