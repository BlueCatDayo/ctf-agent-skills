"""Stage 7 JavaScript analysis tool tests (spec 6)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import js_analysis
from tools.workspace import WorkspaceError

SAMPLE = """
const API = "https://ctf.example.com/api";
fetch(API + "/admin/users", {method: "POST"});
const xhr = new XMLHttpRequest();
xhr.open("GET", "/graphql?query={__typename}");
xhr.send();
const ws = new WebSocket("wss://ctf.example.com/ws");
const KEY = "sk-abcdef1234567890abcdef";
const creds = { user: "admin", pass: "hunter2" };
if (user.role === "admin") { showAdmin(); }
//# sourceMappingURL=app.js.map
"""


class TestExtractors(unittest.TestCase):
    def test_extract_endpoints(self):
        endpoints = js_analysis.extract_javascript_endpoints(SAMPLE)
        self.assertIn("/admin/users", endpoints)
        self.assertIn("/graphql?query={__typename}", endpoints)

    def test_extract_api_base_urls(self):
        urls = js_analysis.extract_api_base_urls(SAMPLE)
        self.assertIn("https://ctf.example.com/api", urls)

    def test_extract_secrets(self):
        secrets = js_analysis.extract_javascript_secrets(SAMPLE)
        self.assertTrue(any("sk-abcdef1234567890abcdef" in s for s in secrets))

    def test_extract_hardcoded_credentials(self):
        creds = js_analysis.extract_hardcoded_credentials(SAMPLE)
        self.assertTrue(any("admin" in c and "hunter2" in c for c in creds))

    def test_extract_source_maps(self):
        maps = js_analysis.extract_source_map_refs(SAMPLE)
        self.assertTrue(any("app.js.map" in m for m in maps))

    def test_extract_fetch_calls(self):
        calls = js_analysis.extract_fetch_calls(SAMPLE)
        self.assertTrue(any("fetch" in c and "/admin/users" in c for c in calls))

    def test_extract_graphql(self):
        gql = js_analysis.extract_graphql_endpoints(SAMPLE)
        self.assertTrue(any("graphql" in g for g in gql))

    def test_extract_websockets(self):
        ws = js_analysis.extract_websocket_urls(SAMPLE)
        self.assertIn("wss://ctf.example.com/ws", ws)

    def test_extract_client_authorization(self):
        authz = js_analysis.extract_client_authorization(SAMPLE)
        self.assertTrue(any("role condition" in a for a in authz))

    def test_analyze_report_capped_and_labeled(self):
        report = js_analysis.analyze_javascript_text(SAMPLE)
        self.assertIn("# JavaScript Analysis", report)
        self.assertIn("Endpoints:", report)
        self.assertIn("/admin/users", report)
        self.assertIn("Hardcoded credentials:", report)

    def test_search_with_line_context(self):
        result = js_analysis.search_javascript_text(SAMPLE, r"WebSocket")
        self.assertIn("line 7", result)
        self.assertIn("WebSocket", result)

    def test_search_no_match(self):
        result = js_analysis.search_javascript_text(SAMPLE, r"nothere")
        self.assertIn("No matches", result)

    def test_search_invalid_regex(self):
        result = js_analysis.search_javascript_text(SAMPLE, "[")
        self.assertIn("invalid regex", result)


class TestBeautifier(unittest.TestCase):
    def test_braces_and_semicolons(self):
        out = js_analysis.beautify_javascript('function f(){if(a){b();}else{c();}}')
        self.assertIn("function f()", out)
        self.assertIn("b();", out)
        self.assertIn("}", out)

    def test_empty_input(self):
        self.assertEqual(js_analysis.beautify_javascript(""), "")

    def test_strings_preserved(self):
        out = js_analysis.beautify_javascript('var s = "a;{b}";')
        self.assertIn('"a;{b}"', out)


class TestFileTools(unittest.TestCase):
    def _fixture_dir(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

    def test_analyze_javascript_file(self):
        report = js_analysis.analyze_javascript_file(
            "sample.js", self._fixture_dir()
        )
        self.assertIn("File: sample.js", report)
        self.assertIn("Endpoints:", report)
        self.assertIn("/admin/users", report)

    def test_analyze_javascript_file_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = js_analysis.analyze_javascript_file("nope.js", tmp)
        self.assertIn("Workspace error", out)

    def test_analyze_javascript_file_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = js_analysis.analyze_javascript_file("../secret.js", tmp)
        self.assertIn("outside the workspace", out)

    def test_search_javascript_file(self):
        result = js_analysis.search_javascript_file("sample.js", "graphql", self._fixture_dir())
        self.assertIn("graphql", result)

    def test_analyze_javascript_url_validation_failure(self):
        # Localhost blocked by default -> request never reaches the network.
        out = js_analysis.analyze_javascript_url("http://localhost/x.js")
        self.assertIn("blocked", out.lower())


if __name__ == "__main__":
    unittest.main()
