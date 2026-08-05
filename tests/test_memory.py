"""Stage 6 tests: session memory."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.memory import CATEGORIES, SessionMemory


class TestMemoryBasics(unittest.TestCase):
    def test_add_and_get(self):
        m = SessionMemory()
        m.add_url("http://example.com/")
        self.assertEqual(m.get("urls"), ["http://example.com/"])

    def test_deduplication(self):
        m = SessionMemory()
        self.assertTrue(m.add("urls", "http://example.com/"))
        self.assertFalse(m.add("urls", "http://example.com/"))  # duplicate
        self.assertFalse(m.add("urls", "HTTP://example.com/"))  # case-insensitive
        self.assertEqual(len(m.get("urls")), 1)

    def test_ignores_empty(self):
        m = SessionMemory()
        self.assertFalse(m.add("urls", ""))
        self.assertFalse(m.add("urls", "   "))
        self.assertEqual(m.total(), 0)

    def test_categories_exist(self):
        m = SessionMemory()
        for c in CATEGORIES:
            m.add(c, f"value-{c}")
            self.assertEqual(m.get(c), [f"value-{c}"])

    def test_all_returns_copy(self):
        m = SessionMemory()
        m.add_url("http://x/")
        data = m.all()
        data["urls"].append("mutated")
        self.assertEqual(len(m.get("urls")), 1)

    def test_clear(self):
        m = SessionMemory()
        m.add_url("http://x/")
        m.add_flag("flag{a}")
        m.clear()
        self.assertEqual(m.total(), 0)

    def test_counts(self):
        m = SessionMemory()
        m.add_url("http://a/")
        m.add_url("http://b/")
        m.add_flag("flag{x}")
        counts = m.counts()
        self.assertEqual(counts["urls"], 2)
        self.assertEqual(counts["flags"], 1)

    def test_cap_limits_total(self):
        m = SessionMemory(max_entries=5)
        for i in range(20):
            m.add("urls", f"http://u{i}/")
        self.assertLessEqual(m.total(), 5)


class TestConvenienceAdders(unittest.TestCase):
    def test_add_cookie_stores_name_only(self):
        m = SessionMemory()
        m.add_cookie("session")
        self.assertEqual(m.get("cookies"), ["session"])

    def test_add_decoded(self):
        m = SessionMemory()
        m.add_decoded("base64", "SGVsbG8=")
        self.assertIn("base64", m.get("decoded")[0])

    def test_add_technology(self):
        m = SessionMemory()
        m.add_technology("nginx")
        self.assertEqual(m.get("technologies"), ["nginx"])

    def test_add_file(self):
        m = SessionMemory()
        m.add_file("test/sample.bin")
        self.assertEqual(m.get("files"), ["test/sample.bin"])

    def test_add_flag(self):
        m = SessionMemory()
        m.add_flag("flag{abc}")
        self.assertEqual(m.get("flags"), ["flag{abc}"])


class TestRememberToolResult(unittest.TestCase):
    def setUp(self):
        self.m = SessionMemory()

    def test_urls_extracted_from_output(self):
        self.m.remember_tool_result("http_get", {"url": "http://t/"}, "Final URL: http://t/ OK")
        self.assertIn("http://t/", self.m.get("urls"))

    def test_files_from_arguments(self):
        self.m.remember_tool_result("binary_strings", {"path": "test/sample.bin"}, "some strings")
        self.assertIn("test/sample.bin", self.m.get("files"))

    def test_decode_data_records_decoded(self):
        self.m.remember_tool_result("decode_data", {"data": "SGk=", "encoding": "base64"}, "Hi")
        self.assertTrue(any("base64" in d for d in self.m.get("decoded")))

    def test_cookie_names_from_session_tools(self):
        self.m.remember_tool_result(
            "manage_cookies", {"operation": "show"},
            "session = abc123\nother = xyz",
        )
        self.assertIn("session", self.m.get("cookies"))
        self.assertIn("other", self.m.get("cookies"))

    def test_flag_extracted(self):
        self.m.remember_tool_result("search_files", {}, "found flag{stage6_test_only} here")
        self.assertIn("flag{stage6_test_only}", self.m.get("flags"))

    def test_technologies_from_detection(self):
        self.m.remember_tool_result(
            "detect_server", {}, "Server: nginx/1.18.0"
        )
        self.assertIn("nginx", self.m.get("technologies"))

    def test_endpoints_from_discovery(self):
        self.m.remember_tool_result(
            "enumerate_directories", {"url": "http://t/"},
            "/admin -> status 200\n/api -> status 200",
        )
        endpoints = self.m.get("endpoints")
        self.assertTrue(any("/admin" in e for e in endpoints) or "/admin" in endpoints)
        self.assertTrue(any("/api" in e for e in endpoints) or "/api" in endpoints)

    def test_null_output_safe(self):
        self.m.remember_tool_result("http_get", {"url": "http://t/"}, None)
        self.assertEqual(self.m.total(), 0)


class TestPromptRendering(unittest.TestCase):
    def test_to_prompt_empty(self):
        m = SessionMemory()
        text = m.to_prompt()
        self.assertIn("Session Memory", text)
        self.assertIn("no discoveries", text)

    def test_to_prompt_with_data(self):
        m = SessionMemory()
        m.add_url("http://x/")
        m.add_technology("nginx")
        text = m.to_prompt()
        self.assertIn("URLs (1): http://x/", text)
        self.assertIn("Technologies (1): nginx", text)

    def test_to_prompt_truncates(self):
        m = SessionMemory()
        for i in range(50):
            m.add("urls", f"http://very-long-url-{i}/")
        text = m.to_prompt(max_chars=300)
        self.assertLessEqual(len(text), 300 + len("... [memory truncated]") + 1)

    def test_summary(self):
        m = SessionMemory()
        m.add_url("http://x/")
        m.add_flag("flag{a}")
        s = m.summary()
        self.assertIn("urls=1", s)
        self.assertIn("flags=1", s)

    def test_summary_empty(self):
        m = SessionMemory()
        self.assertIn("empty", m.summary())


if __name__ == "__main__":
    unittest.main()
