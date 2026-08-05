"""Tests for the HTTP session manager (cookies, headers, masking)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.http_session import (
    HttpSessionManager,
    is_sensitive_cookie,
    is_sensitive_header,
    mask_value,
)


class TestMasking(unittest.TestCase):
    def test_sensitive_header_detection(self):
        self.assertTrue(is_sensitive_header("Authorization"))
        self.assertTrue(is_sensitive_header("x-api-key"))
        self.assertTrue(is_sensitive_header("Set-Cookie"))
        self.assertFalse(is_sensitive_header("User-Agent"))

    def test_sensitive_cookie_detection(self):
        self.assertTrue(is_sensitive_cookie("sessionid"))
        self.assertTrue(is_sensitive_cookie("auth_token"))
        self.assertFalse(is_sensitive_cookie("theme"))

    def test_mask_value(self):
        self.assertEqual(mask_value("abcdef"), "abcd********")
        self.assertNotIn("abcdef", mask_value("abcdef")[4:])


class TestSessionManager(unittest.TestCase):
    def setUp(self):
        self.m = HttpSessionManager()

    def test_cookie_set_show_clear(self):
        self.m.set_cookie("theme", "dark", "example.com")
        out = self.m.show_cookies()
        self.assertIn("theme", out)
        self.assertIn("dark", out)  # non-sensitive value visible
        self.m.clear_cookies()
        out = self.m.show_cookies()
        self.assertIn("No cookies", out)

    def test_sensitive_cookie_masked(self):
        self.m.set_cookie("sessionid", "super-secret-value", "example.com")
        out = self.m.show_cookies()
        self.assertIn("sessionid", out)
        self.assertNotIn("super-secret-value", out)

    def test_set_remove_cookie(self):
        self.m.set_cookie("a", "1")
        out = self.m.remove_cookie("a")
        self.assertIn("removed", out.lower())
        out = self.m.remove_cookie("a")
        self.assertIn("not found", out.lower())

    def test_reset_clears_state(self):
        self.m.set_cookie("a", "1")
        self.m.set_header("X-Test", "yes")
        self.m.reset_session()
        out = self.m.show_cookies()
        self.assertIn("No cookies", out)

    def test_default_headers(self):
        self.m.set_header("X-Test", "hello")
        out = self.m.show_headers()
        self.assertIn("X-Test: hello", out)
        self.m.remove_header("X-Test")
        out = self.m.show_headers()
        self.assertNotIn("X-Test", out)

    def test_sensitive_header_masked(self):
        self.m.set_header("Authorization", "Bearer secret-token-xyz")
        out = self.m.show_headers()
        self.assertNotIn("secret-token-xyz", out)
        # Only the first few characters remain visible
        self.assertIn("Bear", out)

    def test_remove_missing_header(self):
        out = self.m.remove_header("X-Missing")
        self.assertIn("not found", out.lower())


class TestSessionManagerTransport(unittest.TestCase):
    def test_cookie_persistence_across_requests(self):
        import httpx

        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(200, headers={"Set-Cookie": "session=abc123; Path=/"}, text="first")
            # Second request should carry the cookie
            return httpx.Response(200, text=f"cookie={request.headers.get('cookie', '')}")

        m = HttpSessionManager(timeout=5, transport=httpx.MockTransport(handler))
        r1 = m.get_client().get("http://example.com/")
        m.cookies.update(r1.cookies)
        r2 = m.get_client().get("http://example.com/page")
        m.cookies.update(r2.cookies)
        self.assertIn("session=abc123", r2.text)

    def test_client_reuse_after_reset(self):
        import httpx

        m = HttpSessionManager(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, text="ok")
        ))
        r = m.get_client().get("http://example.com/")
        self.assertEqual(r.status_code, 200)
        m.reset_session()
        r2 = m.get_client().get("http://example.com/")
        self.assertEqual(r2.status_code, 200)
