"""Tests for HTTP tools using httpx.MockTransport (no public sites)."""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from tools.http_session import HttpSessionManager
from tools.registry import ToolRegistry

FIXTURE_HTML = (Path(__file__).parent / "fixtures" / "test_page.html").read_text(encoding="utf-8")


def make_manager(handler) -> HttpSessionManager:
    """Create a session manager backed by a mock transport."""
    return HttpSessionManager(
        timeout=5,
        max_redirects=5,
        transport=httpx.MockTransport(handler),
    )


def patch_manager(handler):
    """Return (patcher, manager) that swaps in a mocked session manager."""
    mgr = make_manager(handler)
    return patch("tools.http_tools.session_manager", mgr), mgr


def simple_handler(body: str = "hello", status: int = 200, headers=None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body, headers=headers or {})
    return handler


class TestHttpRequestBasics(unittest.TestCase):
    def test_get_returns_status_and_body(self):
        p, _ = patch_manager(simple_handler("<html><body>ok</body></html>"))
        with p:
            from tools.http_tools import http_request
            out = http_request("http://example.com/")
        self.assertIn("Status code: 200", out)
        self.assertIn("ok", out)

    def test_blocked_scheme(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.http_tools import http_request
            out = http_request("ftp://example.com/file")
        self.assertIn("url_validation_error", out)
        self.assertIn("scheme", out.lower())

    def test_embedded_credentials_blocked(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.http_tools import http_request
            out = http_request("http://user:pass@example.com/")
        self.assertIn("url_validation_error", out)
        self.assertIn("credential", out.lower())

    def test_localhost_blocked(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.http_tools import http_request
            out = http_request("http://localhost:5000/")
        self.assertIn("url_validation_error", out)
        self.assertIn("localhost", out.lower())

    def test_private_ip_blocked(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.http_tools import http_request
            out = http_request("http://192.168.1.5/")
        self.assertIn("private", out.lower())

    def test_metadata_ip_blocked(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.http_tools import http_request
            out = http_request("http://169.254.169.254/latest/meta-data/")
        self.assertIn("blocked", out.lower())

    def test_redirect_limit(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "/again"})

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import http_request
            out = http_request("http://example.com/", follow_redirects=True)
        self.assertIn("too_many_redirects", out)

    def test_timeout_handling(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("simulated timeout")

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import http_request
            out = http_request("http://example.com/")
        self.assertIn("timeout", out.lower())
        self.assertIn("timed out", out.lower())

    def test_output_truncation(self):
        p, _ = patch_manager(simple_handler("x" * 5000))
        with p:
            from tools.http_tools import http_request
            out = http_request("http://example.com/", max_body_chars=100)
        self.assertIn("truncated", out)
        self.assertIn("Response length: 5000", out)

    def test_connection_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import http_request
            out = http_request("http://example.com/")
        self.assertIn("connection_error", out)


class TestHttpRequestBodies(unittest.TestCase):
    def test_json_request(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["content_type"] = request.headers.get("content-type", "")
            seen["body"] = request.content.decode("utf-8", errors="replace")
            return httpx.Response(200, text="ok")

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import http_request
            http_request(
                "http://example.com/api",
                method="POST",
                json_body={"user": "alice", "admin": True},
            )
        self.assertIn("application/json", seen["content_type"])
        self.assertEqual(json.loads(seen["body"]), {"user": "alice", "admin": True})

    def test_form_request(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["content_type"] = request.headers.get("content-type", "")
            seen["body"] = request.content.decode("utf-8", errors="replace")
            return httpx.Response(200, text="ok")

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import http_request
            http_request(
                "http://example.com/login",
                method="POST",
                form_data={"username": "bob", "password": "pw"},
            )
        self.assertIn("x-www-form-urlencoded", seen["content_type"])
        self.assertIn("username=bob", seen["body"])
        self.assertIn("password=pw", seen["body"])

    def test_custom_method(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            return httpx.Response(200, text="ok")

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import http_request
            http_request("http://example.com/", method="OPTIONS")
        self.assertEqual(seen["method"], "OPTIONS")


class TestCookiePersistence(unittest.TestCase):
    def test_cookies_persist_across_requests(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(200, headers={"Set-Cookie": "session=abc123; Path=/"}, text="first")
            return httpx.Response(200, text=request.headers.get("cookie", ""))

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import http_request
            http_request("http://example.com/")
            out2 = http_request("http://example.com/page")
        self.assertIn("session=abc123", out2)


class TestManageSessionTool(unittest.TestCase):
    def test_show_and_mask(self):
        p, mgr = patch_manager(simple_handler())
        with p:
            from tools.http_tools import manage_http_session
            mgr.set_cookie("sessionid", "super-secret", "example.com")
            out = manage_http_session("show")
        self.assertIn("sessionid", out)
        self.assertNotIn("super-secret", out)

    def test_reset(self):
        p, mgr = patch_manager(simple_handler())
        with p:
            from tools.http_tools import manage_http_session
            mgr.set_cookie("a", "1")
            out = manage_http_session("reset")
            out2 = manage_http_session("show")
        self.assertIn("reset", out.lower())
        self.assertIn("No cookies", out2)

    def test_set_header_masked(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.http_tools import manage_http_session
            out = manage_http_session(
                "set_header", header_name="Authorization", header_value="Bearer sekret123"
            )
        self.assertNotIn("sekret123", out)

    def test_unknown_operation(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.http_tools import manage_http_session
            out = manage_http_session("nope")
        self.assertIn("unknown operation", out.lower())


class TestInspectWebpage(unittest.TestCase):
    def test_title_and_tech(self):
        headers = {"Content-Type": "text/html", "Server": "nginx/1.24"}
        p, _ = patch_manager(simple_handler(FIXTURE_HTML, headers=headers))
        with p:
            from tools.http_tools import inspect_webpage
            out = inspect_webpage("http://example.com/")
        self.assertIn("Title: Stage 3 Test Page", out)
        self.assertIn("nginx", out.lower())
        self.assertIn("Forms (2):", out)

    def test_security_headers_reported(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        p, _ = patch_manager(simple_handler("<html><head><title>T</title></head></html>", headers=headers))
        with p:
            from tools.http_tools import inspect_webpage
            out = inspect_webpage("http://example.com/")
        self.assertIn("content-security-policy", out.lower())
        self.assertIn("strict-transport-security", out.lower())

    def test_flag_reported_only_from_output(self):
        # The fixture contains a hidden flag value; it must appear in tool output
        p, _ = patch_manager(simple_handler(FIXTURE_HTML))
        with p:
            from tools.http_tools import extract_web_elements
            out = extract_web_elements("http://example.com/", element_type="hidden_inputs")
        self.assertIn("flag{stage3_test_only}", out)


class TestExtractElements(unittest.TestCase):
    def test_links(self):
        p, _ = patch_manager(simple_handler(FIXTURE_HTML))
        with p:
            from tools.http_tools import extract_web_elements
            out = extract_web_elements("http://example.com/", element_type="links")
        self.assertIn("http://example.com/login", out)
        self.assertIn("http://example.com/api/users", out)

    def test_forms_with_hidden_inputs(self):
        p, _ = patch_manager(simple_handler(FIXTURE_HTML))
        with p:
            from tools.http_tools import extract_web_elements
            out = extract_web_elements("http://example.com/", element_type="forms")
        self.assertIn("POST -> http://example.com/api/search", out)
        self.assertIn("hidden=True", out)

    def test_hidden_inputs_only(self):
        p, _ = patch_manager(simple_handler(FIXTURE_HTML))
        with p:
            from tools.http_tools import extract_web_elements
            out = extract_web_elements("http://example.com/", element_type="hidden_inputs")
        self.assertIn("flag{stage3_test_only}", out)
        self.assertNotIn("username", out)

    def test_relative_urls_resolved(self):
        p, _ = patch_manager(simple_handler(FIXTURE_HTML))
        with p:
            from tools.http_tools import extract_web_elements
            out = extract_web_elements("http://example.com/", element_type="links")
        self.assertIn("http://example.com/", out)
        self.assertNotIn("href", out)

    def test_unsupported_element_type(self):
        p, _ = patch_manager(simple_handler(FIXTURE_HTML))
        with p:
            from tools.http_tools import extract_web_elements
            out = extract_web_elements("http://example.com/", element_type="xss")
        self.assertIn("unsupported element type", out.lower())


class TestCompareResponses(unittest.TestCase):
    def test_compare_same(self):
        p, _ = patch_manager(simple_handler("hello world"))
        with p:
            from tools.http_tools import compare_http_responses
            out = compare_http_responses(
                {"url": "a", "status_code": 200, "headers": {}, "cookies": {},
                 "body_length": 11, "body": "hello world", "redirects": []},
                {"url": "b", "status_code": 200, "headers": {}, "cookies": {},
                 "body_length": 11, "body": "hello world", "redirects": []},
            )
        self.assertIn("Status difference: A=200 B=200 (same)", out)
        self.assertIn("Body length difference: A=11 B=11 (same)", out)

    def test_compare_different(self):
        p, _ = patch_manager(simple_handler("hello world"))
        with p:
            from tools.http_tools import compare_http_responses
            out = compare_http_responses(
                {"url": "a", "status_code": 200, "headers": {"x-a": "1"}, "cookies": {},
                 "body_length": 11, "body": "hello world", "redirects": []},
                {"url": "b", "status_code": 403, "headers": {"x-a": "2"}, "cookies": {},
                 "body_length": 5, "body": "denied", "redirects": []},
            )
        self.assertIn("DIFFERENT", out)
        self.assertIn("Body similarity", out)

    def test_compare_via_urls(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen[request.url.path] = seen.get(request.url.path, 0) + 1
            return httpx.Response(200, text="same body")

        p, _ = patch_manager(handler)
        with p:
            from tools.http_tools import compare_http_responses
            out = compare_http_responses("http://example.com/a", "http://example.com/b")
        self.assertIn("Status difference", out)
        self.assertEqual(seen.get("/a"), 1)
        self.assertEqual(seen.get("/b"), 1)


class TestRegistryIntegration(unittest.TestCase):
    def test_new_tools_in_registry_definitions(self):
        from tools.http_tools import http_request, inspect_webpage, extract_web_elements
        registry = ToolRegistry()
        registry.register("http_request", http_request, "desc", {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]})
        registry.register("inspect_webpage", inspect_webpage, "desc", {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]})
        registry.register("extract_web_elements", extract_web_elements, "desc", {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]})
        defs = registry.get_definitions()
        names = [d["function"]["name"] for d in defs]
        self.assertIn("http_request", names)
        self.assertIn("inspect_webpage", names)
        self.assertIn("extract_web_elements", names)
        for d in defs:
            self.assertEqual(d["type"], "function")

    def test_unknown_tool(self):
        registry = ToolRegistry()
        result = registry.execute("http_request_missing", {})
        self.assertFalse(result.success)
        self.assertIn("unknown tool", result.error.lower())

    def test_malformed_arguments_missing_url(self):
        from tools.http_tools import http_request
        registry = ToolRegistry()
        registry.register(
            "http_request", http_request, "desc",
            {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
            required=["url"],
        )
        result = registry.execute("http_request", {})
        self.assertFalse(result.success)
        self.assertIn("missing required", result.error.lower())
