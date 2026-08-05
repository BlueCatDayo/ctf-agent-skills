"""Tests for Stage 5 web tools using httpx.MockTransport (no public sites)."""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from tools.http_session import HttpSessionManager
from tools.registry import ToolRegistry


EMPTY_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
}

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


def routed_handler(routes):
    """Route by (method, path-suffix) -> (status, body, headers)."""
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for key, (status, body, headers) in routes.items():
            method, suffix = key
            if request.method == method and path.endswith(suffix):
                return httpx.Response(status, text=body, headers=headers or {})
        return httpx.Response(404, text="not found")
    return handler


class TestHttpMethodWrappers(unittest.TestCase):
    def test_http_get(self):
        p, _ = patch_manager(simple_handler("<html><body>get ok</body></html>"))
        with p:
            from tools.web_tools import http_get
            out = http_get("http://example.com/")
        self.assertIn("Status code: 200", out)
        self.assertIn("get ok", out)

    def test_http_post_form(self):
        p, _ = patch_manager(simple_handler("<html><body>post ok</body></html>"))
        with p:
            from tools.web_tools import http_post
            out = http_post("http://example.com/login", form_data={"user": "a", "pass": "b"})
        self.assertIn("post ok", out)

    def test_http_post_json(self):
        p, _ = patch_manager(simple_handler('{"ok": true}'))
        with p:
            from tools.web_tools import http_post
            out = http_post("http://example.com/api", json_body={"a": 1})
        self.assertIn("ok", out)

    def test_http_put(self):
        p, _ = patch_manager(simple_handler("put done"))
        with p:
            from tools.web_tools import http_put
            out = http_put("http://example.com/resource", json_body={"x": 1})
        self.assertIn("put done", out)

    def test_http_delete(self):
        p, _ = patch_manager(simple_handler("deleted", status=200))
        with p:
            from tools.web_tools import http_delete
            out = http_delete("http://example.com/resource/1")
        self.assertIn("deleted", out)


class TestManageCookies(unittest.TestCase):
    def test_set_and_show_cookie(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.web_tools import manage_cookies
            out = manage_cookies("set_cookie", cookie_name="session", cookie_value="abc123")
        self.assertIn("session", out)
        out2 = manage_cookies("show")
        self.assertIn("session", out2)

    def test_clear_cookies(self):
        p, _ = patch_manager(simple_handler())
        with p:
            from tools.web_tools import manage_cookies
            manage_cookies("set_cookie", cookie_name="session", cookie_value="abc123")
            out = manage_cookies("clear_cookies")
        self.assertIn("clear", out.lower())


class TestAnalyzeHeaders(unittest.TestCase):
    def test_security_headers_report(self):
        headers = {
            "server": "nginx/1.18.0",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        }
        p, _ = patch_manager(simple_handler("body", headers=headers))
        with p:
            from tools.web_tools import analyze_headers
            out = analyze_headers("http://example.com/")
        self.assertIn("nginx/1.18.0", out)
        self.assertIn("content-security-policy", out)
        self.assertIn("Security headers present", out)

    def test_sensitive_header_masked(self):
        p, _ = patch_manager(simple_handler("body", headers={"set-cookie": "session=supersecretvalue"}))
        with p:
            from tools.web_tools import analyze_headers
            out = analyze_headers("http://example.com/")
        self.assertNotIn("supersecretvalue", out)

    def test_sensitive_cookie_masked(self):
        p, _ = patch_manager(simple_handler("body", headers={"set-cookie": "session=supersecretvalue"}))
        with p:
            from tools.web_tools import analyze_headers
            out = analyze_headers("http://example.com/")
        self.assertNotIn("supersecretvalue", out)


class TestRobotsAndSitemap(unittest.TestCase):
    def test_robots_txt(self):
        body = "User-agent: *\nDisallow: /admin\nDisallow: /secret\nSitemap: /sitemap.xml\n"
        routes = {("GET", "/robots.txt"): (200, body, {})}
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.web_tools import read_robots_txt
            out = read_robots_txt("http://example.com/")
        self.assertIn("/admin", out)
        self.assertIn("/secret", out)
        self.assertIn("Disallowed paths", out)

    def test_robots_not_found(self):
        routes = {("GET", "/robots.txt"): (404, "nope", {})}
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.web_tools import read_robots_txt
            out = read_robots_txt("http://example.com/")
        self.assertIn("not found", out.lower())

    def test_sitemap_xml(self):
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<url><loc>http://example.com/</loc></url>"
            "<url><loc>http://example.com/admin</loc></url>"
            "</urlset>"
        )
        routes = {("GET", "/sitemap.xml"): (200, body, {})}
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.web_tools import read_sitemap_xml
            out = read_sitemap_xml("http://example.com/")
        self.assertIn("http://example.com/admin", out)

    def test_sitemap_not_found(self):
        routes = {("GET", "/sitemap.xml"): (404, "", {})}
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.web_tools import read_sitemap_xml
            out = read_sitemap_xml("http://example.com/")
        self.assertIn("not found", out.lower())


class TestHtmlExtraction(unittest.TestCase):
    HTML = """
    <html><head><title>Test</title></head><body>
    <!-- hidden hint: /flag.txt -->
    <a href="/login">Login</a>
    <script src="/static/app.js"></script>
    <form action="/submit" method="post">
      <input type="hidden" name="token" value="abc">
      <input type="text" name="user">
    </form>
    </body></html>
    """

    def test_extract_links(self):
        p, _ = patch_manager(simple_handler(self.HTML))
        with p:
            from tools.web_tools import extract_links_from_page
            out = extract_links_from_page("http://example.com/")
        self.assertIn("/login", out)

    def test_extract_forms(self):
        p, _ = patch_manager(simple_handler(self.HTML))
        with p:
            from tools.web_tools import extract_forms_from_page
            out = extract_forms_from_page("http://example.com/")
        self.assertIn("/submit", out)
        self.assertIn("token", out)

    def test_extract_javascript(self):
        p, _ = patch_manager(simple_handler(self.HTML))
        with p:
            from tools.web_tools import extract_javascript_from_page
            out = extract_javascript_from_page("http://example.com/")
        self.assertIn("/static/app.js", out)

    def test_extract_html_comments(self):
        p, _ = patch_manager(simple_handler(self.HTML))
        with p:
            from tools.web_tools import extract_html_comments
            out = extract_html_comments("http://example.com/")
        self.assertIn("/flag.txt", out)

    def test_no_comments(self):
        p, _ = patch_manager(simple_handler("<html><body>no comments</body></html>"))
        with p:
            from tools.web_tools import extract_html_comments
            out = extract_html_comments("http://example.com/")
        self.assertIn("No HTML comments", out)


class TestEndpointDiscovery(unittest.TestCase):
    def test_enumerate_directories_finds_admin(self):
        routes = {("GET", "/admin"): (200, "admin panel", {})}
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.web_tools import enumerate_directories
            out = enumerate_directories("http://example.com/", max_checks=40)
        self.assertIn("/admin", out)
        self.assertIn("200", out)

    def test_enumerate_directories_all_404(self):
        p, _ = patch_manager(simple_handler("nope", status=404))
        with p:
            from tools.web_tools import enumerate_directories
            out = enumerate_directories("http://example.com/", max_checks=40)
        self.assertIn("No interesting paths", out)

    def test_discover_api_endpoints(self):
        routes = {("GET", "/api/flag"): (200, '{"flag":"fake"}', {})}
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.web_tools import discover_api_endpoints
            out = discover_api_endpoints("http://example.com/")
        self.assertIn("api/flag", out)

    def test_discover_hidden_endpoints(self):
        routes = {("GET", "/.git/HEAD"): (200, "ref: refs/heads/main", {})}
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.web_tools import discover_hidden_endpoints
            out = discover_hidden_endpoints("http://example.com/")
        self.assertIn(".git/HEAD", out)


class TestRegistryIntegration(unittest.TestCase):
    def test_web_tools_registered(self):
        registry = ToolRegistry()
        from tools.web_tools import (
            analyze_headers, discover_api_endpoints, discover_hidden_endpoints,
            enumerate_directories, extract_forms_from_page, extract_html_comments,
            extract_javascript_from_page, extract_links_from_page, http_delete,
            http_get, http_post, http_put, read_robots_txt, read_sitemap_xml,
        )
        funcs = {
            "http_get": http_get, "http_post": http_post, "http_put": http_put,
            "http_delete": http_delete, "analyze_headers": analyze_headers,
            "read_robots_txt": read_robots_txt, "read_sitemap_xml": read_sitemap_xml,
            "extract_links_from_page": extract_links_from_page,
            "extract_forms_from_page": extract_forms_from_page,
            "extract_javascript_from_page": extract_javascript_from_page,
            "extract_html_comments": extract_html_comments,
            "enumerate_directories": enumerate_directories,
            "discover_api_endpoints": discover_api_endpoints,
            "discover_hidden_endpoints": discover_hidden_endpoints,
        }
        for name, func in funcs.items():
            registry.register(name=name, func=func, description="test", parameters=EMPTY_SCHEMA)
        names = [t["name"] for t in registry.list_tools()]
        for name in funcs:
            self.assertIn(name, names)

    def test_execute_http_get_through_registry(self):
        registry = ToolRegistry()
        from tools.web_tools import http_get
        registry.register(name="http_get", func=http_get, description="test", parameters=EMPTY_SCHEMA)
        p, _ = patch_manager(simple_handler("registry get ok"))
        with p:
            result = registry.execute("http_get", {"url": "http://example.com/"})
        self.assertTrue(result.success)
        self.assertIn("registry get ok", result.output)


if __name__ == "__main__":
    unittest.main()
