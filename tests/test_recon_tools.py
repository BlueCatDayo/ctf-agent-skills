"""Tests for Stage 5 recon tools using httpx.MockTransport (no public sites)."""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from tools.http_session import HttpSessionManager


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


class TestPageFinders(unittest.TestCase):
    def test_find_login_page(self):
        routes = {
            ("GET", "/login"): (200, "<title>Login</title>", {}),
        }
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.recon_tools import find_login_page
            out = find_login_page("http://example.com/")
        self.assertIn("/login", out)
        self.assertIn("200", out)

    def test_find_login_page_none(self):
        p, _ = patch_manager(routed_handler({}))
        with p:
            from tools.recon_tools import find_login_page
            out = find_login_page("http://example.com/")
        self.assertIn("No common login pages", out)

    def test_find_admin_page(self):
        routes = {
            ("GET", "/admin"): (200, "<title>Admin</title>", {}),
        }
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.recon_tools import find_admin_page
            out = find_admin_page("http://example.com/")
        self.assertIn("/admin", out)

    def test_find_admin_page_none(self):
        p, _ = patch_manager(routed_handler({}))
        with p:
            from tools.recon_tools import find_admin_page
            out = find_admin_page("http://example.com/")
        self.assertIn("No common admin pages", out)


class TestEndpointFinders(unittest.TestCase):
    def test_find_api_endpoints(self):
        routes = {
            ("GET", "/api/status"): (200, '{"status":"ok"}', {}),
        }
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.recon_tools import find_api_endpoints
            out = find_api_endpoints("http://example.com/")
        self.assertIn("api/status", out)

    def test_find_api_endpoints_none(self):
        p, _ = patch_manager(routed_handler({}))
        with p:
            from tools.recon_tools import find_api_endpoints
            out = find_api_endpoints("http://example.com/")
        self.assertIn("No common API endpoints", out)

    def test_find_backup_files(self):
        routes = {
            ("GET", "/index.php.bak"): (200, "backup content", {}),
            ("GET", "/db.sql"): (200, "SQL dump", {}),
        }
        p, _ = patch_manager(routed_handler(routes))
        with p:
            from tools.recon_tools import find_backup_files
            out = find_backup_files("http://example.com/", file_paths=["db", "index.php"])
        self.assertIn("index.php.bak", out)
        self.assertIn("db.sql", out)

    def test_find_backup_files_none(self):
        p, _ = patch_manager(routed_handler({}))
        with p:
            from tools.recon_tools import find_backup_files
            out = find_backup_files("http://example.com/")
        self.assertIn("No backup files", out)


class TestTechDetection(unittest.TestCase):
    def test_detect_framework_django_marker(self):
        body = (
            '<html><body><form>'
            '<input type="hidden" name="csrfmiddlewaretoken" value="abc">'
            '</form></body></html>'
        )
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, body, {})}))
        with p:
            from tools.recon_tools import detect_framework
            out = detect_framework("http://example.com/")
        self.assertIn("Django", out)

    def test_detect_framework_none(self):
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, "<html>plain</html>", {})}))
        with p:
            from tools.recon_tools import detect_framework
            out = detect_framework("http://example.com/")
        self.assertIn("No framework confidently identified", out)

    def test_detect_server(self):
        headers = {"server": "Apache/2.4.41 (Ubuntu)"}
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, "x", headers)}))
        with p:
            from tools.recon_tools import detect_server
            out = detect_server("http://example.com/")
        self.assertIn("Apache/2.4.41", out)

    def test_detect_server_none(self):
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, "x", {})}))
        with p:
            from tools.recon_tools import detect_server
            out = detect_server("http://example.com/")
        self.assertIn("No identifying server headers", out)

    def test_detect_technology_stack(self):
        headers = {"server": "nginx/1.18.0", "x-powered-by": "Express"}
        body = '<html><script src="https://cdn/jquery.min.js"></script></html>'
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, body, headers)}))
        with p:
            from tools.recon_tools import detect_technology_stack
            out = detect_technology_stack("http://example.com/")
        self.assertIn("nginx/1.18.0", out)
        self.assertIn("Express", out)

    def test_detect_technology_stack_none(self):
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, "nothing here", {})}))
        with p:
            from tools.recon_tools import detect_technology_stack
            out = detect_technology_stack("http://example.com/")
        self.assertIn("No technology stack confidently identified", out)


class TestContentExtraction(unittest.TestCase):
    def test_extract_emails(self):
        body = '<a href="mailto:admin@example.com">admin@example.com</a> support@test.org'
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, body, {})}))
        with p:
            from tools.recon_tools import extract_emails
            out = extract_emails("http://example.com/")
        self.assertIn("admin@example.com", out)
        self.assertIn("support@test.org", out)

    def test_extract_emails_none(self):
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, "no emails here", {})}))
        with p:
            from tools.recon_tools import extract_emails
            out = extract_emails("http://example.com/")
        self.assertIn("No email addresses", out)

    def test_extract_version_info_from_headers(self):
        headers = {"server": "nginx/1.18.0"}
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, "x", headers)}))
        with p:
            from tools.recon_tools import extract_version_info
            out = extract_version_info("http://example.com/")
        self.assertIn("1.18.0", out)

    def test_extract_version_info_from_source(self):
        body = '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, body, {})}))
        with p:
            from tools.recon_tools import extract_version_info
            out = extract_version_info("http://example.com/")
        self.assertIn("3.6.0", out)

    def test_extract_version_info_none(self):
        p, _ = patch_manager(routed_handler({("GET", "/"): (200, "no versions here", {})}))
        with p:
            from tools.recon_tools import extract_version_info
            out = extract_version_info("http://example.com/")
        self.assertIn("No version information", out)


class TestTitleExtraction(unittest.TestCase):
    def test_extract_title(self):
        from tools.recon_tools import _extract_title
        self.assertEqual(_extract_title("<html><title>My Page</title></html>"), "My Page")

    def test_extract_title_none(self):
        from tools.recon_tools import _extract_title
        self.assertEqual(_extract_title("<html>no title</html>"), "")


if __name__ == "__main__":
    unittest.main()
