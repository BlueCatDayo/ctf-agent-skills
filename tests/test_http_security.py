"""Tests for HTTP URL safety validation."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.http_security import validate_http_url


class TestAllowedUrls(unittest.TestCase):
    def test_http_allowed(self):
        url, err = validate_http_url("http://example.com/")
        self.assertIsNone(err)
        self.assertEqual(url, "http://example.com/")

    def test_https_allowed(self):
        url, err = validate_http_url("https://example.com/path?q=1")
        self.assertIsNone(err)
        self.assertEqual(url, "https://example.com/path?q=1")

    def test_http_with_port(self):
        url, err = validate_http_url("http://example.com:8080/login")
        self.assertIsNone(err)


class TestUnsupportedSchemes(unittest.TestCase):
    def test_file_scheme(self):
        _, err = validate_http_url("file:///etc/passwd")
        self.assertIsNotNone(err)
        self.assertIn("scheme", err.lower())

    def test_ftp_scheme(self):
        _, err = validate_http_url("ftp://example.com/file")
        self.assertIsNotNone(err)

    def test_gopher_scheme(self):
        _, err = validate_http_url("gopher://example.com/1")
        self.assertIsNotNone(err)

    def test_data_scheme(self):
        _, err = validate_http_url("data:text/html,<b>hi</b>")
        self.assertIsNotNone(err)

    def test_javascript_scheme(self):
        _, err = validate_http_url("javascript:alert(1)")
        self.assertIsNotNone(err)

    def test_no_scheme(self):
        _, err = validate_http_url("example.com")
        self.assertIsNotNone(err)


class TestEmbeddedCredentials(unittest.TestCase):
    def test_credentials_blocked(self):
        _, err = validate_http_url("http://user:pass@example.com/")
        self.assertIsNotNone(err)
        self.assertIn("credential", err.lower())


class TestLocalhostBlocking(unittest.TestCase):
    def test_localhost_blocked_by_default(self):
        _, err = validate_http_url("http://localhost:5000/")
        self.assertIsNotNone(err)
        self.assertIn("localhost", err.lower())

    def test_127_0_0_1_blocked(self):
        _, err = validate_http_url("http://127.0.0.1/")
        self.assertIsNotNone(err)

    def test_localhost_allowed_when_enabled(self):
        url, err = validate_http_url("http://localhost:5000/", allow_localhost=True)
        self.assertIsNone(err)
        self.assertIsNotNone(url)

    def test_ip_loopback_allowed_when_enabled(self):
        url, err = validate_http_url("http://127.0.0.1:8080/", allow_localhost=True)
        self.assertIsNone(err)
        self.assertIsNotNone(url)


class TestPrivateBlocking(unittest.TestCase):
    def test_10_0_0_0_blocked(self):
        _, err = validate_http_url("http://10.0.0.5/")
        self.assertIsNotNone(err)
        self.assertIn("private", err.lower())

    def test_192_168_blocked(self):
        _, err = validate_http_url("http://192.168.1.10/")
        self.assertIsNotNone(err)

    def test_172_16_blocked(self):
        _, err = validate_http_url("http://172.16.0.1/")
        self.assertIsNotNone(err)

    def test_private_allowed_when_enabled(self):
        url, err = validate_http_url("http://192.168.1.10/", allow_private=True)
        self.assertIsNone(err)


class TestMetadataBlocking(unittest.TestCase):
    def test_aws_metadata_ip(self):
        _, err = validate_http_url("http://169.254.169.254/latest/meta-data/")
        self.assertIsNotNone(err)

    def test_aws_metadata_hostname(self):
        _, err = validate_http_url("http://metadata.google.internal/")
        self.assertIsNotNone(err)

    def test_link_local_range(self):
        _, err = validate_http_url("http://169.254.5.5/")
        self.assertIsNotNone(err)


class TestInvalidHosts(unittest.TestCase):
    def test_empty_url(self):
        _, err = validate_http_url("")
        self.assertIsNotNone(err)

    def test_none_url(self):
        _, err = validate_http_url(None)
        self.assertIsNotNone(err)

    def test_whitespace_in_host(self):
        _, err = validate_http_url("http://exa mple.com/")
        self.assertIsNotNone(err)

    def test_no_host(self):
        _, err = validate_http_url("http:///path")
        self.assertIsNotNone(err)
