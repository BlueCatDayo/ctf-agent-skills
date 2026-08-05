"""Tests for HTML parsing helpers (network-free)."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bs4 import BeautifulSoup

from tools.html_parser import (
    extract_api_routes,
    extract_comments,
    extract_forms,
    extract_links,
    extract_meta,
    extract_scripts,
    extract_visible_text,
)

FIXTURE = Path(__file__).parent / "fixtures" / "test_page.html"


def _soup():
    return BeautifulSoup(FIXTURE.read_text(encoding="utf-8"), "html.parser")


class TestTitleExtraction(unittest.TestCase):
    def test_title(self):
        soup = _soup()
        self.assertEqual(soup.title.get_text(strip=True), "Stage 3 Test Page")


class TestLinkExtraction(unittest.TestCase):
    def test_links_count_and_values(self):
        soup = _soup()
        links = extract_links(soup, "http://challenge.local/")
        self.assertEqual(len(links), 5)
        self.assertIn("http://challenge.local/login", links)
        self.assertIn("http://challenge.local/api/users", links)

    def test_relative_url_resolution(self):
        soup = _soup()
        links = extract_links(soup, "http://challenge.local/docs/index.html")
        self.assertIn("http://challenge.local/docs/index.html", links)


class TestFormExtraction(unittest.TestCase):
    def test_get_and_post_forms(self):
        soup = _soup()
        forms = extract_forms(soup, "http://challenge.local/")
        self.assertEqual(len(forms), 2)
        methods = {f["method"] for f in forms}
        self.assertEqual(methods, {"GET", "POST"})

    def test_form_actions_resolved(self):
        soup = _soup()
        forms = extract_forms(soup, "http://challenge.local/")
        actions = {f["action"] for f in forms}
        self.assertIn("http://challenge.local/login", actions)
        self.assertIn("http://challenge.local/api/search", actions)

    def test_hidden_inputs(self):
        soup = _soup()
        forms = extract_forms(soup, "http://challenge.local/")
        hidden = []
        for f in forms:
            for i in f["inputs"]:
                if i["hidden"]:
                    hidden.append(i)
        self.assertGreaterEqual(len(hidden), 3)
        flags = [i for i in hidden if i.get("value") == "flag{stage3_test_only}"]
        self.assertEqual(len(flags), 1)

    def test_input_names(self):
        soup = _soup()
        forms = extract_forms(soup, "http://challenge.local/")
        names = {i["name"] for f in forms for i in f["inputs"]}
        self.assertIn("username", names)
        self.assertIn("password", names)
        self.assertIn("query", names)


class TestScriptsComments(unittest.TestCase):
    def test_scripts_found(self):
        soup = _soup()
        scripts = extract_scripts(soup, "http://challenge.local/")
        self.assertGreaterEqual(len(scripts), 3)

    def test_comments_found(self):
        soup = _soup()
        comments = extract_comments(soup)
        self.assertTrue(any("hint" in c.lower() for c in comments))

    def test_meta_found(self):
        soup = _soup()
        metas = extract_meta(soup)
        names = {m["name"] for m in metas}
        self.assertIn("description", names)


class TestApiRoutes(unittest.TestCase):
    def test_api_routes(self):
        soup = _soup()
        html = FIXTURE.read_text(encoding="utf-8")
        routes = extract_api_routes(soup, html)
        self.assertIn("/api/users", routes)
        self.assertIn("/api/search", routes)
        self.assertIn("/api/health", routes)
        self.assertIn("/v1/status", routes)


class TestVisibleText(unittest.TestCase):
    def test_visible_text(self):
        soup = _soup()
        text = extract_visible_text(soup)
        self.assertIn("Welcome to the test challenge", text)
        self.assertIn("Good luck", text)
