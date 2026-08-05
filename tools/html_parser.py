"""HTML parsing helpers for webpage inspection (network-free)."""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment

MAX_ELEMENT_COUNT = 50

# Regexes used to spot plausible API routes in text/scripts
API_HINT_RE = re.compile(
    r"(/api/[\w\-/{}.*]+|/v\d+(?:\.\d+)?/[\w\-/]+|/graphql|/rest/[\w\-/]+)",
    re.IGNORECASE,
)

TECH_RE = re.compile(
    r"(bootstrap|jquery|react|angular|vue|django|flask|wordpress|laravel|express|next\.js|svelte|tailwind)"
    r"|(cloudflare|nginx|apache|gunicorn|uvicorn)",
    re.IGNORECASE,
)


def _resolve(base_url: str, href: str) -> str:
    """Resolve a possibly-relative URL against a base URL."""
    try:
        return urljoin(base_url, href)
    except ValueError:
        return href


def extract_links(soup: BeautifulSoup, base_url: str) -> List[str]:
    """Extract absolute hrefs from <a> tags."""
    links = []
    for a in soup.find_all("a", href=True):
        url = _resolve(base_url, a["href"])
        if url not in links:
            links.append(url)
    return links[:MAX_ELEMENT_COUNT]


def extract_forms(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    """Extract forms with actions, methods, and input fields."""
    forms = []
    for i, form in enumerate(soup.find_all("form"), start=1):
        action = _resolve(base_url, form.get("action") or base_url)
        method = (form.get("method") or "get").upper()
        inputs = []
        for inp in form.find_all("input"):
            inputs.append(
                {
                    "name": inp.get("name"),
                    "type": inp.get("type") or "text",
                    "value": inp.get("value"),
                    "hidden": (inp.get("type") == "hidden"),
                }
            )
        for sel in form.find_all("select"):
            inputs.append(
                {"name": sel.get("name"), "type": "select", "value": None, "hidden": False}
            )
        for ta in form.find_all("textarea"):
            inputs.append(
                {"name": ta.get("name"), "type": "textarea", "value": None, "hidden": False}
            )
        forms.append(
            {
                "index": i,
                "action": action,
                "method": method,
                "inputs": inputs,
            }
        )
    return forms[:MAX_ELEMENT_COUNT]


def extract_scripts(soup: BeautifulSoup, base_url: str) -> List[str]:
    """Extract script src URLs and inline script snippets."""
    scripts = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            scripts.append(f"src: {_resolve(base_url, src)}")
        elif s.string and s.string.strip():
            scripts.append(f"inline: {s.string.strip()[:200]}")
    return scripts[:MAX_ELEMENT_COUNT]


def extract_stylesheets(soup: BeautifulSoup, base_url: str) -> List[str]:
    """Extract stylesheet hrefs."""
    css = []
    for link in soup.find_all("link", rel=lambda v: v and "stylesheet" in [x.lower() for x in v]):
        href = link.get("href")
        if href:
            css.append(_resolve(base_url, href))
    return css[:MAX_ELEMENT_COUNT]


def extract_comments(soup: BeautifulSoup) -> List[str]:
    """Extract HTML comments."""
    return [str(c).strip()[:200] for c in soup.find_all(string=lambda t: isinstance(t, Comment))][:MAX_ELEMENT_COUNT]


def extract_meta(soup: BeautifulSoup) -> List[Dict[str, str]]:
    """Extract meta tags."""
    metas = []
    for m in soup.find_all("meta"):
        name = m.get("name") or m.get("property") or m.get("http-equiv") or ""
        content = m.get("content") or ""
        if name:
            metas.append({"name": name, "content": content[:200]})
    return metas[:MAX_ELEMENT_COUNT]


def extract_iframes(soup: BeautifulSoup, base_url: str) -> List[str]:
    """Extract iframe src URLs."""
    return [
        _resolve(base_url, f["src"])
        for f in soup.find_all("iframe", src=True)
    ][:MAX_ELEMENT_COUNT]


def extract_buttons(soup: BeautifulSoup) -> List[Dict[str, str]]:
    """Extract buttons with text and type."""
    buttons = []
    for b in soup.find_all("button"):
        buttons.append(
            {"text": (b.get_text(strip=True) or "")[:100], "type": b.get("type") or "submit"}
        )
    return buttons[:MAX_ELEMENT_COUNT]


def extract_api_routes(soup: BeautifulSoup, html: str) -> List[str]:
    """Find plausible API routes in HTML/script text."""
    routes = set()
    for m in API_HINT_RE.findall(html):
        routes.add(m)
    return sorted(routes)[:MAX_ELEMENT_COUNT]


def extract_visible_text(soup: BeautifulSoup, limit: int = 500) -> str:
    """Return a summary of the visible page text."""
    for tag in soup(["script", "style", "noscript", "head"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
    if len(text) > limit:
        return text[:limit] + " ..."
    return text


def detect_technologies(soup: BeautifulSoup, headers: Dict[str, str], html: str) -> List[str]:
    """Return technology names only when supported by evidence."""
    found = set()
    lower_html = html.lower()
    for tech in [
        "bootstrap", "jquery", "react", "angular", "vue", "django",
        "flask", "wordpress", "laravel", "express", "next.js", "svelte",
        "tailwind", "cloudflare", "nginx", "apache", "gunicorn", "uvicorn",
    ]:
        if tech in lower_html:
            found.add(tech)
    server = (headers.get("server") or headers.get("Server") or "").lower()
    if server:
        for s in ["nginx", "apache", "cloudflare", "gunicorn", "uvicorn"]:
            if s in server:
                found.add(s)
    return sorted(found)
