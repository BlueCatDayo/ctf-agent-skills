"""HTTP tools for authorized CTF web challenges.

Network logic only — URL safety lives in http_security.py, session state
in http_session.py, and HTML parsing in html_parser.py.
"""

import json
import time
from typing import Any, Dict, List, Optional

import httpx

from .http_security import HttpSecurityError, validate_http_url
from .http_session import (
    HttpSessionManager,
    is_sensitive_cookie,
    is_sensitive_header,
    mask_value,
    session_manager,
)
from .html_parser import (
    extract_api_routes,
    extract_buttons,
    extract_comments,
    extract_forms,
    extract_iframes,
    extract_links,
    extract_meta,
    extract_scripts,
    extract_stylesheets,
    extract_visible_text,
)

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
DEFAULT_BODY_LIMIT = 3000

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]

ELEMENT_TYPES = {
    "links": "links",
    "forms": "forms",
    "scripts": "scripts",
    "stylesheets": "stylesheets",
    "comments": "comments",
    "meta": "meta",
    "buttons": "buttons",
    "iframes": "iframes",
}


def _truncate(text: str, limit: int) -> str:
    if len(text) > limit:
        return text[:limit] + f"\n... [body truncated at {limit} characters]"
    return text


def _fetch(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    form_data: Optional[Dict[str, str]] = None,
    json_body: Any = None,
    raw_body: Optional[str] = None,
    cookies: Optional[Dict[str, str]] = None,
    follow_redirects: bool = False,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Perform a validated HTTP request, following redirects manually with
    per-hop URL validation.  Returns a normalized result dict."""
    manager = session_manager
    result: Dict[str, Any] = {
        "url": url,
        "final_url": url,
        "status_code": None,
        "headers": {},
        "cookies": {},
        "redirects": [],
        "content_type": None,
        "body_length": 0,
        "body": "",
        "elapsed": None,
        "error_type": None,
        "error": None,
    }

    cleaned, err = validate_http_url(
        url,
        allow_localhost=manager.allow_localhost,
        allow_private=manager.allow_private,
    )
    if err:
        result["error_type"] = "url_validation_error"
        result["error"] = err
        return result

    current_url = cleaned
    method = method.upper()
    if method not in ALLOWED_METHODS:
        result["error_type"] = "invalid_method"
        result["error"] = f"Method '{method}' is not supported."
        return result

    client = manager.get_client()
    request_headers = dict(manager.default_headers)
    if headers:
        request_headers.update(headers)

    request_cookies = dict(cookies or {})
    effective_timeout = timeout if timeout is not None else manager.timeout

    max_redirects = manager.max_redirects
    redirects = []

    try:
        followed = 0
        while True:
            start = time.monotonic()
            response = client.request(
                method,
                current_url,
                params=params,
                headers=request_headers or None,
                data=form_data,
                json=json_body,
                content=raw_body,
                cookies=request_cookies or None,
                timeout=effective_timeout,
            )
            elapsed = round(time.monotonic() - start, 3)

            # Persist any cookies the server set
            for c in response.cookies.jar:
                manager.cookies.set(c.name, c.value, domain=c.domain or "", path=c.path or "/")

            location = response.headers.get("location") or response.headers.get("Location")
            is_redirect = response.status_code in (301, 302, 303, 307, 308) and bool(location)

            # If we do not need to follow this redirect, return the response
            if not (follow_redirects and is_redirect):
                body_bytes = response.content
                try:
                    body_text = body_bytes.decode("utf-8", errors="replace")
                except Exception:
                    body_text = body_bytes.decode("latin-1", errors="replace")

                result.update(
                    {
                        "url": url,
                        "final_url": str(response.url),
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "cookies": {c.name: c.value for c in response.cookies.jar},
                        "redirects": redirects,
                        "content_type": response.headers.get("content-type") or response.headers.get("Content-Type"),
                        "body_length": len(body_bytes),
                        "body": body_text,
                        "elapsed": elapsed,
                    }
                )
                return result

            redirects.append(
                {
                    "status": response.status_code,
                    "location": location,
                    "url": str(response.url),
                }
            )
            followed += 1

            if followed > max_redirects:
                result["error_type"] = "too_many_redirects"
                result["error"] = f"Exceeded maximum of {max_redirects} redirects."
                result["redirects"] = redirects
                return result

            # Follow the redirect with fresh URL validation
            next_url = str(httpx.URL(current_url).join(location))
            cleaned_next, err = validate_http_url(
                next_url,
                allow_localhost=manager.allow_localhost,
                allow_private=manager.allow_private,
            )
            if err:
                result["error_type"] = "redirect_url_validation_error"
                result["error"] = f"Blocked redirect target: {err}"
                result["redirects"] = redirects
                return result
            current_url = cleaned_next

    except httpx.TimeoutException:
        result["error_type"] = "timeout"
        result["error"] = f"Request timed out after {effective_timeout}s."
        result["redirects"] = redirects
        return result
    except httpx.ConnectError as e:
        result["error_type"] = "connection_error"
        result["error"] = f"Could not connect: {e}"
        return result
    except httpx.RequestError as e:
        result["error_type"] = "request_error"
        result["error"] = f"HTTP request failed: {e}"
        return result
    except HttpSecurityError as e:
        result["error_type"] = "url_validation_error"
        result["error"] = str(e)
        return result
    except Exception as e:  # pragma: no cover
        result["error_type"] = "unexpected_error"
        result["error"] = str(e)
        return result


def _format_response(res: Dict[str, Any], body_limit: int) -> str:
    """Format a normalized response dict as a readable string."""
    if res.get("error_type"):
        return (
            f"URL: {res.get('url')}\n"
            f"Error type: {res.get('error_type')}\n"
            f"Error: {res.get('error')}"
        )

    lines = [
        f"Requested URL: {res.get('url')}",
        f"Final URL: {res.get('final_url')}",
        f"Status code: {res.get('status_code')}",
        f"Content type: {res.get('content_type') or '(none)'}",
        f"Response length: {res.get('body_length')} bytes",
        f"Elapsed: {res.get('elapsed')}s",
    ]
    redirects = res.get("redirects") or []
    if redirects:
        chain = " -> ".join(
            f"{r['status']} {r['location'] or r['url']}" for r in redirects
        )
        lines.append(f"Redirects ({len(redirects)}): {chain}")

    headers = res.get("headers") or {}
    if headers:
        selected = []
        for name, value in headers.items():
            if name.lower() in ("content-type", "server", "set-cookie", "location", "date", "cache-control", "x-powered-by"):
                selected.append(f"{name}: {value}")
        if selected:
            lines.append("Key headers:")
            lines.extend(f"  {h}" for h in selected)

    resp_cookies = res.get("cookies") or {}
    if resp_cookies:
        lines.append("Response cookies:")
        for name, value in resp_cookies.items():
            shown = mask_value(value) if is_sensitive_cookie(name) else value
            lines.append(f"  {name} = {shown}")

    body = res.get("body") or ""
    if body:
        lines.append(f"Body ({len(body)} chars):")
        lines.append(_truncate(body, body_limit))
    else:
        lines.append("Body: (empty)")

    return "\n".join(lines)


def http_request(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    form_data: Optional[Dict[str, str]] = None,
    json_body: Any = None,
    raw_body: Optional[str] = None,
    cookies: Optional[Dict[str, str]] = None,
    follow_redirects: bool = False,
    timeout: Optional[float] = None,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Send a controlled HTTP request (see requirements in the spec).

    Supports GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS with query params,
    headers, form data, JSON or raw bodies, cookies, redirect control,
    and a timeout.  Returns a formatted result including status, headers,
    cookies, redirect history, truncated body, and elapsed time.
    """
    res = _fetch(
        url,
        method=method,
        params=params,
        headers=headers,
        form_data=form_data,
        json_body=json_body,
        raw_body=raw_body,
        cookies=cookies,
        follow_redirects=follow_redirects,
        timeout=timeout,
    )
    return _format_response(res, max_body_chars)


def inspect_webpage(
    url: str,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Inspect a webpage and report title, technologies, forms, scripts,
    stylesheets, comments, meta tags, text summary, API routes,
    security headers, and cookies."""
    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)

    body = res.get("body") or ""
    headers = res.get("headers") or {}
    cookies = res.get("cookies") or {}
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(body, "html.parser")

    title = soup.title.get_text(strip=True) if soup.title else "(no title)"

    lines = [
        f"URL: {res.get('url')}",
        f"Final URL: {res.get('final_url')}",
        f"Status code: {res.get('status_code')}",
        f"Content type: {res.get('content_type') or '(none)'}",
        f"Title: {title}",
    ]

    server = headers.get("Server") or headers.get("server")
    if server:
        lines.append(f"Server header: {server}")

    techs = detect_technologies_from_source(body, headers)
    lines.append(f"Detected technologies (heuristic): {', '.join(techs) if techs else 'none confidently identified'}")

    security = []
    for h in SECURITY_HEADERS:
        if h in headers:
            security.append(f"{h}: {headers[h]}")
    if security:
        lines.append("Security headers:")
        lines.extend(f"  {s}" for s in security)
    else:
        lines.append("Security headers: none of the common security headers found")

    if cookies:
        lines.append("Cookies:")
        for name, value in cookies.items():
            shown = mask_value(value) if is_sensitive_cookie(name) else value
            lines.append(f"  {name} = {shown}")

    forms = extract_forms(soup, res.get("url") or url)
    if forms:
        lines.append(f"Forms ({len(forms)}):")
        for f in forms:
            lines.append(f"  [{f['index']}] {f['method']} {f['action']} inputs={len(f['inputs'])}")

    scripts = extract_scripts(soup, res.get("url") or url)
    if scripts:
        lines.append(f"Scripts ({len(scripts)}):")
        lines.extend(f"  {s[:150]}" for s in scripts[:10])

    css = extract_stylesheets(soup, res.get("url") or url)
    if css:
        lines.append(f"Stylesheets ({len(css)}):")
        lines.extend(f"  {c}" for c in css[:10])

    comments = extract_comments(soup)
    if comments:
        lines.append(f"Comments ({len(comments)}):")
        lines.extend(f"  {c}" for c in comments[:10])

    metas = extract_meta(soup)
    if metas:
        lines.append(f"Meta tags ({len(metas)}):")
        lines.extend(f"  {m['name']} = {m['content'][:80]}" for m in metas[:10])

    routes = extract_api_routes(soup, body)
    if routes:
        lines.append(f"Possible API routes ({len(routes)}):")
        lines.extend(f"  {r}" for r in routes[:20])

    text = extract_visible_text(soup)
    if text:
        lines.append(f"Visible text summary ({len(text)} chars):")
        lines.append(f"  {_truncate(text, 300)}")

    return "\n".join(lines)


def detect_technologies_from_source(body: str, headers: Dict[str, str]) -> List[str]:
    """Return technologies evidenced by the page source or headers."""
    found = set()
    lower = body.lower()
    markers = {
        "jquery": ["jquery"], "bootstrap": ["bootstrap"], "react": ["react"],
        "angular": ["ng-", "angular"], "vue": ["vue"], "django": ["csrfmiddlewaretoken"],
        "wordpress": ["wp-content", "wp-includes"], "laravel": ["laravel"],
        "express": ["x-powered-by: express"],
        "flask": ["flask"], "tailwind": ["tailwind"], "next.js": ["next.js", "__next"],
    }
    for tech, needles in markers.items():
        if any(n in lower for n in needles):
            found.add(tech)
    server = (headers.get("Server") or headers.get("server") or "").lower()
    for s in ["nginx", "apache", "cloudflare", "gunicorn", "uvicorn"]:
        if s in server:
            found.add(s)
    return sorted(found)


def extract_web_elements(
    url: str,
    element_type: str = "all",
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Extract specific elements from a webpage (links, forms, inputs,
    scripts, comments, iframes, ...)."""
    if element_type not in ELEMENT_TYPES and element_type not in ("all", "inputs", "hidden_inputs"):
        return f"Unsupported element type: '{element_type}'. Supported: {', '.join(sorted(ELEMENT_TYPES)) + ', inputs, hidden_inputs'}."

    res = _fetch(url, method="GET")
    if res.get("error_type"):
        return _format_response(res, max_body_chars)

    body = res.get("body") or ""
    base = res.get("url") or url
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(body, "html.parser")

    lines = [f"URL: {url}"]
    page_url = res.get("url") or url

    if element_type in ("all", "links"):
        links = extract_links(soup, page_url)
        lines.append(f"Links ({len(links)}):")
        lines.extend(f"  {l}" for l in links)

    if element_type in ("all", "forms"):
        forms = extract_forms(soup, page_url)
        lines.append(f"Forms ({len(forms)}):")
        for f in forms:
            lines.append(f"  [{f['index']}] {f['method']} -> {f['action']}")
            for inp in f["inputs"]:
                lines.append(f"      input name={inp['name']} type={inp['type']} hidden={inp['hidden']}")

    if element_type in ("all", "inputs", "hidden_inputs"):
        hidden = element_type == "hidden_inputs"
        found = []
        for form in soup.find_all("form"):
            for inp in form.find_all("input"):
                if hidden and inp.get("type") != "hidden":
                    continue
                found.append(
                    f"    name={inp.get('name')} type={inp.get('type') or 'text'} "
                    f"value={inp.get('value')}"
                )
        lines.append(f"{'Hidden inputs' if hidden else 'Inputs'} ({len(found)}):")
        lines.extend(found)

    if element_type in ("all", "scripts"):
        scripts = extract_scripts(soup, page_url)
        lines.append(f"Scripts ({len(scripts)}):")
        lines.extend(f"  {s[:150]}" for s in scripts)

    if element_type in ("all", "stylesheets"):
        css = extract_stylesheets(soup, page_url)
        lines.append(f"Stylesheets ({len(css)}):")
        lines.extend(f"  {c}" for c in css)

    if element_type in ("all", "comments"):
        comments = extract_comments(soup)
        lines.append(f"Comments ({len(comments)}):")
        lines.extend(f"  {c}" for c in comments)

    if element_type in ("all", "meta"):
        metas = extract_meta(soup)
        lines.append(f"Meta tags ({len(metas)}):")
        lines.extend(f"  {m['name']} = {m['content'][:80]}" for m in metas)

    if element_type in ("all", "buttons"):
        buttons = extract_buttons(soup)
        lines.append(f"Buttons ({len(buttons)}):")
        lines.extend(f"  {b['text']} (type={b['type']})" for b in buttons)

    if element_type in ("all", "iframes"):
        iframes = extract_iframes(soup, page_url)
        lines.append(f"Iframes ({len(iframes)}):")
        lines.extend(f"  {i}" for i in iframes)

    return "\n".join(lines)


def compare_http_responses(
    response_a: Any,
    response_b: Any,
    max_body_chars: int = DEFAULT_BODY_LIMIT,
) -> str:
    """Compare two responses (URLs or stored JSON response dicts)."""
    res_a = _resolve_comparison_source(response_a)
    res_b = _resolve_comparison_source(response_b)

    if res_a.get("error_type"):
        return f"Error fetching response A: {res_a.get('error')}"
    if res_b.get("error_type"):
        return f"Error fetching response B: {res_b.get('error')}"

    lines = [
        f"A: {res_a.get('url')} -> {res_a.get('final_url')} ({res_a.get('status_code')})",
        f"B: {res_b.get('url')} -> {res_b.get('final_url')} ({res_b.get('status_code')})",
        f"Status difference: A={res_a.get('status_code')} B={res_b.get('status_code')} "
        f"({'same' if res_a.get('status_code') == res_b.get('status_code') else 'DIFFERENT'})",
        f"Body length difference: A={res_a.get('body_length')} B={res_b.get('body_length')} "
        f"({'same' if res_a.get('body_length') == res_b.get('body_length') else 'DIFFERENT'})",
    ]

    # Header differences
    ha = res_a.get("headers") or {}
    hb = res_b.get("headers") or {}
    header_diffs = []
    for key in sorted(set(ha) | set(hb)):
        va = ha.get(key)
        vb = hb.get(key)
        if va != vb:
            header_diffs.append(f"{key}: A={va} B={vb}")
    lines.append(f"Header differences ({len(header_diffs)}):")
    lines.extend(f"  {d}" for d in header_diffs[:15])

    # Cookie differences
    ca = res_a.get("cookies") or {}
    cb = res_b.get("cookies") or {}
    cookie_diffs = [k for k in set(ca) | set(cb) if ca.get(k) != cb.get(k)]
    lines.append(f"Cookie differences ({len(cookie_diffs)}): {', '.join(cookie_diffs) or 'none'}")

    # Redirect differences
    ra = [f"{r['status']} {r['location'] or r['url']}" for r in (res_a.get('redirects') or [])]
    rb = [f"{r['status']} {r['location'] or r['url']}" for r in (res_b.get('redirects') or [])]
    lines.append(f"Redirect difference: {'same' if ra == rb else 'DIFFERENT'}")

    # Similarity summary
    ba = res_a.get("body") or ""
    bb = res_b.get("body") or ""
    if ba and bb:
        import difflib
        ratio = difflib.SequenceMatcher(None, ba, bb).ratio()
        lines.append(f"Body similarity: {ratio:.1%}")

    # Notable changed lines
    changed = []
    for a, b in zip(ba.splitlines(), bb.splitlines()):
        if a.strip() and b.strip() and a != b and len(a) < 200 and len(b) < 200:
            changed.append(f"  A: {a}\n  B: {b}")
            if len(changed) >= 8:
                break
    if changed:
        lines.append("Notable changed lines:")
        lines.extend(changed)

    return "\n".join(lines)


def _resolve_comparison_source(source: Any) -> Dict[str, Any]:
    """Resolve a comparison source: a URL string or a stored response dict."""
    if isinstance(source, dict):
        return source
    if isinstance(source, str):
        return _fetch(source, method="GET")
    return {"error_type": "invalid_source", "error": "Source must be a URL or a JSON response dict."}


def manage_http_session(
    operation: str = "show",
    cookie_name: Optional[str] = None,
    cookie_value: Optional[str] = None,
    cookie_domain: str = "",
    header_name: Optional[str] = None,
    header_value: Optional[str] = None,
) -> str:
    """Manage the shared HTTP session: cookies, default headers, reset."""
    manager = session_manager
    op = (operation or "show").lower()

    if op in ("show", "show_cookies", "cookies"):
        return manager.show_cookies()
    if op == "clear_cookies":
        return manager.clear_cookies()
    if op == "set_cookie":
        if not cookie_name:
            return "Error: cookie_name is required for set_cookie."
        return manager.set_cookie(cookie_name, cookie_value or "", cookie_domain)
    if op == "remove_cookie":
        if not cookie_name:
            return "Error: cookie_name is required for remove_cookie."
        return manager.remove_cookie(cookie_name, cookie_domain)
    if op == "reset":
        manager.reset_session()
        return "HTTP session reset (cookies and default headers cleared)."
    if op in ("show_headers", "headers"):
        return manager.show_headers()
    if op == "set_header":
        if not header_name:
            return "Error: header_name is required for set_header."
        return manager.set_header(header_name, header_value or "")
    if op == "remove_header":
        if not header_name:
            return "Error: header_name is required for remove_header."
        return manager.remove_header(header_name)
    return (
        f"Unknown operation: '{operation}'. Supported: show, clear_cookies, "
        f"set_cookie, remove_cookie, reset, show_headers, set_header, remove_header."
    )


def init_http_session_from_config(config: Any) -> None:
    """Configure the shared session manager from the application Config."""
    session_manager.timeout = config.http_timeout_seconds
    session_manager.max_redirects = config.max_redirects
    session_manager.user_agent = config.http_user_agent
    session_manager.allow_localhost = config.allow_localhost_targets
    session_manager.allow_private = config.allow_private_targets
    session_manager.default_headers = {"User-Agent": config.http_user_agent}
    session_manager.reset_session()
