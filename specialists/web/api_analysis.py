"""Stage 7 JavaScript & API analysis specialist (spec 6).

Analyzes evidence produced by the JavaScript analysis tools
(``analyze_javascript_url`` / ``analyze_javascript_file`` /
``analyze_javascript_text``):

- endpoints, API base URLs, hidden routes
- tokens, secrets, hardcoded credentials
- source-map references
- fetch / XMLHttpRequest calls
- GraphQL endpoints and WebSocket URLs
- client-side authorization logic
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "javascript", "js", "api", "endpoint", "fetch", "xmlhttprequest",
    "source map", "sourcemap", "websocket", "graphql", "token", "secret",
    "key", "minified", "route", "ajax", "api key", "bearer", "auth",
    "hidden", ".js", "script src",
]

# Labels produced by the js_analysis tools (keep in sync with tools/js_analysis.py).
ANALYSIS_LABELS = [
    "endpoints", "api base urls", "secrets", "source maps", "fetch",
    "graphql", "websocket", "routes", "credentials", "authorization",
    "client-side", "api keys", "hidden",
]


class JavaScriptApiSpecialist(Specialist):
    """Evidence-driven JavaScript/API analysis workflow (spec 6)."""

    name = "web.api_analysis"
    category = "web"
    description = "Analyze JavaScript for endpoints, secrets, GraphQL/WebSocket surfaces, and client-side authz."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        js_evidence = self._js_evidence(evidence)

        if not js_evidence:
            rejected.append(
                "No JavaScript analysis evidence yet (analyze_javascript_url / "
                "analyze_javascript_file / extract_javascript_from_page)."
            )
            steps.append(
                "Fetch the page's scripts: extract_javascript_from_page to list "
                "script URLs, then analyze_javascript_url on each script."
            )
            return self._result(
                evidence, profile,
                hypothesis="JavaScript may reveal hidden endpoints, secrets, or API surfaces.",
                confirmed=confirmed, rejected=rejected, steps=steps,
                next_specialist="web.authentication",
                summary="No JavaScript evidence available yet.",
            )

        # Parse each analysis output into labeled findings.
        for out in js_evidence:
            findings = self._parse_analysis_output(out)
            for label, items in findings.items():
                if items:
                    preview = ", ".join(items[:6])
                    confirmed.append(f"JavaScript {label}: {preview}")

        # Raw JS evidence (no structured analysis) -> extract basics.
        raw_js = " ".join(js_evidence)
        if not any(l in raw_js for l in ANALYSIS_LABELS):
            endpoints = self._regex_endpoints(raw_js)
            if endpoints:
                confirmed.append(f"Endpoints in raw JS: {', '.join(endpoints[:6])}")
            secrets = self._regex_secrets(raw_js)
            if secrets:
                confirmed.append(f"Secret-like values in JS: {', '.join(secrets[:4])}")

        steps.append(
            "Beautify minified scripts (beautify_javascript) before searching for "
            "endpoints and secrets."
        )
        steps.append(
            "Check source-map references (sourceMappingURL) - if present, fetch the "
            ".map file to recover original source."
        )
        steps.append(
            "Verify candidate endpoints with http_get (small, targeted probes only)."
        )
        steps.append(
            "Never use a secret found in JS without first confirming it is honored "
            "by the server via an authorized request."
        )

        next_spec = "web.graphql" if any("graphql" in o.lower() for o in js_evidence) else ""
        if not next_spec and any("websocket" in o.lower() for o in js_evidence):
            next_spec = "web.websocket"
        return self._result(
            evidence, profile,
            hypothesis="Client-side code may expose endpoints, secrets, or misconfigured APIs.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist=next_spec,
            summary=f"JavaScript analysis: {len(confirmed)} finding(s) extracted.",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _js_evidence(self, evidence: EvidenceSnapshot) -> List[str]:
        outputs = evidence.outputs_for(
            "analyze_javascript_url", "analyze_javascript_file",
            "analyze_javascript_text", "extract_javascript_from_page",
            "extract_web_elements",
        )
        return [o for o in outputs if o.strip()]

    def _parse_analysis_output(self, out: str) -> Dict[str, List[str]]:
        """Parse a js_analysis report into {label: [items]}."""
        result: Dict[str, List[str]] = {}
        current: Optional[str] = None
        for line in out.splitlines():
            stripped = line.strip()
            low = stripped.lower()
            if low.endswith(":") and low.rstrip(":").strip().replace(" ", "_") in (
                "endpoints", "api_base_urls", "secrets", "source_maps",
                "fetch_calls", "graphql_endpoints", "websocket_urls",
                "hidden_routes", "hardcoded_credentials",
                "client_side_authorization", "api_keys",
            ):
                current = low.rstrip(":").strip()
                result.setdefault(current, [])
                continue
            if current and stripped.startswith(("-", "*", "•")):
                item = stripped.lstrip("-*• ").strip()
                if item:
                    result[current].append(item)
            elif current and stripped and not stripped.startswith("#") and not low.startswith("no "):
                # tolerate plain lines following a header
                if len(stripped) < 120:
                    result[current].append(stripped)
        return result

    def _regex_endpoints(self, text: str) -> List[str]:
        seen: List[str] = []
        for m in re.finditer(r"['\"`](/[A-Za-z0-9_\-/{}:.?&=]{2,80})['\"`]", text):
            path = m.group(1)
            if path not in seen:
                seen.append(path)
            if len(seen) >= 10:
                break
        return seen

    def _regex_secrets(self, text: str) -> List[str]:
        patterns = [
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
            r"(?i)sk-[A-Za-z0-9]{16,}",
            r"(?i)AKIA[0-9A-Z]{16}",
        ]
        seen: List[str] = []
        for p in patterns:
            for m in re.finditer(p, text):
                value = m.group(0)[:80]
                if value not in seen:
                    seen.append(value)
                if len(seen) >= 6:
                    break
        return seen
