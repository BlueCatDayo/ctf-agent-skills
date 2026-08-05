"""Stage 7 authentication & session specialist (spec 3).

Analyzes evidence for authentication/session weaknesses:

- login forms, registration flows, password reset flows
- cookies and session identifiers
- authorization headers and JWT structure (JWT details delegated to the
  JWT specialist)
- role/permission fields and client-side authentication checks
- user identifiers in URLs or requests

Response comparison guidance: unauthenticated vs authenticated, different
user identifiers, and modified role/claim values.  An authentication
bypass is only reported when access is actually confirmed by tool output.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist, find_substrings

SIGNALS = [
    "login", "password", "auth", "authentication", "session", "cookie",
    "register", "reset", "role", "admin", "token", "authorization",
    "401", "403", "user", "account", "logout", "bearer", "permission",
    "jwt", "csrf", "password reset",
]

AUTH_FLOW_MARKERS = {
    "login form": ["type=\"password\"", "name=\"password\"", "login",
                  "signin", "log in"],
    "registration flow": ["register", "signup", "sign up", "create account"],
    "password reset": ["forgot", "reset password", "reset-password",
                       "password reset"],
    "cookie/session": ["session", "cookie", "set-cookie", "phpsessid",
                       "jsessionid", "connect.sid"],
}

ROLE_FIELDS = ["role", "admin", "is_admin", "isadmin", "permission",
               "privilege", "access_level", "group"]

STATUS_CODES = ["401", "403", "302", "200 ok", "404"]


class AuthenticationSpecialist(Specialist):
    """Evidence-driven authentication/session workflow (spec 3)."""

    name = "web.authentication"
    category = "web"
    description = "Inspect login/registration/reset flows, sessions, cookies, and access control."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text().lower()
        success_text = evidence.successful_output().lower()

        # 1. Identify authentication surfaces
        surfaces = []
        for label, keys in AUTH_FLOW_MARKERS.items():
            if any(k in text for k in keys):
                surfaces.append(label)
        if surfaces:
            confirmed.append(f"Authentication surface(s) present: {', '.join(surfaces)}")

        # 2. Cookies / session identifiers
        cookie_names = self._cookie_names(evidence)
        if cookie_names:
            confirmed.append(f"Cookie/session identifier(s) observed: {', '.join(cookie_names[:6])}")

        # 3. Authorization headers / bearer tokens
        if any(k in text for k in ("authorization", "bearer")):
            confirmed.append("Authorization header / bearer token usage observed in requests.")

        # 4. Role / permission fields
        role_hits = [r for r in ROLE_FIELDS if r in text]
        if role_hits:
            confirmed.append(
                f"Role/permission field(s) present: {', '.join(role_hits[:5])} - "
                "check whether the server enforces them."
            )

        # 5. User identifiers in URLs / requests
        user_ids = regex_user_identifiers(text)
        if user_ids:
            confirmed.append(
                f"User identifier(s) in URLs/parameters: {', '.join(user_ids[:5])} - "
                "compare access across identifiers (IDOR surface)."
            )

        # 6. Response codes suggesting access control differences
        if "401" in text or "403" in text:
            confirmed.append("Access-denied status observed (401/403) - the server enforces some control.")
        if "403" in text and "200" in text:
            confirmed.append("Mixed 403/200 responses observed - possible broken access control surface.")

        # 7. Client-side auth checks
        js_evidence = " ".join(evidence.outputs_for("analyze_javascript_file", "analyze_javascript_url"))
        client_checks = self._client_side_auth(js_evidence)
        if client_checks:
            confirmed.append(
                f"Client-side authentication logic found in JavaScript: {', '.join(client_checks[:4])}"
            )

        # Recommended low-risk steps
        steps.append(
            "Compare responses: unauthenticated request vs authenticated request "
            "(use the shared HTTP session) - record status, size, and body differences."
        )
        steps.append(
            "If role/claim fields exist, compare behavior for different role values "
            "only after confirming the claim is actually honored by the server."
        )
        steps.append(
            "If JWT is present, run the web.jwt specialist to decode claims and check "
            "expiry/algorithms before altering anything."
        )
        steps.append(
            "Do NOT report an authentication bypass unless tool output confirms "
            "access to a protected resource (e.g., admin page content returned)."
        )

        if not surfaces and not cookie_names and not role_hits:
            rejected.append(
                "No login form, session cookie, or role/permission signals found in "
                "evidence so far."
            )
            steps.append(
                "Locate the auth surface first: find_login_page, extract_forms_from_page, "
                "and analyze_headers (look for auth-related headers)."
            )

        next_spec = "web.jwt" if any(k in text for k in ("jwt", "eyj", "bearer")) else ""
        return self._result(
            evidence,
            profile,
            hypothesis="Authentication or session handling may be weak.",
            confirmed=confirmed,
            rejected=rejected,
            steps=steps,
            next_specialist=next_spec,
            summary="Authentication evidence: " + (", ".join(surfaces[:2]) if surfaces else "no auth surface confirmed yet"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _cookie_names(self, evidence: EvidenceSnapshot) -> List[str]:
        names: List[str] = []
        for item in evidence.items():
            out = str(getattr(item, "output", "") or "")
            for m in re.finditer(
                r"(?:set-cookie|cookie)[:=]\s*([A-Za-z_][A-Za-z0-9_.\-]*)",
                out, re.IGNORECASE,
            ):
                name = m.group(1)
                if name.lower() not in ("cookie", "set-cookie") and name not in names:
                    names.append(name)
        # Cookies managed through the session tool
        for item in evidence.items():
            if getattr(item, "tool", "") == "manage_cookies":
                for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_.\-]*)\s*=", str(getattr(item, "output", "") or "")):
                    name = m.group(1).strip()
                    if name and name not in names:
                        names.append(name)
        return names[:10]

    def _client_side_auth(self, js_text: str) -> List[str]:
        if not js_text:
            return []
        low = js_text.lower()
        found = []
        for pattern, label in [
            ("isadmin", "isAdmin flag"),
            ("localstorage", "localStorage-based auth"),
            ("role ===", "role equality check"),
            ("role ==", "role equality check"),
            ("admin", "admin string reference"),
            ("redirect('login", "client-side redirect on auth"),
            ("token", "token handling"),
        ]:
            if pattern in low:
                found.append(label)
        return found[:5]


def regex_user_identifiers(text: str) -> List[str]:
    """Extract user-identifier parameters from URLs/requests."""
    found: List[str] = []
    for m in re.finditer(r"([?&](?:user|uid|user_id|userid|id|account|profile)=)([A-Za-z0-9_.\-]+)", text):
        param = m.group(1).replace("=", "")
        val = m.group(2)
        entry = f"{param}={val}"
        if entry not in found:
            found.append(entry)
        if len(found) >= 6:
            break
    return found
