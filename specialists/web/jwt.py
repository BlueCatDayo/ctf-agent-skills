"""Stage 7 JWT weakness specialist.

Analyzes evidence for JSON Web Tokens: structure, claims, expiry,
algorithms, and role/permission fields.  Decodes JWT header/payload from
tool output (signature is never verified - decoder only) and highlights
weakness indicators such as ``alg: none``, missing ``exp``, or privileged
role claims.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "jwt", "eyj", "bearer", "token", "alg", "iat", "exp", "nbf", "iss",
    "role", "claims", "json web token", "authorization: bearer",
]

# Header starts with "eyJ"; signature may be absent (alg:none style tokens).
JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(\.[A-Za-z0-9_\-]{0,})?"
)


def decode_jwt_part(part: str) -> Optional[Dict[str, Any]]:
    """Decode a base64url JWT segment to a dict, or None."""
    try:
        padded = part + "=" * (-len(part) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def parse_jwt(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[str]]:
    """Return (header, payload, error) for a JWT string.

    ``error`` is None on success and a string describing the problem
    otherwise.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return None, None, "not a JWT (needs header and payload)"
    header = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])
    if header is None:
        return None, None, "could not decode header"
    if payload is None:
        return header, None, "could not decode payload"
    return header, payload, None


class JWTSpecialist(Specialist):
    """Evidence-driven JWT weakness analysis."""

    name = "web.jwt"
    category = "web"
    description = "Decode JWT claims, check expiry, algorithms, and role fields."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        raw_evidence: List[str] = []

        tokens = self._collect_tokens(evidence)
        if not tokens:
            rejected.append(
                "No JWT token found in tool output. Look for Authorization: Bearer "
                "headers or tokens in cookies/JavaScript."
            )
            steps.append(
                "Find the token first: analyze_headers / manage_cookies for "
                "authorization and cookie values; analyze_javascript_* for embedded tokens."
            )
            return self._result(
                evidence, profile,
                hypothesis="A JWT may contain weak claims or algorithm handling.",
                confirmed=confirmed, rejected=rejected, steps=steps,
                next_specialist="web.authentication",
                summary="No JWT observed in evidence.",
            )

        for token in tokens[:4]:
            header, payload, error = parse_jwt(token)
            raw_evidence.append(f"token: {token[:60]}...")
            if error:
                rejected.append(f"Token could not be decoded ({error}).")
                continue
            header = header or {}
            payload = payload or {}

            alg = str(header.get("alg", "?"))
            typ = str(header.get("typ", "?"))
            confirmed.append(f"JWT algorithm: {alg} (typ={typ})")

            if alg.lower() in ("none", "null"):
                confirmed.append(
                    "JWT header declares algorithm 'none' - the server may accept "
                    "unsigned tokens (verify with a request before claiming)."
                )
            if alg == "RS256":
                steps.append(
                    "RS256 token - check whether the server verifies against the "
                    "public key or falls back to HS256 using the public key as HMAC secret."
                )

            # Claims analysis
            claims = self._analyze_claims(payload)
            if claims:
                confirmed.extend(claims)

            if "exp" not in payload:
                steps.append("Token has no 'exp' claim - check whether expiry is enforced.")

        # Evidence-based guidance
        steps.append(
            "Verify before claiming: replay the token / a modified role claim through "
            "an authorized request and confirm the server accepts it (tool output must "
            "show the protected resource)."
        )
        steps.append(
            "Never report a JWT bypass without repeatable evidence: the modified "
            "token must produce an actual access change in tool output."
        )

        next_spec = "web.authentication"
        return self._result(
            evidence, profile,
            hypothesis="JWT claims or algorithm handling may be weak.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            raw_evidence=raw_evidence,
            next_specialist=next_spec,
            summary=f"Decoded {len(tokens)} JWT(s); algorithm and claims recorded.",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_tokens(self, evidence: EvidenceSnapshot) -> List[str]:
        tokens: List[str] = []
        for item in evidence.items():
            out = str(getattr(item, "output", "") or "")
            args = getattr(item, "arguments", None)
            for source in (out, str(args)):
                for m in JWT_RE.finditer(source):
                    token = m.group(0)
                    if token not in tokens:
                        tokens.append(token)
        return tokens[:6]

    def _analyze_claims(self, payload: Dict[str, Any]) -> List[str]:
        notes: List[str] = []
        for key in ("role", "admin", "is_admin", "permission", "group", "user_type"):
            if key in payload:
                notes.append(f"JWT claim '{key}' = {payload[key]!r} - verify server enforces it.")
        for key in ("user", "uid", "user_id", "sub"):
            if key in payload:
                notes.append(f"JWT identity claim '{key}' = {payload[key]!r}.")
        if "exp" in payload:
            notes.append("JWT has 'exp' claim (expiry present).")
        return notes[:6]
