"""Stage 7 GraphQL misconfiguration specialist.

Analyzes evidence for GraphQL endpoints and misconfiguration indicators:
introspection enabled, unauthenticated mutations, and field-level access
control gaps.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "graphql", "gql", "introspection", "__typename", "__schema",
    "query", "mutation", "subscription", "/graphql", "graphql endpoint",
    "apollo", "relay", "graphene",
]


class GraphQLSpecialist(Specialist):
    """Evidence-driven GraphQL analysis."""

    name = "web.graphql"
    category = "web"
    description = "Detect GraphQL endpoints and misconfigurations (introspection, authz gaps)."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text()
        low = text.lower()

        if "/graphql" in low or "graphql" in low:
            confirmed.append("GraphQL endpoint reference detected (e.g., /graphql).")

        if "__typename" in text or "__schema" in low:
            confirmed.append(
                "GraphQL introspection indicator observed (__schema/__typename in "
                "responses) - introspection may be enabled."
            )

        if "mutation" in low:
            confirmed.append("GraphQL mutation(s) referenced - check authorization on state-changing operations.")

        steps.append(
            "Probe the GraphQL endpoint with a harmless introspection query "
            "({ __schema { types { name } } }) and record the response."
        )
        steps.append(
            "If introspection is enabled, enumerate types and fields with targeted "
            "queries; do not dump the entire schema repeatedly."
        )
        steps.append(
            "Compare mutation behavior with and without credentials; only report an "
            "authorization gap when a privileged mutation succeeds without auth in "
            "tool output."
        )
        steps.append(
            "Avoid expensive/recursive queries (billion-laughs style) - those are "
            "DoS behavior and out of scope."
        )

        if "graphql" not in low and "__schema" not in low:
            rejected.append("No GraphQL indicator in evidence yet.")
            steps.append(
                "Detect GraphQL endpoints via discover_api_endpoints or by searching "
                "JavaScript with analyze_javascript_* for '/graphql'."
            )

        return self._result(
            evidence, profile,
            hypothesis="A GraphQL endpoint may expose too much via introspection or weak authorization.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist="web.api_analysis",
            summary="GraphQL: " + ("indicators found" if confirmed else "none yet"),
        )
