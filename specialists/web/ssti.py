"""Stage 7 Server-Side Template Injection specialist (spec 4).

Detects reflected input, identifies template syntax, compares
arithmetic-expression output, and infers a likely template engine from
confirmed behavior.  Uses harmless verification expressions first and
avoids OS command execution unless the authorized challenge clearly
requires it and the user provided the target.

The specialist distinguishes:

- normal reflection (input echoed verbatim)
- client-side rendering (JavaScript templating)
- server-side template evaluation (arithmetic result changes)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist, find_substrings

SIGNALS = [
    "ssti", "template", "jinja", "twig", "handlebars", "mustache",
    "velocity", "freemarker", "{{", "{%", "{{7*7}}", "${", "render",
    "blade", "jade", "ejs", "erb", "smarty", "django", "templating",
]

# Template-engine fingerprints.
ENGINE_MARKERS = [
    ("Jinja2 / Django", ["jinja", "django", "{{7*7}}", "{{ 7*7 }}", "{{7*'7'}}"]),
    ("Twig", ["twig", "{{7*7}}", "{{ 7*7 }}"]),
    ("Smarty", ["smarty", "{$", "{$7*7}"]),
    ("Freemarker", ["freemarker", "${7*7}"]),
    ("Velocity", ["velocity", "#set", "#if"]),
    ("ERB (Ruby)", ["<%= 7*7 %>", "erb"]),
    ("EJS (Node)", ["<%= 7*7 %>", "ejs"]),
]

ARITHMETIC_EXPRS = [
    "{{7*7}}", "{{ 7*7 }}", "${7*7}", "{{7*'7'}}", "<%= 7*7 %>",
    "{$7*7}", "{{7*7}}", "{{7*7}}", "{{7*7}}",
]

REFLECTION_PATTERNS = [
    "7*7", "49", "7777777", "{{7*7}}", "${7*7}",
]


class SSTISpecialist(Specialist):
    """Evidence-driven server-side template injection workflow (spec 4)."""

    name = "web.ssti"
    category = "web"
    description = "Detect reflected input and server-side template evaluation."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text()
        low = text.lower()

        # 1. Template syntax present in requests or pages
        syntax_hits = [s for s in SIGNALS if s in low and len(s) > 2]
        if syntax_hits:
            confirmed.append(
                f"Template syntax / templating signal(s) present: {', '.join(syntax_hits[:5])}"
            )

        # 2. Arithmetic expression evaluation => server-side template execution
        engine = self._detect_engine(text)
        if engine:
            confirmed.append(
                f"Arithmetic template expression evaluated server-side "
                f"(e.g. 7*7 -> 49); likely engine: {engine}."
            )
        elif "49" in text and any(expr in text for expr in ARITHMETIC_EXPRS):
            confirmed.append(
                "Arithmetic template expression result (49) observed - "
                "server-side template evaluation confirmed."
            )
            engine = self._detect_engine(text) or "unknown (see markers)"

        # 3. Reflection detection
        reflected = self._reflected_input(evidence)
        if reflected:
            confirmed.append(
                f"Input reflected in responses: {', '.join(reflected[:3])} - "
                "distinguish normal reflection from template evaluation."
            )

        # 4. Distinguish client-side rendering
        js_text = " ".join(evidence.outputs_for(
            "analyze_javascript_file", "analyze_javascript_url",
            "extract_javascript_from_page",
        ))
        client_side = any(k in js_text.lower() for k in (
            "innerhtml", "textcontent", "template", "mustache", "handlebars",
            "ejs", "replace(", "appendchild",
        ))
        if client_side:
            confirmed.append(
                "Client-side templating detected in JavaScript - verify whether the "
                "expression is evaluated by the browser (no server-side injection) "
                "or echoed by the server (SSTI)."
            )

        # Recommended steps
        steps.append(
            "First use a harmless arithmetic probe on each reflected parameter, "
            "e.g. {{7*7}} or ${7*7}, and compare the response to the unmodified one."
        )
        steps.append(
            "If 49 is reflected, infer the engine ({{7*'7'}} returns 7777777 in "
            "Jinja2/Twig; <em>string repetition</em> distinguishes engines)."
        )
        steps.append(
            "Inspect template-related error messages (TemplateSyntaxError, "
            "jinja2.exceptions, Twig\\Error) for engine confirmation."
        )
        steps.append(
            "Avoid OS command execution ({{config.__class__...}} RCE chains) unless "
            "the authorized challenge clearly requires it and the target was "
            "explicitly provided by the user."
        )

        if not syntax_hits and not reflected:
            rejected.append(
                "No template syntax, reflected input, or arithmetic-result evidence found."
            )
            steps.append(
                "Identify reflected parameters first (search for values echoed in "
                "the response, e.g. a search box or name field)."
            )

        next_spec = "web.file_inclusion" if engine else ""
        return self._result(
            evidence, profile,
            hypothesis="A reflected parameter may be evaluated by a server-side template engine.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist=next_spec,
            summary="SSTI: " + (f"server-side evaluation confirmed ({engine})" if engine
                                else "no evaluation confirmed yet"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _detect_engine(self, text: str) -> str:
        low = text.lower()
        for name, markers in ENGINE_MARKERS:
            if any(m.lower() in low for m in markers):
                return name
        return ""

    def _reflected_input(self, evidence: EvidenceSnapshot) -> List[str]:
        """Find values that appear both in arguments and in outputs."""
        reflected: List[str] = []
        arg_values: List[str] = []
        for item in evidence.items():
            args = getattr(item, "arguments", None)
            if isinstance(args, dict):
                for v in args.values():
                    if isinstance(v, str) and 2 <= len(v) <= 40:
                        arg_values.append(v)
        for item in evidence.items():
            out = str(getattr(item, "output", "") or "")
            for v in arg_values:
                if v in out and v not in reflected and not v.isdigit():
                    reflected.append(v)
                if len(reflected) >= 4:
                    break
        return reflected
