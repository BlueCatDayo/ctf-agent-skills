"""Stage 7 insecure file upload specialist.

Analyzes evidence for upload surfaces: upload forms, extension/MIME
handling differences, client-side restriction lists, and path disclosure.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "upload", "file upload", "multipart", "enctype", "extension", "mime",
    "content-type", "jpg", "png", "gif", "php", "allowed types",
    "accept=", "submit file", "drag and drop",
]

# Extensions commonly restricted or abused in CTF upload challenges.
RISKY_EXTENSIONS = ["php", "php5", "phtml", "phar", "jsp", "asp", "aspx",
                    "exe", "cgi", "pl", "py", "html", "svg"]


class UploadAnalysisSpecialist(Specialist):
    """Evidence-driven file upload analysis."""

    name = "web.upload_analysis"
    category = "web"
    description = "Inspect upload forms, extension/MIME restrictions, and file handling."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text().lower()

        if "upload" in text or "multipart" in text or "enctype" in text:
            confirmed.append("File upload surface detected (upload form / multipart request).")

        # Client-side restriction list
        m = re.search(r"accept\s*=\s*[\"']([^\"']+)[\"']", text, re.IGNORECASE)
        if m:
            confirmed.append(f"Client-side accept list: {m.group(1)} - note it is bypassable (server must re-validate).")

        ext_hits = [e for e in RISKY_EXTENSIONS if e in text]
        if ext_hits:
            confirmed.append(
                f"Executable/risky extension reference(s): {', '.join(ext_hits[:5])} - "
                "check whether the server blocks them or only the client does."
            )

        if evidence.has_tool("http_post"):
            confirmed.append("Upload attempt(s) made via http_post - responses recorded.")

        steps.append(
            "Upload a harmless test file first and record status code, response "
            "body, and whether a stored path is echoed."
        )
        steps.append(
            "If the server reflects a storage path, request it directly to confirm "
            "whether the file is served (and with what content-type)."
        )
        steps.append(
            "Test extension/MIME variations only after baseline behavior is recorded "
            "(e.g., .png vs .png.php vs .php%00.png); keep payloads harmless."
        )
        steps.append(
            "Never upload or create backdoor/webshell content outside an authorized "
            "training environment, and never claim code execution without confirmed "
            "tool output showing it."
        )

        if "upload" not in text and not evidence.has_tool("http_post"):
            rejected.append("No upload surface found in evidence so far.")
            steps.append("Look for upload forms via extract_forms_from_page and inspect_webpage.")

        return self._result(
            evidence, profile,
            hypothesis="The file upload handler may accept dangerous files or mis-handle extensions.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist="web.file_inclusion",
            summary="Upload analysis: " + ("upload surface found" if confirmed else "no surface yet"),
        )
