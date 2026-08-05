"""Stage 7 File & Path workflow specialist (spec 5).

Analyzes evidence for:

- path traversal
- local file inclusion (LFI)
- file-download parameters, template file parameters, language/page params
- exposed source files and backup files
- configuration disclosure
- SQLite database discovery

Uses controlled checks, normalizes paths safely, and records the exact
requested path and confirmed response evidence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist, find_substrings

SIGNALS = [
    "lfi", "rfi", "file", "include", "page=", "lang=", "template=",
    "download", "readfile", "path traversal", "dir", "directory",
    "/etc/passwd", "../", "..\\", "backup", ".bak", ".git", "sqlite",
    "config", ".env", "source", "flag", "index.php", "load", "view=",
    "cat ", "document=", "doc=",
]

# Parameter names commonly used for file/path access.
FILE_PARAMETERS = ["file", "page", "lang", "template", "view", "download",
                   "doc", "document", "load", "include", "path", "dir",
                   "read", "show", "filename", "name"]

# Confirmation markers: real file content disclosed in output.
DISCLOSURE_MARKERS = [
    "root:x:0:0", "/etc/passwd", "nobody:x:", "daemon:x:", "uid=",
    "mysql", "<?php", "<?", "define(", "app.listen", "require('", "import ",
    "CREATE TABLE", "sqlite", ".env", "app.config",
]

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".swp", "~", ".zip",
                     ".tar.gz", ".sql", ".txt", ".php~", ".env"]


class FileInclusionSpecialist(Specialist):
    """Evidence-driven file & path workflow (spec 5)."""

    name = "web.file_inclusion"
    category = "web"
    description = "Detect path traversal, LFI, backup/config disclosure, and sqlite discovery."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        raw: List[str] = []
        text = evidence.text()
        low = text.lower()

        # 1. File-ish parameters used
        used_params = [p for p in FILE_PARAMETERS if re.search(rf"[?&]{p}=", low)]
        if used_params:
            confirmed.append(
                f"File/path-like parameter(s) in use: {', '.join(used_params[:8])}"
            )

        # 2. Traversal markers in requests
        if "../" in text or "..\\" in text or "%2e%2e%2f" in low:
            confirmed.append("Path traversal sequence(s) observed in requests (../).")

        # 3. Disclosure confirmation (file content leaked)
        disclosure = find_substrings(evidence.successful_output().lower(), DISCLOSURE_MARKERS)
        if disclosure:
            confirmed.append(
                f"File-content disclosure markers in responses: {', '.join(disclosure[:5])} "
                "- file read confirmed (record the exact path used)."
            )
            for item in evidence.items():
                out = str(getattr(item, "output", "") or "").lower()
                if any(d in out for d in disclosure):
                    raw.append(f"[{getattr(item, 'tool', '')}] {str(getattr(item, 'output', ''))[:200]}")
                    break

        # 4. Backup files discovered
        backup_hits = [e for e in BACKUP_EXTENSIONS if e in low]
        if backup_hits:
            confirmed.append(
                f"Backup/source file reference(s) found: {', '.join(backup_hits[:5])} - "
                "use discover_hidden_endpoints / find_backup_files to fetch them."
            )

        # 5. SQLite database discovery
        if re.search(r"\.(sqlite|db|sqlite3)\b", low):
            confirmed.append("SQLite database file reference detected (download and inspect with read_text_file/search_files).")

        # 6. Source-code / config disclosure
        if ".git" in low:
            confirmed.append(".git exposure indicator found - check for /.git/HEAD and config disclosure.")
        if ".env" in low:
            confirmed.append(".env configuration disclosure indicator found.")

        # Recommended steps (controlled)
        steps.append(
            "For each file-like parameter, request a known safe local file with a "
            "controlled traversal (e.g. /etc/passwd) and record status + body differences."
        )
        steps.append(
            "Normalize paths safely: never send raw binary null bytes or command "
            "chains; keep traversal depth minimal and targeted."
        )
        steps.append(
            "Check backup files via find_backup_files / discover_hidden_endpoints "
            "(small conservative lists) and read any hit with read_text_file."
        )
        steps.append(
            "Record the exact requested path and the response excerpt for every "
            "confirmed disclosure."
        )

        if not used_params and not disclosure and not backup_hits:
            rejected.append(
                "No file-like parameters, traversal markers, backup references, or "
                "disclosure evidence found yet."
            )
            steps.append(
                "Find file-reading surface first: extract_forms_from_page and "
                "discover_api_endpoints to locate page=/file=/download= parameters."
            )

        next_spec = "web.api_analysis" if ".js" in low or ".js" in text.lower() else ""
        return self._result(
            evidence, profile,
            hypothesis="A file/path parameter may allow reading files outside the intended directory.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            raw_evidence=raw,
            next_specialist=next_spec,
            summary="File/path evidence: " + ("disclosure confirmed" if disclosure
                                              else "indicators only" if used_params or backup_hits
                                              else "none yet"),
        )
