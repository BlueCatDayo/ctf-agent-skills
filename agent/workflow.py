"""Stage 6 workflow manager - challenge type detection and workflow selection.

Detects the challenge type (Web, Binary, Crypto, Forensics, Misc) from the
user request, filenames, file extensions, and tool observations, then maps
the type to an ordered investigation workflow with recommended tools.

Progress evaluation decides whether more investigation is required based on
the current plan and evidence (flag confirmed, plan complete, steps remain).
"""

import re
from typing import Any, Dict, List, Optional, Tuple

CHALLENGE_TYPES = ["web", "binary", "crypto", "forensics", "misc"]

# Signal keywords per challenge type (normalized matching).
SIGNALS: Dict[str, Dict[str, Any]] = {
    "web": {
        "keywords": [
            "http", "https", "url", "website", "web", "login", "cookie",
            "session", "header", "xss", "sql injection", "sqli", "csrf",
            "injection", "endpoint", "form", "javascript", "robots.txt",
            "sitemap", "jwt", "api", "parameter", "authentication",
            "lfi", "rfi", "ssrf", "ssti", "upload", "path traversal",
            "directory", "hidden endpoint", "web exploitation",
            "server", "express", "flask", "django", "x-powered-by",
        ],
        "extensions": [".html", ".htm", ".php", ".aspx", ".jsp", ".js", ".json"],
    },
    "binary": {
        "keywords": [
            "binary", "elf", "pwn", "exploit", "buffer overflow", "reverse",
            "reverse engineering", "disassembly", "gdb", "objdump", "readelf",
            "stack", "format string", "rop", "shellcode", "heap", "overflow",
            "mitigation", "nx", "aslr", "pie", "canary", "relro", "fortify",
            "binary exploitation",
        ],
        "extensions": [".bin", ".elf", ".out", ".exe", ".so", ".dll", ".o", ".a"],
    },
    "crypto": {
        "keywords": [
            "crypto", "cipher", "encrypt", "decrypt", "base64", "rot13",
            "hash", "aes", "rsa", "xor", "caesar", "encode", "decode",
            "jwt", "md5", "sha", "vigenere", "key", "ciphertext",
            "plaintext", "otp", "cryptography", "cryptographic",
        ],
        "extensions": [".enc", ".crypt", ".pem", ".key", ".crt", ".csr"],
    },
    "forensics": {
        "keywords": [
            "forensics", "forensic", "pcap", "dump", "memory", "image",
            "stego", "steganography", "metadata", "carving", "exif",
            "packet", "disk", "usb", "malware", "artifact", "timeline",
            "recovery", "hidden file", "file carving", "network capture",
        ],
        "extensions": [
            ".pcap", ".pcapng", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
            ".zip", ".gz", ".iso", ".raw", ".vhd", ".img", ".tiff",
        ],
    },
    "misc": {
        "keywords": ["misc", "puzzle", "quiz", "general", "riddle", "miscellaneous"],
        "extensions": [],
    },
}

# Ordered investigation workflows per challenge type.  Each step has a
# title, description, and the tool names that can address it (filtered to
# what is available at plan time by the planner).
WORKFLOWS: Dict[str, List[Dict[str, Any]]] = {
    "web": [
        {
            "title": "Initial inspection of the target",
            "description": "Fetch the target page and summarize technologies, forms, scripts, comments, links, and security headers.",
            "tools": ["http_get", "inspect_webpage", "analyze_headers", "http_request"],
        },
        {
            "title": "Session and cookie review",
            "description": "Show cookies and session state set by the server; note sensitive cookie attributes.",
            "tools": ["manage_cookies", "manage_http_session"],
        },
        {
            "title": "Read robots.txt and sitemap",
            "description": "Check /robots.txt and /sitemap.xml for allowed, disallowed, and referenced paths.",
            "tools": ["read_robots_txt", "read_sitemap_xml"],
        },
        {
            "title": "Extract page attack surface",
            "description": "Extract links, forms, JavaScript references, and HTML comments from the page.",
            "tools": [
                "extract_links_from_page", "extract_forms_from_page",
                "extract_javascript_from_page", "extract_html_comments",
                "extract_web_elements",
            ],
        },
        {
            "title": "Discover endpoints and hidden files",
            "description": "Enumerate common directories, API routes, and sensitive files (backups, .git, .env).",
            "tools": [
                "enumerate_directories", "discover_api_endpoints",
                "discover_hidden_endpoints", "find_api_endpoints",
                "find_backup_files",
            ],
        },
        {
            "title": "Identify the technology stack",
            "description": "Detect the framework, server software, and frontend libraries in use.",
            "tools": [
                "detect_framework", "detect_server",
                "detect_technology_stack", "extract_version_info",
                "extract_emails",
            ],
        },
        {
            "title": "Auth and admin surface analysis",
            "description": "Locate login and admin pages and probe their behavior.",
            "tools": ["find_login_page", "find_admin_page", "http_post", "http_get"],
        },
        {
            "title": "Targeted parameter and payload testing",
            "description": "Test specific parameters and injection hypotheses with evidence-backed requests.",
            "tools": [
                "http_post", "http_get", "http_put", "http_delete",
                "compare_http_responses", "decode_data",
            ],
        },
        {
            "title": "Consolidate findings and report",
            "description": "Summarize confirmed findings with evidence and report flag status.",
            "tools": [],
        },
    ],
    "binary": [
        {
            "title": "Identify the binary file",
            "description": "Determine file type and architecture with the file command.",
            "tools": ["binary_file_info"],
        },
        {
            "title": "Check security mitigations",
            "description": "Check NX, PIE, canary, and RELRO with checksec (if installed).",
            "tools": ["binary_checksec", "binary_readelf"],
        },
        {
            "title": "Extract strings",
            "description": "Extract readable strings to spot flags, secrets, and interesting references.",
            "tools": ["binary_strings", "binary_hexdump"],
        },
        {
            "title": "Inspect ELF structure",
            "description": "Inspect ELF headers, sections, relocations, and dynamic entries.",
            "tools": ["binary_readelf", "binary_objdump"],
        },
        {
            "title": "Symbols and libraries",
            "description": "List symbols and linked shared libraries.",
            "tools": ["binary_symbols", "binary_libraries"],
        },
        {
            "title": "Disassemble and analyze",
            "description": "Disassemble interesting functions and analyze control flow.",
            "tools": ["binary_objdump", "analyze_binary"],
        },
        {
            "title": "Consolidate findings and report",
            "description": "Summarize confirmed findings with evidence and report flag status.",
            "tools": [],
        },
    ],
    "crypto": [
        {
            "title": "Inventory crypto files",
            "description": "List and inspect files that may contain ciphertext or keys.",
            "tools": ["list_files", "inspect_file"],
        },
        {
            "title": "Read encoded material",
            "description": "Read text files containing encoded or encrypted values.",
            "tools": ["read_text_file", "search_files"],
        },
        {
            "title": "Decode and identify encodings",
            "description": "Try Base64, hex, URL, ROT13, binary, octal, decimal, ASCII, UTF-8, JWT, Gzip, Zlib, and auto-detection.",
            "tools": ["decode_data"],
        },
        {
            "title": "Analyze hashes and integrity",
            "description": "Compute hashes and compare against known values.",
            "tools": ["calculate_file_hash"],
        },
        {
            "title": "Custom crypto analysis",
            "description": "Use python via run_ctf_command for XOR, Caesar, or custom cipher work.",
            "tools": ["run_ctf_command"],
        },
        {
            "title": "Consolidate findings and report",
            "description": "Summarize confirmed findings with evidence and report flag status.",
            "tools": [],
        },
    ],
    "forensics": [
        {
            "title": "Inventory forensic artifacts",
            "description": "List all files in the challenge and their sizes.",
            "tools": ["list_files"],
        },
        {
            "title": "Inspect artifacts",
            "description": "Identify file types, metadata, hashes, and content previews.",
            "tools": ["inspect_file", "read_text_file"],
        },
        {
            "title": "Extract strings and hex data",
            "description": "Pull readable strings and hex dumps from binaries and captures.",
            "tools": ["binary_strings", "binary_hexdump", "binary_file_info"],
        },
        {
            "title": "Search for flags and secrets",
            "description": "Search text recursively for flag patterns and secrets.",
            "tools": ["search_files"],
        },
        {
            "title": "Decode embedded values",
            "description": "Decode any encoded values found in artifacts.",
            "tools": ["decode_data", "calculate_file_hash"],
        },
        {
            "title": "Consolidate findings and report",
            "description": "Summarize confirmed findings with evidence and report flag status.",
            "tools": [],
        },
    ],
    "misc": [
        {
            "title": "Inventory challenge files",
            "description": "List and inspect all challenge files.",
            "tools": ["list_files", "inspect_file"],
        },
        {
            "title": "Read and search content",
            "description": "Read text files and search for flags and clues.",
            "tools": ["read_text_file", "search_files"],
        },
        {
            "title": "Decode and analyze",
            "description": "Decode encoded values and run approved analysis commands.",
            "tools": ["decode_data", "run_ctf_command", "calculate_file_hash"],
        },
        {
            "title": "Consolidate findings and report",
            "description": "Summarize confirmed findings with evidence and report flag status.",
            "tools": [],
        },
    ],
}

# Default workflow when nothing matches (Misc).
DEFAULT_WORKFLOW = "misc"

# Priority used to break ties (web > binary > crypto > forensics > misc).
_TYPE_PRIORITY = {t: i for i, t in enumerate(CHALLENGE_TYPES)}


class WorkflowManager:
    """Detects challenge types and provides workflow/tool recommendations."""

    # ------------------------------------------------------------------
    # Challenge type detection
    # ------------------------------------------------------------------

    def detect_challenge_type(
        self,
        user_request: str = "",
        filenames: Optional[List[str]] = None,
        file_extensions: Optional[List[str]] = None,
        observations: Optional[List[str]] = None,
    ) -> Tuple[str, float, List[str]]:
        """Detect the challenge type.

        Returns (challenge_type, confidence, reasons) where confidence is a
        float in [0, 1] and reasons lists the matched signals.

        Scoring: each keyword/extensions hit adds 1 point; the type with the
        most hits wins.  Ties are broken by the canonical type order.  When
        nothing matches, returns ("misc", 0.0, []).
        """
        text = " ".join(filter(None, [
            (user_request or "").lower(),
            " ".join(f.lower() for f in (filenames or [])),
            " ".join((o or "").lower() for o in (observations or [])),
        ]))
        ext_list = [e.lower() for e in (file_extensions or [])]

        scores: Dict[str, int] = {}
        reasons: Dict[str, List[str]] = {}

        for ctype, signals in SIGNALS.items():
            score = 0
            hits = []
            for kw in signals["keywords"]:
                if kw in text:
                    score += 1
                    hits.append(kw)
            for ext in signals["extensions"]:
                if any(fname.lower().endswith(ext) for fname in (filenames or [])) or ext in ext_list:
                    score += 2
                    hits.append(ext)
            scores[ctype] = score
            reasons[ctype] = hits

        total = sum(scores.values())
        if total == 0:
            return "misc", 0.0, []

        best = max(CHALLENGE_TYPES, key=lambda t: (scores[t], -_TYPE_PRIORITY[t]))
        confidence = min(1.0, scores[best] / 4.0)
        return best, round(confidence, 2), reasons[best][:8]

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------

    def workflow_for(self, challenge_type: str) -> List[Dict[str, Any]]:
        """Return the ordered workflow steps for a challenge type."""
        return WORKFLOWS.get(challenge_type, WORKFLOWS[DEFAULT_WORKFLOW])

    def recommended_tools(
        self,
        challenge_type: str,
        used_tools: Optional[List[str]] = None,
        available_tools: Optional[List[str]] = None,
        limit: int = 6,
    ) -> List[str]:
        """Return the next recommended tools for the challenge type.

        Tools already used are skipped; tools that are not available are
        skipped.  Returns up to *limit* recommended tool names.
        """
        used = set(used_tools or [])
        available = set(available_tools or [])
        recommended = []
        for step in self.workflow_for(challenge_type):
            for tool in step["tools"]:
                if tool in available and tool not in used and tool not in recommended:
                    recommended.append(tool)
                if len(recommended) >= limit:
                    return recommended
        return recommended

    def workflow_title(self, challenge_type: str) -> str:
        """Return a human-readable workflow title."""
        return {
            "web": "Web Exploitation Workflow",
            "binary": "Binary Exploitation Workflow",
            "crypto": "Cryptography Workflow",
            "forensics": "Forensics Workflow",
            "misc": "General/Misc Workflow",
        }.get(challenge_type, "General Workflow")

    # ------------------------------------------------------------------
    # Progress evaluation
    # ------------------------------------------------------------------

    def evaluate_progress(self, plan: Any, evidence_log: Any) -> Dict[str, Any]:
        """Decide whether more investigation is required before stopping.

        Parameters
        ----------
        plan:
            A planner plan-like object with ``is_complete()`` and
            ``pending_steps()``.
        evidence_log:
            An evidence log-like object with ``has_flag()``.

        Returns
        -------
        dict
            Keys: more_investigation_required, reason, flag_status,
            completed_steps, total_steps.
        """
        flag = bool(evidence_log is not None and evidence_log.has_flag())
        completed = plan.completed_count() if plan is not None else 0
        total = plan.total_count() if plan is not None else 0

        if flag:
            return {
                "more_investigation_required": False,
                "reason": "Flag confirmed via tool output - stop and report.",
                "flag_status": "confirmed",
                "completed_steps": completed,
                "total_steps": total,
            }
        if plan is None or total == 0:
            return {
                "more_investigation_required": True,
                "reason": "No active investigation plan yet.",
                "flag_status": "none",
                "completed_steps": 0,
                "total_steps": 0,
            }
        if plan.is_complete():
            return {
                "more_investigation_required": False,
                "reason": "All planned investigation steps completed.",
                "flag_status": "none",
                "completed_steps": completed,
                "total_steps": total,
            }
        pending = len(plan.pending_steps())
        return {
            "more_investigation_required": pending > 0,
            "reason": f"{pending} planned investigation step(s) remain." if pending else
                      "No active plan yet.",
            "flag_status": "none",
            "completed_steps": completed,
            "total_steps": total,
        }
