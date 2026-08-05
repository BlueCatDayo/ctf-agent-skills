"""Stage 7 SQL injection specialist (spec 2).

Analyzes evidence for SQL injection indicators:

- possible injectable parameters (forms / URL params / API args)
- SQL error messages and database family identification
- normal vs altered response differences (boolean-based signals)
- time-response differences (reported as hypotheses, never fabricated)
- login forms and API parameters

The specialist is read-only: it inspects tool output and recommends
low-risk verification steps.  It NEVER recommends or performs DROP,
DELETE, UPDATE, INSERT, file-writing SQL, or OS command execution.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist, find_substrings, regex_matches

# ---------------------------------------------------------------------------
# Signal and evidence patterns
# ---------------------------------------------------------------------------

SIGNALS = [
    "sql", "injection", "sqli", "query", "database", "mysql", "postgres",
    "sqlite", "select", "union", "parameter", "login", "where", "order by",
    "id=", "1=1", "1=2", "'", "table", "column", "insert into",
]

# Error-message fingerprints that confirm SQL parsing errors.
SQL_ERROR_PATTERNS = [
    "sql syntax",
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "postgresql",
    "psycopg2",
    "sqlite3.operationalerror",
    "sqlite3.error",
    "ora-",
    "oracle error",
    "microsoft ole db",
    "unclosed quotation mark",
    "jdbc",
    "hibernate",
    "db2 sql error",
    "sqlstate",
    "mdb2 error",
    "syntax error",
    "near \"",
    "sqlalchemy",
]

# Database family detection from error text.
DB_FAMILY_PATTERNS = [
    ("MySQL", ["mysql", "mysqli", "mariadb"]),
    ("PostgreSQL", ["postgres", "psycopg", "sqlstate"]),
    ("SQLite", ["sqlite"]),
    ("Oracle", ["ora-", "oracle"]),
    ("MSSQL", ["microsoft ole db", "unclosed quotation mark", "sql server"]),
    ("JDBC/Hibernate", ["jdbc", "hibernate"]),
]

# Boolean-based evidence: payloads seen in tool arguments or output.
BOOLEAN_MARKERS = ["1=1", "1=2", "'1'='1", "'1'='2", "or 1=1", "or 1=2"]

# Statements that must never be recommended (spec 2).
FORBIDDEN = ["drop ", "delete ", "update ", "insert ", "into outfile",
             "into dumpfile", "xp_cmdshell", "select ... into", "truncate "]


class SQLInjectionSpecialist(Specialist):
    """Evidence-driven SQL injection workflow (spec 2)."""

    name = "web.sql_injection"
    category = "web"
    description = "Detect and verify SQL injection in parameters and login forms."
    signals = SIGNALS

    # ------------------------------------------------------------------
    # Relevance
    # ------------------------------------------------------------------

    def score(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> float:
        base = super().score(evidence, profile)
        # SQL error messages are strong direct evidence.
        text = evidence.text().lower()
        if any(p in text for p in SQL_ERROR_PATTERNS):
            base = max(base, 0.9)
        return base

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        evidence_text = evidence.text().lower()
        success_text = evidence.successful_output()

        # 1. Injectable input points (from evidence arguments/output)
        input_points = self._injectable_parameters(evidence)
        if input_points:
            confirmed.append(
                f"Potential injectable parameter(s): {', '.join(input_points[:6])}"
            )

        # 2. SQL error messages => strongest confirmation
        db_errors = find_substrings(success_text, SQL_ERROR_PATTERNS)
        if db_errors:
            confirmed.append(
                f"SQL error message(s) observed: {', '.join(db_errors[:5])}"
            )
            family = self._detect_db_family(success_text)
            if family:
                confirmed.append(f"Database family indicator: {family}")

        # 3. Boolean-based response differences
        bool_hits = find_substrings(evidence_text, BOOLEAN_MARKERS)
        if bool_hits:
            confirmed.append(
                f"Boolean comparison payload(s) applied: {', '.join(bool_hits[:4])} "
                "- compare responses for 1=1 vs 1=2."
            )
        else:
            steps.append(
                "Compare normal vs altered responses with compare_http_responses "
                "using a single quote and '1=1' / '1=2' on one parameter."
            )

        # 4. Login forms / API parameters
        if evidence.has_tool("extract_forms_from_page", "inspect_webpage"):
            confirmed.append("Login form / page structure inspected (tool output recorded).")
        if evidence.has_tool("http_post", "http_request", "http_get"):
            confirmed.append("Parameterized HTTP requests executed - responses recorded.")

        # 5. Time-based differences (hypothesis only, from evidence timings)
        if evidence.has_tool("http_post", "http_request"):
            steps.append(
                "If boolean checks are inconclusive, one time-based comparison "
                "(sleep(1) vs no-payload) may be attempted on the same parameter "
                "and the response timing compared."
            )

        # Rejections
        if not db_errors and not bool_hits and not input_points:
            rejected.append(
                "No SQL error messages, boolean-payload markers, or injectable "
                "parameters found in evidence so far."
            )
            steps.append(
                "First identify parameters that reach the database: inspect forms "
                "(extract_forms_from_page) and API parameters before testing."
            )

        # Safety statement (read-only rules)
        steps.append(
            "Read-only verification only: never use DROP, DELETE, UPDATE, INSERT, "
            "file-writing SQL (INTO OUTFILE/DUMPFILE), or OS command execution."
        )

        next_spec = "web.authentication" if evidence.has_tool("extract_forms_from_page") else ""
        summary = "SQL injection evidence: " + ("confirmed indicators" if db_errors else "no confirmed error yet")
        return self._result(
            evidence,
            profile,
            hypothesis="A SQL injection may exist in a database-backed parameter.",
            confirmed=confirmed,
            rejected=rejected,
            steps=steps,
            next_specialist=next_spec,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _injectable_parameters(self, evidence: EvidenceSnapshot) -> List[str]:
        """Collect candidate parameter names from tool arguments and output."""
        params: List[str] = []
        for item in evidence.items():
            args = getattr(item, "arguments", None)
            if isinstance(args, dict):
                for key in ("param", "params", "data", "url", "path"):
                    val = args.get(key)
                    if isinstance(val, str):
                        for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)=([^&\s]+)", val):
                            p = m.group(1).lower()
                            if p not in params and p not in ("http", "https"):
                                params.append(p)
        # common parameter names from output text
        text = evidence.text().lower()
        for cand in ["id", "user", "name", "search", "query", "q", "email",
                     "username", "page", "cat", "product", "file"]:
            if re.search(rf"[?&]{cand}=", text) and cand not in params:
                params.append(cand)
        return params[:10]

    def _detect_db_family(self, text: str) -> str:
        low = text.lower()
        for family, keys in DB_FAMILY_PATTERNS:
            if any(k in low for k in keys):
                return family
        return ""
