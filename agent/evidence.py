"""Stage 6 evidence log - every reported finding must originate from tool output.

Every tool result is recorded as an EvidenceItem with its source tool,
arguments, output excerpt, and success/failure status.  Confirmed findings
are derived exclusively from successful tool outputs.  Flags are extracted
with a pattern matcher; a flag is only "confirmed" when it appears in the
output of a successful tool result.
"""

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

FLAG_PATTERN = re.compile(r"flag\{[^}\n]{1,200}\}", re.IGNORECASE)

DEFAULT_MAX_ENTRIES = 200
DEFAULT_EXCERPT_CHARS = 400


@dataclass
class EvidenceItem:
    """A single recorded tool result."""

    id: str
    tool: str
    arguments: str
    output: str
    success: bool
    truncated: bool = False
    timed_out: bool = False
    error: Optional[str] = None
    flag: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def excerpt(self, limit: int = DEFAULT_EXCERPT_CHARS) -> str:
        """Return a compact one-line excerpt of the output."""
        text = " ".join((self.output or "").split())
        if len(text) > limit:
            return text[:limit] + "..."
        return text

    def to_prompt_line(self) -> str:
        """Render this item as a single evidence-log line."""
        status = "ok" if self.success else ("timeout" if self.timed_out else "error")
        args = self.arguments if len(self.arguments) <= 120 else self.arguments[:117] + "..."
        line = f"- [{status}] {self.tool}({args}): {self.excerpt()}"
        if self.flag:
            line += f"  **FLAG: {self.flag}**"
        return line


class EvidenceLog:
    """Ordered, capped log of tool results with derived findings."""

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES):
        self._max_entries = max_entries
        self._items: List[EvidenceItem] = []

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        tool_name: str,
        arguments: Any,
        result: Any,
    ) -> EvidenceItem:
        """Record a tool result and return the new EvidenceItem.

        Parameters
        ----------
        tool_name:
            The executed tool's name.
        arguments:
            The arguments passed to the tool (dict or JSON string).
        result:
            A ToolResult-like object with success/output/error/truncated/
            timed_out attributes.

        Returns
        -------
        EvidenceItem
            The recorded item.
        """
        if isinstance(arguments, dict):
            args_text = json.dumps(arguments, sort_keys=True, default=str)
        else:
            args_text = str(arguments or "")
        output = getattr(result, "output", None) or ""
        success = bool(getattr(result, "success", False))
        error = getattr(result, "error", None)
        truncated = bool(getattr(result, "truncated", False))
        timed_out = bool(getattr(result, "timed_out", False))

        flag = None
        if success:
            match = FLAG_PATTERN.search(output)
            if match:
                flag = match.group(0)

        item = EvidenceItem(
            id=uuid.uuid4().hex[:8],
            tool=tool_name,
            arguments=args_text,
            output=output,
            success=success,
            truncated=truncated,
            timed_out=timed_out,
            error=error,
            flag=flag,
        )
        self._items.append(item)
        if len(self._items) > self._max_entries:
            del self._items[: len(self._items) - self._max_entries]
        return item

    def record_finding(self, tool_name: str, description: str, output: str = "") -> EvidenceItem:
        """Record an explicit finding derived from a tool result.

        Used when the agent (or a test) wants to log a conclusion that is
        still backed by tool output.
        """
        result = type(
            "R",
            (),
            {
                "success": True,
                "output": output or description,
                "error": None,
                "truncated": False,
                "timed_out": False,
            },
        )()
        return self.record(tool_name, {"finding": description}, result)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def items(self) -> List[EvidenceItem]:
        """Return a copy of all recorded items."""
        return list(self._items)

    def clear(self) -> None:
        """Clear all recorded evidence."""
        self._items.clear()

    def has_items(self) -> bool:
        """Return True when at least one tool result has been recorded."""
        return len(self._items) > 0

    def successful_items(self) -> List[EvidenceItem]:
        """Return only successful tool results."""
        return [i for i in self._items if i.success]

    def failed_items(self) -> List[EvidenceItem]:
        """Return only failed tool results."""
        return [i for i in self._items if not i.success]

    def flags_in_output(self) -> List[str]:
        """Return all flag patterns found in any successful output (deduped)."""
        seen = []
        for item in self._items:
            if not item.success or not item.flag:
                continue
            if item.flag not in seen:
                seen.append(item.flag)
        return seen

    def candidate_flags(self) -> List[str]:
        """Return flag patterns found in any recorded output (incl. failures)."""
        seen = []
        for item in self._items:
            match = FLAG_PATTERN.search(item.output or "")
            if match and match.group(0) not in seen:
                seen.append(match.group(0))
        return seen

    def has_flag(self) -> bool:
        """Return True when a flag appears in a successful tool output."""
        return any(i.flag for i in self._items if i.success)

    def flag_status(self) -> Tuple[str, Optional[str]]:
        """Return (status_label, flag_value).

        status_label is "Confirmed" when a flag appears in a successful tool
        result, "Not Confirmed" otherwise.
        """
        confirmed = self.flags_in_output()
        if confirmed:
            return "Confirmed", confirmed[0]
        return "Not Confirmed", None

    def confirmed_findings(self, limit: int = 10) -> List[str]:
        """Derive confirmed findings strictly from successful tool outputs.

        Every returned finding includes the source tool and an output
        excerpt, so each finding can be traced back to tool output.
        """
        findings = []
        for item in self.successful_items():
            if len(findings) >= limit:
                break
            excerpt = item.excerpt(200)
            if not excerpt and not item.flag:
                continue
            text = excerpt if excerpt else "(no textual output)"
            if item.flag:
                text = f"flag found: {item.flag} | {text}"
            findings.append(f"[{item.tool}] {text}")
        return findings

    def report_lines(self, limit: int = 8) -> List[str]:
        """Return the most recent evidence entries as prompt/report lines."""
        return [item.to_prompt_line() for item in self._items[-limit:]]

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def to_prompt(self, max_chars: int = 2500) -> str:
        """Render the evidence log as a prompt section."""
        lines = ["## Evidence Log (confirmed facts only - derive conclusions from these)"]
        if not self._items:
            lines.append("(no tool results recorded yet)")
        else:
            for line in self.report_lines(limit=12):
                lines.append(line)
        text = "\n".join(lines)
        if len(text) > max_chars:
            return text[:max_chars] + "\n... [evidence truncated]"
        return text

    def summary(self) -> str:
        """Return a one-line summary of the evidence log."""
        total = len(self._items)
        ok = len(self.successful_items())
        flags = len(self.flags_in_output())
        return f"Evidence log: {total} results ({ok} ok, {flags} flag{'s' if flags != 1 else ''})"


def format_structured_report(
    confirmed_findings: List[str],
    evidence_lines: List[str],
    flag_status: str,
    flag_value: Optional[str],
    next_step: str,
) -> str:
    """Build the structured final report required by Stage 6.

    Sections: Confirmed Findings, Evidence, Flag Status, Recommended Next Step.
    """
    lines = [
        "## Investigation Report",
        "",
        "### Confirmed Findings",
    ]
    if confirmed_findings:
        lines.extend(f"- {f}" for f in confirmed_findings)
    else:
        lines.append("- (no confirmed findings yet)")

    lines.append("")
    lines.append("### Evidence")
    if evidence_lines:
        lines.extend(evidence_lines)
    else:
        lines.append("- (no evidence recorded)")

    lines.append("")
    lines.append("### Flag Status")
    if flag_value:
        lines.append(f"- {flag_status}: `{flag_value}`")
    else:
        lines.append(f"- {flag_status}")

    lines.append("")
    lines.append("### Recommended Next Step")
    lines.append(f"- {next_step}")
    return "\n".join(lines)
