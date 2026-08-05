"""Stage 7 PHP specialist - type juggling & object injection indicators.

Analyzes evidence (source code, responses) for:

- PHP loose comparison (==) type-juggling patterns (hash strings starting
  with "0e" compared with ==)
- md5/sha1 comparison bypass surfaces (arrays, 0e collisions)
- unserialize() usage and magic-method indicators (__wakeup, __destruct)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "php", "type juggling", "loose comparison", "==", "md5", "sha1",
    "serialize", "unserialize", "magic", "__wakeup", "__destruct",
    "0e", "json", "array", "hash", "php object", "phar", "comparison",
]

JUGGLING_MARKERS = [
    "0e[0-9]{8,}",          # "0e..." scientific-notation hashes
    "md5(", "sha1(",
    "== $", "==$", "if ($a == $b", "== '", '== "',
]

OBJECT_MARKERS = ["unserialize(", "__wakeup", "__destruct", "__toString",
                  "__call", "serialize(", "phar://"]


class PHPSpecialist(Specialist):
    """Evidence-driven PHP type juggling / object injection analysis."""

    name = "web.php"
    category = "web"
    description = "Detect PHP type-juggling comparisons and unserialize() object-injection indicators."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text()
        low = text.lower()

        if "php" in low:
            confirmed.append("PHP technology indicator present in evidence.")

        # Type juggling indicators
        zeroe = re.findall(r"\b0e\d{8,}\b", text)
        if zeroe:
            confirmed.append(
                f"'0e...' scientific-notation hash string(s) found: {', '.join(zeroe[:3])} - "
                "PHP == comparison may treat them as 0 (type-juggling bypass surface)."
            )
        if "==" in text and ("md5" in low or "sha1" in low or "hash" in low):
            confirmed.append(
                "Loose == comparison of hashes detected - test array inputs and "
                "0e-collision strings."
            )

        # Object injection indicators
        obj_hits = [m for m in OBJECT_MARKERS if m in low]
        if obj_hits:
            confirmed.append(
                f"Serialization/magic-method indicator(s): {', '.join(obj_hits[:5])} - "
                "check for unserialize() on user-controlled data."
            )

        steps.append(
            "Verify a juggling hypothesis with a harmless request: pass an array "
            "(e.g. password[]=) or a known 0e string and compare behavior - never "
            "invent hash values."
        )
        steps.append(
            "For unserialize() surfaces, only craft a PHP object payload when the "
            "authorized challenge clearly requires it and source code confirms a "
            "usable gadget (__wakeup/__destruct)."
        )
        steps.append(
            "Record the exact comparison code location (file + line) as evidence "
            "before claiming a bypass."
        )

        if not zeroe and "unserialize(" not in low and "==" not in text:
            rejected.append(
                "No PHP comparison or serialization indicators in evidence yet."
            )
            steps.append(
                "Inspect PHP source files (read_text_file / search_files for "
                "'==' with hashes, 'unserialize(') or identify PHP via "
                "detect_framework."
            )

        return self._result(
            evidence, profile,
            hypothesis="PHP loose comparison or unsafe unserialize() may allow a bypass.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist="web.sql_injection",
            summary="PHP analysis: " + ("indicators found" if confirmed else "none yet"),
        )
