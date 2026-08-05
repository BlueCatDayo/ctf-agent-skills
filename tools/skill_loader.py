"""Skill loader — parses Markdown files with YAML front matter into structured skill objects."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Minimal YAML front-matter parser (no external dependency)
# ---------------------------------------------------------------------------

def parse_front_matter(text: str) -> Optional[Dict[str, Any]]:
    """Extract and parse YAML front matter from a Markdown document.

    Returns None if no valid ``---`` delimited front matter is found.
    """
    lines = text.split("\n")
    if len(lines) < 2 or lines[0].strip() != "---":
        return None

    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_idx = i
            break

    if end_idx is None:
        return None

    fm_lines = lines[1:end_idx]
    return _parse_yaml_block(fm_lines)


def _parse_yaml_block(lines: List[str]) -> Dict[str, Any]:
    """Parse a list of YAML lines into a nested dict/list structure."""
    result: Dict[str, Any] = {}
    # Strip comments and trailing whitespace
    cleaned = []
    for line in lines:
        # Remove trailing comments (not inside quotes)
        idx = _find_comment_start(line)
        if idx >= 0:
            line = line[:idx]
        cleaned.append(line.rstrip())

    _parse_block(cleaned, 0, 0, result, None)
    return result


def _find_comment_start(line: str) -> int:
    """Find the index of a YAML comment (#) that is not inside a quoted string."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return i
    return -1


def _parse_block(
    lines: List[str],
    start: int,
    indent: int,
    container: Any,
    key_hint: Optional[str],
) -> int:
    """Recursively parse indented YAML lines into *container*.

    Returns the index of the next unprocessed line.
    """
    i = start
    n = len(lines)

    while i < n:
        raw = lines[i]

        # Skip blank lines
        if raw.strip() == "":
            i += 1
            continue

        # Compute current line indent
        current_indent = len(raw) - len(raw.lstrip())

        # Lines with less indentation belong to a parent block
        if current_indent < indent:
            return i

        # Lines with greater indentation are unexpected at this level
        if current_indent > indent and i == start:
            # First line of this block is more indented — skip
            i += 1
            continue

        stripped = raw.strip()

        # List item
        if stripped.startswith("- "):
            if not isinstance(container, list):
                # Convert dict value to list
                if isinstance(container, dict) and key_hint is not None:
                    old = container.pop(key_hint, None)
                    new_list = []
                    if old is not None:
                        new_list.append(old)
                    container[key_hint] = new_list
                    container = new_list
                else:
                    i += 1
                    continue

            item_text = stripped[2:].strip()

            # Check if this is a nested mapping item
            if (": " in item_text or item_text.endswith(":")) and not (item_text.startswith('"') or item_text.startswith("'")):
                # Could be a nested object inside a list
                # Parse as a dict inline
                sub_key, _, sub_val = item_text.partition(": ")
                sub_key = _clean_key(sub_key)
                sub_dict: Dict[str, Any] = {}
                if sub_val:
                    sub_dict[sub_key] = _parse_scalar(sub_val.strip())
                elif item_text.endswith(":"):
                    # Nested mapping whose value is on subsequent lines
                    i += 1
                    while i < n:
                        next_raw = lines[i]
                        if next_raw.strip() == "":
                            i += 1
                            continue
                        next_indent = len(next_raw) - len(next_raw.lstrip())
                        if next_indent <= current_indent:
                            break
                        next_stripped = next_raw.strip()
                        if not next_stripped.startswith("- ") and (": " in next_stripped or next_stripped.endswith(":")):
                            sk, _, sv = next_stripped.partition(": ")
                            sk = _clean_key(sk)
                            sub_dict[sk] = _parse_scalar(sv.strip()) if sv.strip() else ""
                            i += 1
                        else:
                            break
                # Check subsequent indented lines
                i += 1
                while i < n:
                    next_raw = lines[i]
                    if next_raw.strip() == "":
                        i += 1
                        continue
                    next_indent = len(next_raw) - len(next_raw.lstrip())
                    if next_indent <= current_indent:
                        break
                    next_stripped = next_raw.strip()
                    if (": " in next_stripped or next_stripped.endswith(":")) and not next_stripped.startswith("- "):
                        sk, _, sv = next_stripped.partition(": ")
                        sk = _clean_key(sk)
                        sub_dict[sk] = _parse_scalar(sv.strip()) if sv.strip() else ""
                        i += 1
                    else:
                        break
                container.append(sub_dict)
            else:
                # Simple scalar list item
                container.append(_parse_scalar(item_text))
                i += 1

            continue

        # Key-value pair
        if ": " in stripped or (stripped.endswith(":") and not stripped.startswith("-")):
            if not isinstance(container, dict):
                i += 1
                continue

            key, _, value = stripped.partition(": ")
            key = _clean_key(key)
            value = value.strip()

            if value == "":
                # Value is on subsequent indented lines (list or nested mapping)
                # Peek ahead to decide
                i += 1
                if i < n:
                    next_raw = lines[i]
                    if next_raw.strip() == "":
                        i += 1
                        if i < n:
                            next_raw = lines[i]

                if i < n:
                    next_indent = len(lines[i]) - len(lines[i].lstrip())
                    if next_indent > current_indent:
                        # Could be a list or a nested mapping
                        # Peek at the first non-blank child line
                        first_child = lines[i].strip()
                        if first_child.startswith("- "):
                            # It's a list
                            new_list: List[Any] = []
                            container[key] = new_list
                            i = _parse_block(lines, i, next_indent, new_list, key)
                        elif ": " in first_child and not first_child.startswith("-"):
                            # It's a nested mapping
                            new_dict: Dict[str, Any] = {}
                            container[key] = new_dict
                            i = _parse_block(lines, i, next_indent, new_dict, key)
                        else:
                            # Empty value
                            container[key] = None
                    else:
                        container[key] = None
                else:
                    container[key] = None
            else:
                container[key] = _parse_scalar(value)
                i += 1
            continue

        # Unrecognized line — skip
        i += 1

    return i


def _clean_key(key: str) -> str:
    """Remove a trailing colon from a YAML key (e.g., 'key:' -> 'key')."""
    key = key.strip()
    if key.endswith(":"):
        key = key[:-1].rstrip()
    return key


def _parse_scalar(value: str) -> Any:
    """Parse a YAML scalar value into a Python object."""
    if not value:
        return ""

    # Quoted strings
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]

    # Booleans
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False

    # Null
    if value.lower() in ("null", "~", ""):
        return None

    # Inline empty collections
    if value == "[]":
        return []
    if value == "{}":
        return {}

    # Inline non-empty lists like [a, b]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item.strip()) for item in inner.split(",")]

    # Integer
    try:
        return int(value)
    except ValueError:
        pass

    # Float
    try:
        return float(value)
    except ValueError:
        pass

    # Plain string
    return value


# ---------------------------------------------------------------------------
# Skill metadata
# ---------------------------------------------------------------------------

REQUIRED_METADATA_FIELDS = [
    "name",
    "identifier",
    "category",
    "description",
    "difficulty",
    "applicable_challenge_types",
    "trigger_keywords",
    "required_tools",
    "optional_tools",
    "prerequisites",
    "investigation_steps",
    "evidence_requirements",
    "success_criteria",
    "stopping_conditions",
    "safety_notes",
    "common_mistakes",
    "version",
]

SUPPORTED_CATEGORIES = {"web", "binary", "common"}
SUPPORTED_DIFFICULTIES = {"easy", "medium", "hard", "all"}


@dataclass
class SkillMetadata:
    """Structured metadata for a single skill."""

    name: str = ""
    identifier: str = ""
    category: str = ""
    description: str = ""
    difficulty: str = "all"
    applicable_challenge_types: List[str] = field(default_factory=list)
    trigger_keywords: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    optional_tools: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    investigation_steps: List[Dict[str, str]] = field(default_factory=list)
    evidence_requirements: List[Dict[str, str]] = field(default_factory=list)
    success_criteria: List[Dict[str, str]] = field(default_factory=list)
    stopping_conditions: List[Dict[str, str]] = field(default_factory=list)
    safety_notes: List[Dict[str, str]] = field(default_factory=list)
    common_mistakes: List[Dict[str, str]] = field(default_factory=list)
    version: str = "1.0.0"
    source_file: str = ""

    def validate(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors = []
        if not self.name:
            errors.append("Missing required field: name")
        if not self.identifier:
            errors.append("Missing required field: identifier")
        if not self.category:
            errors.append("Missing required field: category")
        elif self.category not in SUPPORTED_CATEGORIES:
            errors.append(
                f"Unsupported category: '{self.category}'. "
                f"Must be one of: {', '.join(sorted(SUPPORTED_CATEGORIES))}"
            )
        if not self.description:
            errors.append("Missing required field: description")
        if not self.difficulty:
            errors.append("Missing required field: difficulty")
        elif self.difficulty not in SUPPORTED_DIFFICULTIES:
            errors.append(
                f"Unsupported difficulty: '{self.difficulty}'. "
                f"Must be one of: {', '.join(sorted(SUPPORTED_DIFFICULTIES))}"
            )
        if not self.applicable_challenge_types:
            errors.append("Missing required field: applicable_challenge_types")
        if not self.trigger_keywords:
            errors.append("Missing required field: trigger_keywords")
        if not self.version:
            errors.append("Missing required field: version")
        return errors


@dataclass
class SkillContent:
    """A loaded skill with its metadata and body."""

    metadata: SkillMetadata
    body: str = ""


# ---------------------------------------------------------------------------
# Public loader
# ---------------------------------------------------------------------------

def load_skill(file_path: Path) -> Tuple[Optional[SkillContent], Optional[str]]:
    """Load a single skill file.

    Returns (SkillContent, None) on success or (None, error_message) on failure.
    """
    try:
        text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            text = file_path.read_text(encoding="latin-1")
        except OSError as e:
            return None, f"Encoding error reading {file_path.name}: {e}"
    except OSError as e:
        return None, f"Cannot read {file_path.name}: {e}"

    fm = parse_front_matter(text)
    if fm is None:
        return None, f"No valid YAML front matter in {file_path.name}"

    # Convert lists of single-key dicts to proper lists for list fields
    metadata = SkillMetadata(source_file=str(file_path))
    for field_name in REQUIRED_METADATA_FIELDS:
        value = fm.get(field_name)
        if isinstance(value, list):
            setattr(metadata, field_name, value)
        elif value is not None:
            setattr(metadata, field_name, value)

    # Extract body (everything after the closing ---)
    parts = text.split("---", 2)
    body = parts[2].strip() if len(parts) >= 3 else ""

    # Validate
    validation_errors = metadata.validate()
    if validation_errors:
        return None, f"Validation errors in {file_path.name}: {'; '.join(validation_errors)}"

    return SkillContent(metadata=metadata, body=body), None


def discover_skill_files(skill_dir: str) -> List[Path]:
    """Recursively find all .md skill files under *skill_dir*.

    Ignores hidden files and directories.
    """
    root = Path(skill_dir)
    if not root.is_dir():
        return []

    results: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip hidden directories
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            if fname.startswith("."):
                continue
            if not fname.endswith(".md"):
                continue
            # Skip documentation/index files that are not skill definitions.
            if fname.upper() in ("README.MD", "INDEX.MD", "SKILLS.MD"):
                continue
            results.append(Path(dirpath) / fname)
    return sorted(results)
