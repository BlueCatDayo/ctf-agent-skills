"""Stage 4 tests: skill loader (front matter parsing, validation, discovery)."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tools.skill_loader import (
    SkillMetadata,
    discover_skill_files,
    load_skill,
    parse_front_matter,
)

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def _write(tmpdir: Path, relpath: str, content: str) -> Path:
    """Write a file under a temp skill directory."""
    p = tmpdir / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class TestParseFrontMatter:
    def test_parses_basic_front_matter(self):
        text = "---\nname: Test\ncategory: web\n---\n\nBody here"
        fm = parse_front_matter(text)
        assert fm is not None
        assert fm["name"] == "Test"
        assert fm["category"] == "web"

    def test_returns_none_without_delimiters(self):
        assert parse_front_matter("no front matter") is None

    def test_returns_none_without_closing_delimiter(self):
        assert parse_front_matter("---\nname: Test") is None

    def test_parses_lists(self):
        text = "---\ntags:\n  - one\n  - two\n---\n"
        fm = parse_front_matter(text)
        assert fm["tags"] == ["one", "two"]

    def test_parses_empty_key_with_nested_list(self):
        """Regression: 'key:' followed by an indented list must not keep a colon in the key."""
        text = "---\napplicable_challenge_types:\n  - web\n  - binary\ntrigger_keywords:\n  - sql\n---\n"
        fm = parse_front_matter(text)
        assert "applicable_challenge_types:" not in fm
        assert fm["applicable_challenge_types"] == ["web", "binary"]
        assert fm["trigger_keywords"] == ["sql"]

    def test_parses_nested_mappings(self):
        text = "---\nsteps:\n  - title: First\n    description: Do thing\n  - title: Second\n    description: Do other\n---\n"
        fm = parse_front_matter(text)
        assert fm["steps"] == [
            {"title": "First", "description": "Do thing"},
            {"title": "Second", "description": "Do other"},
        ]

    def test_parses_booleans_and_numbers(self):
        text = "---\nenabled: true\ncount: 5\n---\n"
        fm = parse_front_matter(text)
        assert fm["enabled"] is True
        assert fm["count"] == 5

    def test_strips_comments(self):
        text = "---\nname: Test # inline comment\n---\n"
        fm = parse_front_matter(text)
        assert fm["name"] == "Test"

    def test_parses_quoted_strings(self):
        text = '---\ndescription: "hello world"\n---\n'
        fm = parse_front_matter(text)
        assert fm["description"] == "hello world"


class TestLoadSkill:
    def test_loads_valid_skill(self):
        path = FIXTURES / "valid" / "web" / "test-sql-injection.md"
        content, error = load_skill(path)
        assert error is None
        assert content is not None
        assert content.metadata.identifier == "test-sql-injection"
        assert content.metadata.category == "web"
        assert content.metadata.investigation_steps
        assert isinstance(content.metadata.investigation_steps[0], dict)
        assert content.body.strip()

    def test_rejects_malformed_skill(self, tmp_path):
        p = _write(tmp_path, "bad.md", "---\nname: X\ncategory: web\ndifficulty: medium\nversion: 1\n---\n# x")
        content, error = load_skill(p)
        assert content is None
        assert error is not None
        assert "Validation errors" in error

    def test_rejects_missing_front_matter(self, tmp_path):
        p = _write(tmp_path, "bad.md", "# Just a heading\nNo front matter here.")
        content, error = load_skill(p)
        assert content is None
        assert "front matter" in error

    def test_rejects_missing_file(self, tmp_path):
        content, error = load_skill(tmp_path / "missing.md")
        assert content is None
        assert error is not None

    def test_loads_binary_category_skill(self):
        path = FIXTURES / "valid" / "binary" / "test-buffer-overflow.md"
        content, error = load_skill(path)
        assert error is None
        assert content.metadata.category == "binary"
        assert content.metadata.prerequisites == ["test-static-analysis"]

    def test_loads_common_skill(self):
        path = FIXTURES / "valid" / "common" / "test-common-skill.md"
        content, error = load_skill(path)
        assert error is None
        assert content.metadata.category == "common"

    def test_unsupported_category_rejected(self, tmp_path):
        p = _write(tmp_path, "bad.md", _full_skill(category="network"))
        content, error = load_skill(p)
        assert content is None
        assert "category" in error

    def test_unsupported_difficulty_rejected(self, tmp_path):
        p = _write(tmp_path, "bad.md", _full_skill(difficulty="insane"))
        content, error = load_skill(p)
        assert content is None
        assert "difficulty" in error


class TestDiscoverSkillFiles:
    def test_discovers_all_md_files(self):
        files = discover_skill_files(str(FIXTURES))
        names = [f.name for f in files]
        assert "test-sql-injection.md" in names
        assert "test-buffer-overflow.md" in names
        assert "malformed.md" in names
        assert "no-front-matter.md" in names

    def test_ignores_missing_directory(self, tmp_path):
        assert discover_skill_files(str(tmp_path / "nope")) == []

    def test_ignores_non_md(self, tmp_path):
        _write(tmp_path, "a.txt", "hello")
        _write(tmp_path, "b.md", "# hi")
        files = discover_skill_files(str(tmp_path))
        assert [f.name for f in files] == ["b.md"]

    def test_ignores_hidden_dirs(self, tmp_path):
        _write(tmp_path, ".hidden/s.md", "# hi")
        _write(tmp_path, "visible/s.md", "# hi")
        files = discover_skill_files(str(tmp_path))
        assert len(files) == 1


class TestSkillMetadata:
    def test_validate_ok(self):
        m = SkillMetadata(
            name="X", identifier="x", category="web", description="d",
            difficulty="easy", applicable_challenge_types=["web"],
            trigger_keywords=["x"], version="1.0.0",
        )
        assert m.validate() == []

    def test_validate_missing_name(self):
        m = SkillMetadata(category="web")
        errors = m.validate()
        assert any("name" in e for e in errors)

    def test_validate_missing_identifier(self):
        m = SkillMetadata(name="X", category="web")
        errors = m.validate()
        assert any("identifier" in e for e in errors)


def _full_skill(category="web", difficulty="medium") -> str:
    return f"""---
name: Full
identifier: full-{category}
category: {category}
description: d
difficulty: {difficulty}
applicable_challenge_types:
  - {category}
trigger_keywords:
  - test
required_tools:
  - http_request
optional_tools: []
prerequisites: []
investigation_steps:
  - title: Step
    description: Do it.
evidence_requirements:
  - title: Ev
    description: e
success_criteria:
  - title: Done
    description: d
stopping_conditions:
  - title: Stop
    description: s
safety_notes: []
common_mistakes: []
version: 1.0.0
---

# Full
"""
