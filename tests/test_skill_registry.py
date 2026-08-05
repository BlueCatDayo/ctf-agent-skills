"""Stage 4 tests: skill registry (loading, duplicates, categories, summaries)."""

import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tools.skill_registry import SkillRegistry

FIXTURES = Path(__file__).parent / "fixtures" / "skills"
VALID = FIXTURES / "valid"


class TestSkillRegistry:
    def test_loads_valid_directory(self):
        reg = SkillRegistry(str(VALID))
        result = reg.load_all()
        assert result.loaded_count == 4  # 2 web + 1 binary + 1 common (dup rejected)
        assert result.invalid_count == 1  # duplicate identifier
        assert reg.get_skill("test-sql-injection") is not None

    def test_duplicate_identifier_detected(self):
        reg = SkillRegistry(str(VALID))
        reg.load_all()
        assert any("Duplicate" in e for e in reg.errors)

    def test_empty_directory(self, tmp_path):
        reg = SkillRegistry(str(tmp_path))
        result = reg.load_all()
        assert result.loaded_count == 0

    def test_missing_directory(self):
        reg = SkillRegistry("/nonexistent/path/xyz")
        result = reg.load_all()
        assert result.loaded_count == 0

    def test_list_skills_by_category(self):
        reg = SkillRegistry(str(VALID))
        reg.load_all()
        web = reg.list_skills_by_category("web")
        binary = reg.list_skills_by_category("binary")
        common = reg.list_skills_by_category("common")
        assert len(web) == 2  # test-sql-injection + malicious-instructions
        assert len(binary) == 1
        assert len(common) == 1

    def test_get_definitions(self):
        reg = SkillRegistry(str(VALID))
        reg.load_all()
        defs = reg.get_definitions()
        identifiers = {d["identifier"] for d in defs}
        assert "test-sql-injection" in identifiers
        d = next(d for d in defs if d["identifier"] == "test-sql-injection")
        assert d["category"] == "web"
        assert "http_request" in d["required_tools"]

    def test_startup_summary(self):
        reg = SkillRegistry(str(VALID))
        reg.load_all()
        summary = reg.startup_summary()
        assert "Skills loaded: 4" in summary
        assert "Web: 2" in summary
        assert "Binary: 1" in summary

    def test_errors_are_listed(self):
        reg = SkillRegistry(str(VALID))
        reg.load_all()
        assert len(reg.errors) >= 1

    def test_load_real_skill_library(self):
        """Load the project's actual skill directory to catch real regressions."""
        project_root = Path(__file__).parent.parent
        skill_dir = project_root / "skills"
        if not skill_dir.exists():
            pytest.skip("skills directory not present")
        reg = SkillRegistry(str(skill_dir))
        result = reg.load_all()
        assert result.loaded_count >= 30
        assert result.invalid_count == 0
