"""Skill registry — loads, validates, deduplicates, and stores skills."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .skill_loader import (
    SkillContent,
    SkillMetadata,
    discover_skill_files,
    load_skill,
    REQUIRED_METADATA_FIELDS,
    SUPPORTED_CATEGORIES,
)


@dataclass
class SkillLoadResult:
    """Result of loading skills from a directory."""

    skills: Dict[str, SkillContent] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    loaded_count: int = 0
    invalid_count: int = 0
    skipped_count: int = 0


class SkillRegistry:
    """Registry that loads skills from a directory and manages them."""

    def __init__(self, skill_dir: str = "skills"):
        self._skill_dir = skill_dir
        self._skills: Dict[str, SkillContent] = {}
        self._load_errors: List[str] = []

    @property
    def skill_dir(self) -> str:
        return self._skill_dir

    @property
    def skills(self) -> Dict[str, SkillContent]:
        """Return a copy of the loaded skills."""
        return dict(self._skills)

    @property
    def errors(self) -> List[str]:
        """Return loading errors."""
        return list(self._load_errors)

    def load_all(self) -> SkillLoadResult:
        """Recursively load all skills from the configured directory.

        Returns a SkillLoadResult with counts and any errors.
        """
        result = SkillLoadResult()
        self._skills.clear()
        self._load_errors.clear()

        if not os.path.isdir(self._skill_dir):
            result.skipped_count = 0
            return result

        skill_files = discover_skill_files(self._skill_dir)

        for filepath in skill_files:
            content, error = load_skill(filepath)
            if error:
                result.invalid_count += 1
                self._load_errors.append(error)
                continue

            if content is None:
                result.invalid_count += 1
                continue

            identifier = content.metadata.identifier

            # Duplicate detection
            if identifier in self._skills:
                result.invalid_count += 1
                self._load_errors.append(
                    f"Duplicate skill identifier '{identifier}' "
                    f"(from {filepath} and {self._skills[identifier].metadata.source_file})"
                )
                continue

            # Category validation
            if content.metadata.category not in SUPPORTED_CATEGORIES:
                result.invalid_count += 1
                self._load_errors.append(
                    f"Unsupported category '{content.metadata.category}' "
                    f"in {filepath.name}"
                )
                continue

            self._skills[identifier] = content
            result.loaded_count += 1

        return result

    def get_skill(self, identifier: str) -> Optional[SkillContent]:
        """Retrieve a skill by its identifier."""
        return self._skills.get(identifier)

    def list_skills(self) -> List[SkillMetadata]:
        """Return metadata for all loaded skills."""
        return [sc.metadata for sc in self._skills.values()]

    def list_skills_by_category(self, category: str) -> List[SkillMetadata]:
        """Return metadata for skills in a given category."""
        return [
            sc.metadata
            for sc in self._skills.values()
            if sc.metadata.category == category
        ]

    def get_definitions(self) -> List[Dict]:
        """Return simplified definitions for all loaded skills."""
        defs = []
        for sc in self._skills.values():
            m = sc.metadata
            defs.append(
                {
                    "identifier": m.identifier,
                    "name": m.name,
                    "category": m.category,
                    "description": m.description,
                    "difficulty": m.difficulty,
                    "trigger_keywords": m.trigger_keywords,
                    "required_tools": m.required_tools,
                    "optional_tools": m.optional_tools,
                }
            )
        return defs

    def startup_summary(self) -> str:
        """Return a human-readable startup summary."""
        by_cat: Dict[str, int] = {}
        for sc in self._skills.values():
            cat = sc.metadata.category
            by_cat[cat] = by_cat.get(cat, 0) + 1

        lines = [f"Skills loaded: {len(self._skills)}"]
        for cat in sorted(by_cat):
            lines.append(f"{cat.capitalize()}: {by_cat[cat]}")
        if self._load_errors:
            lines.append(f"Invalid: {len(self._load_errors)}")
        else:
            lines.append("Invalid: 0")
        return "\n".join(lines)
