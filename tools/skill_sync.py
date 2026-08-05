"""Skill synchronization — clone/update skill skills from a GitHub repository.

Uses the `git` subprocess with a list-based command (never ``shell=True``).
Downloaded skills are treated as untrusted data: they are validated by the
normal skill loader and can never override system safety rules.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple


def _git_available() -> bool:
    """Return True if the git executable is available."""
    return shutil.which("git") is not None


def sync_skills_from_repo(
    repository_url: str,
    branch: str = "main",
    sync_dir: str = "skills/downloaded",
    timeout_seconds: int = 120,
) -> Tuple[bool, str]:
    """Clone or update a skill repository into *sync_dir*.

    Returns (success, message). On failure, the sync directory is left
    untouched unless a full clone completes. Existing downloaded skills
    are preserved when possible.
    """
    if not repository_url:
        return False, "No skill repository URL configured (SKILLS_REPOSITORY_URL)."

    if not _git_available():
        return False, "git is not available on this system; cannot sync skills."

    sync_path = Path(sync_dir)
    git_dir = sync_path / ".git"

    try:
        if sync_path.exists() and git_dir.exists():
            # Existing clone: fetch + reset to the target branch.
            result = subprocess.run(
                ["git", "fetch", "origin", branch],
                cwd=str(sync_path),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            if result.returncode != 0:
                return False, (
                    f"git fetch failed: {result.stderr.strip() or result.stdout.strip()}"
                )
            result = subprocess.run(
                ["git", "reset", "--hard", f"origin/{branch}"],
                cwd=str(sync_path),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            if result.returncode != 0:
                return False, (
                    f"git reset failed: {result.stderr.strip() or result.stdout.strip()}"
                )
            return True, f"Updated skills from {repository_url} (branch {branch})."

        # Fresh clone into a temporary directory, then move into place.
        parent = sync_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        tmp_dir = parent / (sync_path.name + ".tmp")
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)

        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repository_url, str(tmp_dir)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if result.returncode != 0:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)
            return False, (
                f"git clone failed: {result.stderr.strip() or result.stdout.strip()}"
            )

        # Atomically replace the sync directory.
        if sync_path.exists():
            backup = parent / (sync_path.name + ".old")
            if backup.exists():
                shutil.rmtree(backup, ignore_errors=True)
            sync_path.rename(backup)
        tmp_dir.rename(sync_path)
        if (parent / (sync_path.name + ".old")).exists():
            shutil.rmtree(parent / (sync_path.name + ".old"), ignore_errors=True)

        return True, f"Cloned skills from {repository_url} (branch {branch})."

    except subprocess.TimeoutExpired:
        return False, f"Skill sync timed out after {timeout_seconds}s."
    except Exception as e:  # pragma: no cover - defensive
        return False, f"Skill sync error: {e}"
