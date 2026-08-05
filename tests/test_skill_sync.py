"""Stage 4 tests: skill synchronization via git subprocess."""

import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tools.skill_sync import _git_available, sync_skills_from_repo


class TestSync:
    def test_no_repo_url_returns_failure(self):
        ok, msg = sync_skills_from_repo("", "main", "/tmp/out")
        assert ok is False
        assert "No skill repository URL" in msg

    def test_git_unavailable_returns_failure(self):
        with mock.patch("tools.skill_sync._git_available", return_value=False):
            ok, msg = sync_skills_from_repo("https://example.com/repo.git")
            assert ok is False
            assert "git is not available" in msg

    def test_fresh_clone_updates_sync_dir(self, tmp_path):
        sync_dir = tmp_path / "downloaded"
        completed = mock.Mock()
        completed.returncode = 0
        completed.stdout = ""
        completed.stderr = ""

        def fake_clone(cmd, **kwargs):
            # Simulate git clone creating the target directory
            if "clone" in cmd:
                dest = cmd[-1]
                Path(dest).mkdir(parents=True, exist_ok=True)
            return completed

        with mock.patch("tools.skill_sync._git_available", return_value=True), \
             mock.patch("tools.skill_sync.subprocess.run", side_effect=fake_clone) as mock_run:
            ok, msg = sync_skills_from_repo(
                "https://example.com/repo.git", branch="main", sync_dir=str(sync_dir)
            )
            assert ok is True
            assert "Cloned" in msg
            # Verify the git clone command is list-based (no shell=True)
            call = mock_run.call_args
            args, kwargs = call
            assert isinstance(args[0], list)
            assert "clone" in args[0]
            assert args[0][0] == "git"
            assert kwargs.get("shell", False) is False

    def test_existing_clone_updates(self, tmp_path):
        sync_dir = tmp_path / "downloaded"
        sync_dir.mkdir()
        (sync_dir / ".git").mkdir()
        completed = mock.Mock()
        completed.returncode = 0
        completed.stdout = ""
        completed.stderr = ""

        with mock.patch("tools.skill_sync._git_available", return_value=True), \
             mock.patch("tools.skill_sync.subprocess.run", return_value=completed) as mock_run:
            ok, msg = sync_skills_from_repo(
                "https://example.com/repo.git", branch="dev", sync_dir=str(sync_dir)
            )
            assert ok is True
            assert "Updated" in msg
            calls = mock_run.call_args_list
            assert len(calls) == 2
            assert calls[0].args[0][1] == "fetch"
            assert calls[1].args[0][1] == "reset"

    def test_clone_failure_returns_error(self, tmp_path):
        sync_dir = tmp_path / "downloaded"
        completed = mock.Mock()
        completed.returncode = 1
        completed.stdout = ""
        completed.stderr = "boom"

        with mock.patch("tools.skill_sync._git_available", return_value=True), \
             mock.patch("tools.skill_sync.subprocess.run", return_value=completed):
            ok, msg = sync_skills_from_repo(
                "https://example.com/repo.git", sync_dir=str(sync_dir)
            )
            assert ok is False
            assert "git clone failed" in msg

    def test_fetch_failure_returns_error(self, tmp_path):
        sync_dir = tmp_path / "downloaded"
        sync_dir.mkdir()
        (sync_dir / ".git").mkdir()

        def side_effect(cmd, **kwargs):
            r = mock.Mock()
            r.returncode = 1
            r.stderr = "fetch refused"
            return r

        with mock.patch("tools.skill_sync._git_available", return_value=True), \
             mock.patch("tools.skill_sync.subprocess.run", side_effect=side_effect):
            ok, msg = sync_skills_from_repo(
                "https://example.com/repo.git", sync_dir=str(sync_dir)
            )
            assert ok is False
            assert "git fetch failed" in msg

    def test_timeout_returns_error(self, tmp_path):
        sync_dir = tmp_path / "downloaded"

        with mock.patch("tools.skill_sync._git_available", return_value=True), \
             mock.patch("tools.skill_sync.subprocess.run",
                        side_effect=__import__("subprocess").TimeoutExpired("git", 30)):
            ok, msg = sync_skills_from_repo(
                "https://example.com/repo.git", sync_dir=str(sync_dir)
            )
            assert ok is False
            assert "timed out" in msg

    def test_no_shell_true_in_any_command(self, tmp_path):
        """Every git invocation must use a list argv, never shell=True."""
        sync_dir = tmp_path / "downloaded"
        completed = mock.Mock()
        completed.returncode = 0
        completed.stdout = ""
        completed.stderr = ""

        def fake_run(cmd, **kwargs):
            assert isinstance(cmd, (list, tuple)), "argv must be a list, not a string"
            assert kwargs.get("shell", False) is False
            if "clone" in cmd:
                Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return completed

        with mock.patch("tools.skill_sync._git_available", return_value=True), \
             mock.patch("tools.skill_sync.subprocess.run", side_effect=fake_run):
            ok, _ = sync_skills_from_repo(
                "https://example.com/repo.git", sync_dir=str(sync_dir)
            )
            assert ok is True

    def test_git_available_reflects_system(self):
        # Just ensure it returns a bool without raising.
        assert isinstance(_git_available(), bool)