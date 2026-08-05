"""Tests for workspace path security."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.workspace import (
    PathTraversalError,
    WorkspaceError,
    WorkspaceNotConfiguredError,
    get_workspace_root,
    is_path_blocked,
    should_skip_entry,
    validate_within_workspace,
)


class TestGetWorkspaceRoot(unittest.TestCase):
    """Test workspace root resolution."""

    def test_default_workspace_exists(self):
        """Default workspace should resolve to project/challenges."""
        root = get_workspace_root(None)
        self.assertTrue(root.exists())
        self.assertTrue(root.is_dir())
        self.assertEqual(root.name, "challenges")

    def test_custom_workspace(self):
        """Custom workspace path should be resolved."""
        root = get_workspace_root("tests/fixtures")
        self.assertTrue(root.exists())

    def test_nonexistent_workspace_raises(self):
        """Non-existent workspace should raise an error."""
        with self.assertRaises(WorkspaceNotConfiguredError):
            get_workspace_root("nonexistent_dir_xyz")


class TestValidateWithinWorkspace(unittest.TestCase):
    """Test that path validation prevents traversal."""

    def setUp(self):
        self.root = get_workspace_root(None)

    def test_valid_relative_path(self):
        """A valid relative path should resolve correctly."""
        result = validate_within_workspace("test", self.root)
        self.assertTrue(result.exists())

    def test_path_traversal_dotdot(self):
        """.. in path should be rejected."""
        with self.assertRaises(PathTraversalError):
            validate_within_workspace("../.env", self.root)

    def test_path_traversal_in_nested(self):
        """.. in a nested path should be rejected."""
        with self.assertRaises(PathTraversalError):
            validate_within_workspace("test/../../.env", self.root)

    def test_absolute_path_outside_workspace(self):
        """Absolute path outside workspace should be rejected."""
        with self.assertRaises(PathTraversalError):
            validate_within_workspace("/etc/passwd", self.root)

    def test_empty_path_raises(self):
        """Empty path should raise an error."""
        with self.assertRaises(WorkspaceError):
            validate_within_workspace("", self.root)

    def test_valid_file_path(self):
        """A valid file path should resolve."""
        result = validate_within_workspace("test/message.txt", self.root)
        self.assertTrue(result.exists())
        self.assertTrue(result.is_file())


class TestIsPathBlocked(unittest.TestCase):
    """Test system path blocking."""

    def test_blocked_etc(self):
        """/etc should be blocked."""
        result = is_path_blocked(Path("/etc/passwd"))
        self.assertIsNotNone(result)
        self.assertIn("blocked", result.lower())

    def test_allowed_workspace_path(self):
        """A workspace path should not be blocked."""
        result = is_path_blocked(Path("/home/user/ctf/challenges/test"))
        self.assertIsNone(result)


class TestShouldSkipEntry(unittest.TestCase):
    """Test directory entry filtering."""

    def test_skip_git(self):
        self.assertTrue(should_skip_entry(".git"))

    def test_skip_venv(self):
        self.assertTrue(should_skip_entry(".venv"))

    def test_skip_pycache(self):
        self.assertTrue(should_skip_entry("__pycache__"))

    def test_skip_hidden(self):
        self.assertTrue(should_skip_entry(".hidden"))

    def test_skip_dotfiles(self):
        self.assertTrue(should_skip_entry(".env"))

    def test_keep_normal(self):
        self.assertFalse(should_skip_entry("normal.txt"))

    def test_keep_subdir(self):
        self.assertFalse(should_skip_entry("subdir"))
