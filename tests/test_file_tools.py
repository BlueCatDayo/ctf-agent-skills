"""Tests for file analysis tools."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.file_tools import (
    calculate_file_hash,
    inspect_file,
    list_files,
    read_text_file,
    search_files,
)


class TestListFiles(unittest.TestCase):
    """Test list_files tool."""

    def test_list_root(self):
        """Listing workspace root should return files."""
        result = list_files(path="")
        self.assertIn("message.txt", result)

    def test_list_subdir(self):
        """Listing a subdirectory should work."""
        result = list_files(path="test")
        self.assertIn("message.txt", result)

    def test_list_nonexistent(self):
        """Listing a non-existent path should return an error."""
        result = list_files(path="nonexistent_xyz")
        self.assertIn("not found", result.lower())

    def test_list_skips_hidden(self):
        """Hidden files should be skipped."""
        result = list_files(path="")
        self.assertNotIn(".git", result)
        self.assertNotIn(".venv", result)

    def test_list_skips_pycache(self):
        """__pycache__ should be skipped."""
        result = list_files(path="")
        self.assertNotIn("__pycache__", result)


class TestReadTextFile(unittest.TestCase):
    """Test read_text_file tool."""

    def test_read_text_file(self):
        """Reading a text file should return its contents."""
        result = read_text_file(path="test/message.txt")
        self.assertIn("flag{stage2_test_only}", result)

    def test_read_nonexistent(self):
        """Reading a non-existent file should return an error."""
        result = read_text_file(path="nonexistent.txt")
        self.assertIn("not found", result.lower())

    def test_read_binary_detected(self):
        """Reading a binary file should detect it."""
        result = read_text_file(path="test/sample.bin")
        self.assertIn("binary", result.lower())

    def test_read_nonexistent_path_traversal(self):
        """Path traversal should be blocked."""
        result = read_text_file(path="../.env")
        self.assertIn("security", result.lower())


class TestInspectFile(unittest.TestCase):
    """Test inspect_file tool."""

    def test_inspect_text_file(self):
        """Inspecting a text file should return metadata."""
        result = inspect_file(path="test/message.txt")
        self.assertIn("Filename:", result)
        self.assertIn("SHA-256:", result)
        self.assertIn("Text file: Yes", result)

    def test_inspect_binary_file(self):
        """Inspecting a binary file should return metadata."""
        result = inspect_file(path="test/sample.bin")
        self.assertIn("Filename:", result)
        self.assertIn("SHA-256:", result)
        self.assertIn("Text file: No", result)

    def test_inspect_nonexistent(self):
        """Inspecting a non-existent file should return an error."""
        result = inspect_file(path="nonexistent.xyz")
        self.assertIn("not found", result.lower())


class TestSearchFiles(unittest.TestCase):
    """Test search_files tool."""

    def test_search_plain_text(self):
        """Searching for plain text should find matches."""
        result = search_files(pattern="flag{stage2_test_only}")
        self.assertIn("message.txt", result)

    def test_search_no_match(self):
        """Searching for non-existent text should return no matches."""
        result = search_files(pattern="nonexistent_flag_xyz")
        self.assertIn("no matches", result.lower())

    def test_search_regex(self):
        """Searching with regex should work."""
        result = search_files(pattern=r"flag\{.*\}", use_regex=True)
        self.assertIn("message.txt", result)

    def test_search_invalid_regex(self):
        """Invalid regex should return a clear error."""
        result = search_files(pattern="[invalid", use_regex=True)
        self.assertIn("invalid", result.lower())

    def test_search_in_subdir(self):
        """Searching within a subdirectory should work."""
        result = search_files(pattern="test", path="test")
        self.assertIn("message.txt", result)


class TestCalculateFileHash(unittest.TestCase):
    """Test calculate_file_hash tool."""

    def test_sha256_text_file(self):
        """SHA-256 hash of a text file should be a valid hex string."""
        result = calculate_file_hash(path="test/message.txt", algorithm="sha256")
        self.assertIn("SHA-256", result)
        # Extract hash and verify it's valid hex
        hash_part = result.split(": ")[-1].strip()
        self.assertEqual(len(hash_part), 64)
        int(hash_part, 16)  # Should not raise

    def test_md5_text_file(self):
        """MD5 hash should be a valid hex string."""
        result = calculate_file_hash(path="test/message.txt", algorithm="md5")
        self.assertIn("MD5", result)
        hash_part = result.split(": ")[-1].strip()
        self.assertEqual(len(hash_part), 32)

    def test_sha1_text_file(self):
        """SHA-1 hash should be a valid hex string."""
        result = calculate_file_hash(path="test/message.txt", algorithm="sha1")
        self.assertIn("SHA-1", result)
        hash_part = result.split(": ")[-1].strip()
        self.assertEqual(len(hash_part), 40)

    def test_sha512_text_file(self):
        """SHA-512 hash should be a valid hex string."""
        result = calculate_file_hash(path="test/message.txt", algorithm="sha512")
        self.assertIn("SHA-512", result)
        hash_part = result.split(": ")[-1].strip()
        self.assertEqual(len(hash_part), 128)

    def test_unsupported_algorithm(self):
        """Unsupported algorithm should return an error."""
        result = calculate_file_hash(path="test/message.txt", algorithm="crc32")
        self.assertIn("unsupported", result.lower())

    def test_hash_nonexistent(self):
        """Hashing a non-existent file should return an error."""
        result = calculate_file_hash(path="nonexistent.txt", algorithm="sha256")
        self.assertIn("not found", result.lower())
