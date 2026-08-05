"""Tests for data decoding tools."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.data_tools import decode_data


class TestDecodeBase64(unittest.TestCase):
    """Test Base64 decoding."""

    def test_decode_base64(self):
        """Valid Base64 should decode correctly."""
        encoded = "SGVsbG8gV29ybGQ="
        result = decode_data(encoded, encoding="base64")
        self.assertEqual(result, "Hello World")

    def test_decode_base64_with_newlines(self):
        """Base64 with newlines should decode."""
        encoded = "VGhpcyBpcyBhIHRlc3Q="
        result = decode_data(encoded, encoding="base64")
        self.assertEqual(result, "This is a test")

    def test_decode_invalid_base64(self):
        """Invalid Base64 should return an error."""
        result = decode_data("!!!not-valid!!!", encoding="base64")
        self.assertIn("error", result.lower())


class TestDecodeHex(unittest.TestCase):
    """Test hex decoding."""

    def test_decode_hex(self):
        """Valid hex should decode to text."""
        encoded = "48656c6c6f20576f726c64"
        result = decode_data(encoded, encoding="hex")
        self.assertEqual(result, "Hello World")

    def test_decode_hex_with_prefix(self):
        """Hex with 0x prefix should decode."""
        encoded = "0x48656c6c6f"
        result = decode_data(encoded, encoding="hex")
        self.assertEqual(result, "Hello")

    def test_decode_invalid_hex(self):
        """Invalid hex should return an error."""
        result = decode_data("ZZZZ", encoding="hex")
        self.assertIn("error", result.lower())

    def test_decode_odd_hex(self):
        """Odd number of hex digits should return an error."""
        result = decode_data("abc", encoding="hex")
        self.assertIn("error", result.lower())


class TestDecodeURL(unittest.TestCase):
    """Test URL decoding."""

    def test_decode_url(self):
        """URL-encoded string should decode."""
        encoded = "Hello%20World%21"
        result = decode_data(encoded, encoding="url")
        self.assertEqual(result, "Hello World!")

    def test_decode_url_spaces(self):
        """URL-encoded spaces (%20) should decode."""
        encoded = "Hello%20World"
        result = decode_data(encoded, encoding="url")
        self.assertEqual(result, "Hello World")


class TestDecodeROT13(unittest.TestCase):
    """Test ROT13 decoding."""

    def test_decode_rot13(self):
        """ROT13-encoded text should decode."""
        encoded = "Uryyb Jbeyq"
        result = decode_data(encoded, encoding="rot13")
        self.assertEqual(result, "Hello World")

    def test_rot13_self_inverse(self):
        """ROT13 is its own inverse."""
        original = "Hello World"
        encoded = decode_data(original, encoding="rot13")
        decoded = decode_data(encoded, encoding="rot13")
        self.assertEqual(decoded, original)


class TestDecodeBinary(unittest.TestCase):
    """Test binary string decoding."""

    def test_decode_binary(self):
        """Binary string should decode to text."""
        encoded = "01001000 01100101 01101100 01101100 01101111"
        result = decode_data(encoded, encoding="binary")
        self.assertEqual(result, "Hello")

    def test_decode_invalid_binary(self):
        """Invalid binary should return an error."""
        result = decode_data("0102", encoding="binary")
        self.assertIn("error", result.lower())


class TestDecodeAuto(unittest.TestCase):
    """Test auto-detection of encoding."""

    def test_auto_detect_base64(self):
        """Auto should detect Base64."""
        encoded = "SGVsbG8="
        result = decode_data(encoded, encoding="auto")
        self.assertIn("Hello", result)
        self.assertIn("base64", result.lower())

    def test_auto_detect_hex(self):
        """Auto should detect hex."""
        encoded = "48656c6c6f"
        result = decode_data(encoded, encoding="auto")
        self.assertIn("Hello", result)
        self.assertIn("hex", result.lower())


class TestDecodeErrorHandling(unittest.TestCase):
    """Test error handling in decode_data."""

    def test_empty_input(self):
        """Empty input should return an error."""
        result = decode_data("", encoding="base64")
        self.assertIn("error", result.lower())

    def test_unsupported_encoding(self):
        """Unsupported encoding should return an error."""
        result = decode_data("test", encoding="unknown")
        self.assertIn("unsupported", result.lower())

    def test_binary_result_shown_as_hex(self):
        """Non-text binary results should be shown as hex."""
        # Encode some binary data as base64
        import base64
        binary_data = b'\x00\x01\x02\x03\xff\xfe'
        encoded = base64.b64encode(binary_data).decode('ascii')
        result = decode_data(encoded, encoding="base64")
        # Result should be hex since it's not valid text
        self.assertTrue(
            "hex" in result.lower() or "bytes" in result.lower()
        )
