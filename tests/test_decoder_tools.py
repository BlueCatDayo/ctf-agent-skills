"""Tests for Stage 5 decoder tools (extended encodings).

The original data_tools.decode_data is left untouched for backward
compatibility; decoder_tools.decode_data extends it with octal, decimal,
ASCII, UTF-8, JWT, Gzip, and Zlib support.
"""

import base64
import gzip
import json
import os
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.decoder_tools import (
    SUPPORTED_ENCODINGS,
    decode_data,
    decode_jwt,
    parse_jwt,
)


class TestSupportedEncodings(unittest.TestCase):
    def test_original_encodings_present(self):
        for enc in ("base64", "hex", "url", "rot13", "binary", "auto"):
            self.assertIn(enc, SUPPORTED_ENCODINGS)

    def test_new_encodings_present(self):
        for enc in ("octal", "decimal", "ascii", "utf8", "jwt", "gzip", "zlib"):
            self.assertIn(enc, SUPPORTED_ENCODINGS)


class TestExtendedDecoders(unittest.TestCase):
    def test_octal(self):
        self.assertIn("Hello", decode_data("110 145 154 154 157", "octal"))

    def test_octal_invalid_char(self):
        out = decode_data("110 8x5", "octal")
        self.assertIn("Error", out)

    def test_decimal(self):
        out = decode_data("72 101 108 108 111", "decimal")
        self.assertIn("Hello", out)

    def test_decimal_out_of_range(self):
        out = decode_data("72 99999", "decimal")
        self.assertIn("Error", out)

    def test_ascii_codes(self):
        out = decode_data("72 101 108 108 111", "ascii")
        self.assertIn("Hello", out)

    def test_ascii_literal_fallback(self):
        out = decode_data("Hello", "ascii")
        self.assertIn("ASCII codes", out)

    def test_utf8_hex_bytes(self):
        out = decode_data("48 65 6c 6c 6f", "utf8")
        self.assertIn("Hello", out)

    def test_utf8_invalid_bytes(self):
        out = decode_data("ff fe 00 41", "utf8")
        self.assertIn("Error", out)

    def test_jwt_decode(self):
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"user": "admin", "role": "admin"}).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}.signature"
        out = decode_jwt(token)
        self.assertIn("alg", out)
        self.assertIn("HS256", out)
        self.assertIn("admin", out)
        self.assertIn("NOT verified", out)

    def test_jwt_invalid(self):
        out = decode_jwt("not-a-jwt")
        self.assertIn("Error", out)

    def test_jwt_via_decode_data(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"flag": "fake"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}."
        out = decode_data(token, "jwt")
        self.assertIn("fake", out)

    def test_parse_jwt_claims(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "user1", "exp": 2147483647, "role": "admin"}).encode()
        ).rstrip(b"=").decode()
        out = parse_jwt(f"{header}.{payload}.sig")
        self.assertIn("HS256", out)
        self.assertIn("sub", out)
        self.assertIn("exp", out)

    def test_parse_jwt_none_algorithm_note(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"user": "admin"}).encode()).rstrip(b"=").decode()
        out = parse_jwt(f"{header}.{payload}.")
        self.assertIn("none", out.lower())

    def test_gzip_raw_base64(self):
        compressed = base64.b64encode(gzip.compress(b"secret payload")).decode()
        out = decode_data(compressed, "gzip")
        self.assertIn("secret payload", out)

    def test_gzip_invalid(self):
        out = decode_data("not a gzip stream at all", "gzip")
        self.assertIn("Error", out)

    def test_zlib_raw_base64(self):
        compressed = base64.b64encode(zlib.compress(b"zlib content")).decode()
        out = decode_data(compressed, "zlib")
        self.assertIn("zlib content", out)

    def test_zlib_invalid(self):
        out = decode_data("this is not zlib data", "zlib")
        self.assertIn("Error", out)


class TestAutoDetection(unittest.TestCase):
    def test_auto_base64(self):
        out = decode_data("SGVsbG8gV29ybGQ=", "auto")
        self.assertIn("Hello World", out)

    def test_auto_hex(self):
        out = decode_data("48656c6c6f", "auto")
        self.assertIn("Hello", out)

    def test_auto_octal(self):
        out = decode_data("110 145 154 154 157", "auto")
        self.assertIn("Hello", out)

    def test_auto_decimal(self):
        out = decode_data("72 101 108 108 111", "auto")
        self.assertIn("Hello", out)

    def test_auto_rot13(self):
        out = decode_data("Uryyb Jbeyq", "auto")
        self.assertIn("Hello World", out)


class TestEdgeCases(unittest.TestCase):
    def test_empty_input(self):
        out = decode_data("", "base64")
        self.assertIn("Error", out)

    def test_unknown_encoding(self):
        out = decode_data("abc", "nonexistent")
        self.assertIn("Error", out)
        self.assertIn("nonexistent", out)

    def test_invalid_base64(self):
        out = decode_data("!!!notbase64!!!", "base64")
        self.assertIn("Error", out)

    def test_hex_odd_length(self):
        out = decode_data("abc", "hex")
        self.assertIn("Error", out)

    def test_binary(self):
        out = decode_data("01001000 01101001", "binary")
        self.assertIn("Hi", out)

    def test_binary_invalid(self):
        out = decode_data("01001x", "binary")
        self.assertIn("Error", out)

    def test_workspace_root_accepted(self):
        # The extended decoder accepts workspace_root for registry compat.
        out = decode_data("SGk=", "base64", workspace_root="/tmp")
        self.assertIn("Hi", out)


if __name__ == "__main__":
    unittest.main()
