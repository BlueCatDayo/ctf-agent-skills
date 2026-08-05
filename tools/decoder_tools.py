"""Stage 5 decoder tools — extended automatic decoders.

Supports Base64, Hex, URL, ROT13, Binary, Octal, Decimal, ASCII, UTF-8,
JWT, Gzip, and Zlib.  All decoding is done locally; no network calls.
"""

import base64
import binascii
import gzip
import json
import re
import zlib
from typing import Any, Dict, Optional

MAX_TOOL_OUTPUT_CHARS = 8192

SUPPORTED_ENCODINGS = [
    "base64",
    "hex",
    "url",
    "rot13",
    "binary",
    "octal",
    "decimal",
    "ascii",
    "utf8",
    "jwt",
    "gzip",
    "zlib",
    "auto",
]


def _truncate(text: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Truncate text to *limit* characters with a notice."""
    if len(text) > limit:
        return text[:limit] + f"\n... [output truncated at {limit} characters]"
    return text


def _is_valid_text(data: bytes) -> bool:
    """Return True if *data* looks like readable text (no NULs, mostly printable)."""
    if not data:
        return False
    if b"\x00" in data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data) > 0.85


def _bytes_to_text(data: bytes) -> str:
    """Render decoded bytes as UTF-8 text when possible, else a hex dump."""
    if _is_valid_text(data):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("latin-1")
            except UnicodeDecodeError:
                return f"Decoded bytes (not valid text):\n{data.hex()}"
    return f"Decoded bytes (not valid text):\n{data.hex()}"


def _decode_base64(data: str) -> str:
    """Decode a Base64-encoded string."""
    try:
        padded = data + "=" * (-len(data) % 4)
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as e:
        return f"Error: Invalid Base64 input - {e}"
    return _bytes_to_text(decoded)


def _decode_hex(data: str) -> str:
    """Decode a hexadecimal string (optional 0x prefix, spaces allowed)."""
    cleaned = data.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = re.sub(r"\s+", "", cleaned)
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        return "Error: Invalid hexadecimal input - contains non-hex characters."
    if len(cleaned) % 2 != 0:
        return "Error: Invalid hexadecimal input - odd number of digits."
    try:
        decoded = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hexadecimal input - {e}"
    return _bytes_to_text(decoded)


def _decode_url(data: str) -> str:
    """Decode a URL-encoded string."""
    from urllib.parse import unquote
    try:
        decoded = unquote(data)
    except Exception as e:
        return f"Error: Invalid URL-encoded input - {e}"
    if decoded == data:
        return "Warning: Input does not appear to be URL-encoded (no percent-encoded sequences found)."
    return decoded


def _decode_rot13(data: str) -> str:
    """Decode a ROT13-encoded string."""
    out = []
    for ch in data:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _decode_binary(data: str) -> str:
    """Decode a binary string (e.g. '01001000 01101001')."""
    tokens = data.strip().split()
    for token in tokens:
        if not re.fullmatch(r"[01]+", token):
            return f"Error: Invalid binary input - '{token}' contains non-binary characters."
    out = bytearray()
    for token in tokens:
        padded = token.zfill(8)
        if len(padded) > 8:
            padded = padded[-8:]
        out.append(int(padded, 2))
    return _bytes_to_text(bytes(out))


def _decode_octal(data: str) -> str:
    """Decode an octal-encoded string (e.g. '110 145 154 154 157')."""
    tokens = re.split(r"[\s,]+", data.strip())
    out = bytearray()
    for token in tokens:
        if not token:
            continue
        if not re.fullmatch(r"[0-7]+", token):
            return f"Error: Invalid octal input - '{token}' contains non-octal characters."
        try:
            out.append(int(token, 8))
        except ValueError:
            return f"Error: Octal value out of range: '{token}'"
    if not out:
        return "Error: No octal tokens found."
    return _bytes_to_text(bytes(out))


def _decode_decimal(data: str) -> str:
    """Decode a decimal-encoded string (e.g. '72 101 108 108 111')."""
    tokens = re.split(r"[\s,]+", data.strip())
    out = bytearray()
    for token in tokens:
        if not token:
            continue
        if not re.fullmatch(r"[0-9]+", token):
            return f"Error: Invalid decimal input - '{token}' is not numeric."
        try:
            val = int(token, 10)
            if val > 255:
                return f"Error: Decimal value out of byte range: {val} (>255)."
            out.append(val)
        except ValueError:
            return f"Error: Invalid decimal value: '{token}'"
    if not out:
        return "Error: No decimal tokens found."
    return _bytes_to_text(bytes(out))


def _decode_ascii(data: str) -> str:
    """Decode an ASCII-code string (space or comma separated byte values).

    Falls back to interpreting the input itself as ASCII text if no numeric
    tokens are present.
    """
    tokens = re.split(r"[\s,]+", data.strip())
    numeric = [t for t in tokens if re.fullmatch(r"[0-9]+", t)]
    if not numeric:
        # Treat input as literal ASCII text and show its byte codes.
        codes = [str(ord(c)) for c in data]
        return f"ASCII codes: {' '.join(codes)}"
    out = bytearray()
    for token in numeric:
        try:
            val = int(token, 10)
            if val > 255:
                return f"Error: ASCII value out of byte range: {val} (>255)."
            out.append(val)
        except ValueError:
            return f"Error: Invalid ASCII value: '{token}'"
    return _bytes_to_text(bytes(out))


def _decode_utf8(data: str) -> str:
    """Decode a UTF-8 byte string (raw text or space-separated hex bytes)."""
    cleaned = data.strip()
    if re.fullmatch(r"([0-9a-fA-F]{2}\s*)+", cleaned):
        try:
            raw = bytes.fromhex(re.sub(r"\s+", "", cleaned))
        except ValueError as e:
            return f"Error: Invalid UTF-8 byte input - {e}"
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as e:
            return f"Error: Bytes are not valid UTF-8 - {e}"
    # Assume input is already UTF-8 text; validate it.
    try:
        encoded = cleaned.encode("utf-8")
        return f"Valid UTF-8 text ({len(encoded)} bytes): {cleaned}"
    except UnicodeEncodeError as e:
        return f"Error: Invalid UTF-8 text - {e}"


def _base64url_decode(segment: str) -> bytes:
    """Decode a base64url JWT segment (no padding required)."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def decode_jwt(token: str) -> str:
    """Decode a JWT's header and payload (no signature verification).

    Returns the decoded header and payload as formatted JSON, plus the raw
    signature for inspection.  This is a *decoder* only — it never trusts or
    verifies the token.
    """
    parts = token.strip().split(".")
    if len(parts) not in (2, 3):
        return (
            "Error: Invalid JWT — expected header.payload.signature "
            "(3 dot-separated segments)."
        )
    header_seg, payload_seg = parts[0], parts[1]
    try:
        header_bytes = _base64url_decode(header_seg)
        payload_bytes = _base64url_decode(payload_seg)
    except (binascii.Error, ValueError, UnicodeError) as e:
        return f"Error: JWT contains invalid base64url data - {e}"

    try:
        header = json.loads(header_bytes.decode("utf-8"))
        header_pretty = json.dumps(header, indent=2, sort_keys=True)
    except (UnicodeDecodeError, json.JSONDecodeError):
        header_pretty = _bytes_to_text(header_bytes)

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
        payload_pretty = json.dumps(payload, indent=2, sort_keys=True)
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload_pretty = _bytes_to_text(payload_bytes)

    lines = [
        "JWT decoded (header + payload; signature NOT verified):",
        f"Header:\n{header_pretty}",
        f"Payload:\n{payload_pretty}",
    ]
    if len(parts) == 3 and parts[2]:
        sig = parts[2]
        try:
            sig_bytes = _base64url_decode(sig)
            lines.append(f"Signature (raw): {sig}")
            lines.append(f"Signature (hex): {sig_bytes.hex()}")
        except (binascii.Error, ValueError):
            lines.append(f"Signature (raw): {sig} (could not base64url-decode)")
    return "\n".join(lines)


def parse_jwt(token: str) -> str:
    """Parse a JWT and summarize its structure and claims.

    Unlike ``decode_jwt``, this focuses on a structured analysis: algorithm,
    token type, expiry, subject, and other standard claims.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return decode_jwt(token)  # fall back to generic decode

    try:
        header = json.loads(_base64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_base64url_decode(parts[1]).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, binascii.Error, ValueError) as e:
        return f"Error: Could not parse JWT - {e}"

    alg = header.get("alg", "(none)")
    typ = header.get("typ", "(none)")
    lines = [
        f"JWT structure: {len(parts)} segments",
        f"Algorithm (alg): {alg}",
        f"Token type (typ): {typ}",
        f"Header keys: {', '.join(sorted(header.keys()))}",
        f"Payload keys: {', '.join(sorted(payload.keys()))}",
    ]
    import datetime as _dt
    for claim, label in [
        ("sub", "Subject (sub)"),
        ("iss", "Issuer (iss)"),
        ("aud", "Audience (aud)"),
        ("jti", "JWT ID (jti)"),
    ]:
        if claim in payload:
            lines.append(f"{label}: {payload[claim]}")
    for claim, label in [
        ("exp", "Expiry (exp)"),
        ("iat", "Issued at (iat)"),
        ("nbf", "Not before (nbf)"),
    ]:
        if claim in payload:
            try:
                when = _dt.datetime.fromtimestamp(payload[claim], tz=_dt.timezone.utc)
                lines.append(f"{label}: {payload[claim]} ({when.isoformat()})")
            except (ValueError, OSError, TypeError):
                lines.append(f"{label}: {payload[claim]}")
    if alg and alg.lower() in ("none", "n0ne"):
        lines.append("NOTE: 'none' algorithm — token may be accepted without a signature.")
    return "\n".join(lines)


def _decode_gzip(data: str) -> str:
    """Decompress a Gzip stream given as raw bytes or Base64 text."""
    raw = None
    # Try raw bytes first (may contain non-printable chars)
    try:
        raw = data.encode("latin-1")
    except Exception:
        raw = None
    candidates = [raw]
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", data.strip()):
        try:
            candidates.append(base64.b64decode(data + "=" * (-len(data) % 4), validate=True))
        except (binascii.Error, ValueError):
            pass
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            out = gzip.decompress(candidate)
            return _bytes_to_text(out)
        except (OSError, EOFError, zlib.error):
            continue
    return "Error: Input is not a valid Gzip stream (tried raw bytes and Base64)."


def _decode_zlib(data: str) -> str:
    """Decompress a Zlib stream given as raw bytes or Base64 text."""
    candidates = []
    try:
        candidates.append(data.encode("latin-1"))
    except Exception:
        pass
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", data.strip()):
        try:
            candidates.append(base64.b64decode(data + "=" * (-len(data) % 4), validate=True))
        except (binascii.Error, ValueError):
            pass
    for candidate in candidates:
        try:
            out = zlib.decompress(candidate)
            return _bytes_to_text(out)
        except zlib.error:
            continue
    return "Error: Input is not a valid Zlib stream (tried raw bytes and Base64)."


def _auto_decode(data: str) -> str:
    """Try each decoder in order and report the most likely result."""
    results = []

    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", data.strip()):
        r = _decode_base64(data)
        if not r.startswith("Error"):
            results.append(("[base64]", r))

    if re.fullmatch(r"[0-9a-fA-F\s]+", data.strip()):
        r = _decode_hex(data)
        if not r.startswith("Error"):
            results.append(("[hex]", r))

    r = _decode_url(data)
    if not r.startswith("Error") and not r.startswith("Warning"):
        results.append(("[url]", r))

    r = _decode_rot13(data)
    if r != data:
        results.append(("[rot13]", r))

    if re.fullmatch(r"[01\s]+", data.strip()):
        r = _decode_binary(data)
        if not r.startswith("Error"):
            results.append(("[binary]", r))

    if re.fullmatch(r"[0-7\s,]+", data.strip()):
        r = _decode_octal(data)
        if not r.startswith("Error"):
            results.append(("[octal]", r))

    if re.fullmatch(r"[0-9\s,]+", data.strip()):
        r = _decode_decimal(data)
        if not r.startswith("Error"):
            results.append(("[decimal]", r))

    for prefix, result in results:
        if "not valid text" not in result.lower() and "decoded bytes" not in result.lower():
            return f"{prefix}\n{result}"

    if results:
        prefix, result = results[0]
        return f"{prefix}\n{result}"

    return (
        "Error: Could not auto-detect the encoding. Supported: "
        + ", ".join(SUPPORTED_ENCODINGS)
    )


def decode_data(
    data: str,
    encoding: str = "auto",
    workspace_root: Optional[str] = None,
) -> str:
    """Decode *data* using the specified *encoding*.

    Parameters
    ----------
    data:
        The encoded string to decode.
    encoding:
        One of: base64, hex, url, rot13, binary, octal, decimal, ascii,
        utf8, jwt, gzip, zlib, auto.
    workspace_root:
        Unused (kept for registry compatibility).

    Returns
    -------
    str
        The decoded text (or hex dump for non-text results).
    """
    if not data:
        return "Error: No input data provided."

    encoding = (encoding or "auto").lower().strip()
    if encoding == "auto":
        return _auto_decode(data)
    if encoding == "base64":
        return _decode_base64(data)
    if encoding == "hex":
        return _decode_hex(data)
    if encoding == "url":
        return _decode_url(data)
    if encoding == "rot13":
        return _decode_rot13(data)
    if encoding == "binary":
        return _decode_binary(data)
    if encoding == "octal":
        return _decode_octal(data)
    if encoding == "decimal":
        return _decode_decimal(data)
    if encoding == "ascii":
        return _decode_ascii(data)
    if encoding == "utf8":
        return _decode_utf8(data)
    if encoding == "jwt":
        return decode_jwt(data)
    if encoding == "gzip":
        return _decode_gzip(data)
    if encoding == "zlib":
        return _decode_zlib(data)

    return (
        f"Error: Unsupported encoding '{encoding}'. "
        f"Supported: {', '.join(SUPPORTED_ENCODINGS)}."
    )
