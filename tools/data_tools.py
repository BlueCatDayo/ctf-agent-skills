"""Data decoding tool - supports Base64, hex, URL, ROT13, and binary strings."""

import base64
import binascii
import re
from typing import Optional

from .workspace import PathTraversalError, WorkspaceError

MAX_TOOL_OUTPUT_CHARS = 4096


def _truncate(text: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Truncate text to *limit* characters."""
    if len(text) > limit:
        return text[:limit] + f"\n... [output truncated at {limit} characters]"
    return text


def _is_valid_text(data: bytes) -> bool:
    """Return True if *data* appears to be valid readable text."""
    if not data:
        return False
    # Check for NUL bytes
    if b"\x00" in data:
        return False
    # Check that the majority of bytes are printable or common whitespace
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data) > 0.85


def decode_data(
    data: str,
    encoding: str = "auto",
    workspace_root: Optional[str] = None,
) -> str:
    """Decode data from a supported encoding.

    Supported encodings: base64, hex, url, rot13, binary, auto.

    Parameters
    ----------
    data:
        The encoded string to decode.
    encoding:
        The encoding to use.  ``auto`` attempts detection.
    workspace_root:
        Unused for this tool (present for API consistency).

    Returns
    -------
    str
        The decoded text, hex output for non-text results, or an error.
    """
    if not data:
        return "Error: No input data provided."

    encoding = encoding.lower().strip()

    # Auto-detection: try each encoding in order
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

    return (
        f"Error: Unsupported encoding '{encoding}'. "
        f"Supported: base64, hex, url, rot13, binary, auto."
    )


def _decode_base64(data: str) -> str:
    """Decode a Base64-encoded string."""
    try:
        # Pad if necessary
        padded = data + "=" * (-len(data) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as e:
        return f"Error: Invalid Base64 input - {e}"

    if _is_valid_text(decoded_bytes):
        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return decoded_bytes.decode("latin-1")
            except UnicodeDecodeError:
                return (
                    f"Decoded bytes (not valid text):\n"
                    f"{decoded_bytes.hex()}"
                )
    return f"Decoded bytes (not valid text):\n{decoded_bytes.hex()}"


def _decode_hex(data: str) -> str:
    """Decode a hexadecimal string."""
    # Strip common prefixes
    cleaned = data.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]

    # Remove whitespace
    cleaned = re.sub(r"\s+", "", cleaned)

    # Validate hex characters
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        return "Error: Invalid hexadecimal input - contains non-hex characters."

    if len(cleaned) % 2 != 0:
        return "Error: Invalid hexadecimal input - odd number of digits."

    try:
        decoded_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hexadecimal input - {e}"

    if _is_valid_text(decoded_bytes):
        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return decoded_bytes.decode("latin-1")
            except UnicodeDecodeError:
                return (
                    f"Decoded bytes (not valid text):\n"
                    f"{decoded_bytes.hex()}"
                )
    return f"Decoded bytes (not valid text):\n{decoded_bytes.hex()}"


def _decode_url(data: str) -> str:
    """Decode a URL-encoded string."""
    try:
        # Use urllib.parse for URL decoding
        from urllib.parse import unquote
    except ImportError:
        return "Error: URL decoding module not available."

    try:
        decoded = unquote(data)
    except Exception as e:
        return f"Error: Invalid URL-encoded input - {e}"

    if decoded == data:
        return (
            "Warning: Input does not appear to be URL-encoded "
            "(no percent-encoded sequences found)."
        )

    return decoded


def _decode_rot13(data: str) -> str:
    """Decode a ROT13-encoded string."""
    result = []
    for ch in data:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def _decode_binary(data: str) -> str:
    """Decode a binary string (e.g. '01001000 01101001')."""
    # Clean up the input
    cleaned = data.strip()
    # Split on whitespace
    tokens = cleaned.split()

    # Validate that each token is a binary string
    for token in tokens:
        if not re.fullmatch(r"[01]+", token):
            return (
                f"Error: Invalid binary input - "
                f"'{token}' contains non-binary characters."
            )

    # Convert each byte
    decoded_bytes = bytearray()
    for token in tokens:
        # Pad to 8 bits
        padded = token.zfill(8)
        if len(padded) > 8:
            # Take the last 8 bits
            padded = padded[-8:]
        decoded_bytes.append(int(padded, 2))

    if _is_valid_text(bytes(decoded_bytes)):
        try:
            return bytes(decoded_bytes).decode("utf-8")
        except UnicodeDecodeError:
            try:
                return bytes(decoded_bytes).decode("latin-1")
            except UnicodeDecodeError:
                return (
                    f"Decoded bytes (not valid text):\n"
                    f"{bytes(decoded_bytes).hex()}"
                )
    return f"Decoded bytes (not valid text):\n{bytes(decoded_bytes).hex()}"


def _auto_decode(data: str) -> str:
    """Try each encoding automatically and return the first successful result."""
    import re as _re

    # Collect results from each encoding attempt
    results = []

    # Try Base64 (only if it looks like valid base64)
    if _re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', data.strip()):
        result = _decode_base64(data)
        if not result.startswith("Error") and not result.startswith("Warning"):
            results.append(("[auto-detected: base64]", result))

    # Try hex (only if it looks like valid hex)
    if _re.fullmatch(r'[0-9a-fA-F]+', data.strip()):
        result = _decode_hex(data)
        if not result.startswith("Error") and not result.startswith("Warning"):
            results.append(("[auto-detected: hex]", result))

    # Try URL
    result = _decode_url(data)
    if not result.startswith("Error") and not result.startswith("Warning"):
        results.append(("[auto-detected: url]", result))

    # Try ROT13
    result = _decode_rot13(data)
    if result != data:
        results.append(("[auto-detected: rot13]", result))

    # Try binary (only if it looks like valid binary)
    if _re.fullmatch(r'[01\s]+', data.strip()):
        result = _decode_binary(data)
        if not result.startswith("Error") and not result.startswith("Warning"):
            results.append(("[auto-detected: binary]", result))

    # Return the first result that produces valid text
    for prefix, result in results:
        # Check if the result is valid text (not hex dump of bytes)
        if "not valid text" not in result.lower() and "decoded bytes" not in result.lower():
            return f"{prefix}\n{result}"

    # If no result produced valid text, return the first one or an error
    if results:
        prefix, result = results[0]
        return f"{prefix}\n{result}"

    return (
        "Error: Could not auto-detect the encoding. "
        "Try specifying encoding explicitly: base64, hex, url, rot13, or binary."
    )
