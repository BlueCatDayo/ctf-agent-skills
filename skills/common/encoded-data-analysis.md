---
name: Encoded Data Analysis
identifier: encoded-data-analysis
category: common
description: Guide for identifying and decoding obfuscated data in CTF challenges.
difficulty: easy
applicable_challenge_types:
  - web
  - binary
  - forensics
trigger_keywords:
  - encoded
  - base64
  - hex
  - url
  - rot13
  - decode
  - obfuscation
  - cipher
required_tools:
  - decode_data
optional_tools:
  - calculate_file_hash
  - search_files
prerequisites: []
investigation_steps:
  - title: Identify encoding type
    description: Look for patterns like base64 alphabet, hex strings, or URL percent-encoding in file contents or HTTP responses.
  - title: Attempt auto-detection
    description: Use decode_data with encoding=auto to let the tool detect the encoding automatically.
  - title: Try common encodings manually
    description: If auto-detection fails, try base64, hex, url, rot13, and binary in sequence.
  - title: Verify decoded output
    description: Check if decoded content is readable text, JSON, or a known file format.
  - title: Chain decodings
    description: Some challenges layer multiple encodings; decode the result again if it looks still encoded.
evidence_requirements:
  - title: Decoded content is readable
    description: The decoded output must be human-readable text or a structured format (JSON, XML).
  - title: Decoding is repeatable
    description: Running the same decode on the same input produces the same output.
success_criteria:
  - title: Data successfully decoded
    description: The encoded data is decoded to meaningful, readable content that advances the investigation.
stopping_conditions:
  - title: Content is fully decoded
    description: Stop once the decoded content is readable and no further encoding layers are apparent.
safety_notes:
  - title: Do not execute decoded content blindly
    description: Decoded data may contain malicious payloads; inspect before running.
common_mistakes:
  - title: Assuming a single encoding layer
    description: Some challenges use multiple layers of encoding; always check if the decoded result is still encoded.
  - title: Ignoring binary encoding
    description: Binary-to-text encodings (base64, hex) are common; do not skip them.
version: 1.0.0
---

# Encoded Data Analysis

This skill guides you through identifying and decoding obfuscated data in CTF challenges.

## When to use

- You find strings that look like random base64, hex, or URL-encoded text.
- A challenge description mentions encoding, obfuscation, or ciphers.
- HTTP responses contain encoded parameters or body content.

## Key tools

- `decode_data` — auto-detects and decodes base64, hex, URL, ROT13, and binary strings.
- `search_files` — find encoded strings across challenge files.
- `calculate_file_hash` — verify file integrity after decoding.

## Workflow

1. Identify the encoding type by inspecting the string format.
2. Use `decode_data` with `encoding=auto` for automatic detection.
3. If auto-detection fails, try specific encodings manually.
4. Verify the decoded output is meaningful.
5. If the decoded output still looks encoded, chain decodings.

## Common pitfalls

- Assuming only one encoding layer is applied.
- Not checking for binary-to-text encodings like base64 or hex.
- Executing decoded content without inspecting it first.
