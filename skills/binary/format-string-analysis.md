---
name: Format String Analysis
identifier: format-string-analysis
category: binary
description: Guide for analyzing format string vulnerabilities in binary challenges.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - format string
  - printf
  - sprintf
  - format
  - %n
  - %x
  - %s
required_tools:
  - run_ctf_command
optional_tools:
  - decode_data
prerequisites:
  - static-disassembly-analysis
investigation_steps:
  - title: Identify format string functions
    description: Look for calls to printf, sprintf, fprintf, snprintf, and syslog in disassembly.
  - title: Check if user input is the format string
    description: Determine if a user-controlled string is passed directly as the format argument.
  - title: Test for format string vulnerabilities
    description: Send format specifiers (%x, %s, %n) to input points and observe output differences.
  - title: Analyze output differences
    description: Analyze the output to confirm if format specifiers are being expanded.
evidence_requirements:
  - title: Format string vulnerability confirmed
    description: Format specifier output must be visible in tool output.
  - title: Vulnerable function identified
    description: The unsafe format string function call must be documented.
success_criteria:
  - title: Format string vulnerability confirmed with evidence
    description: A format string vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: Format string vulnerability confirmed
    description: Stop once the format string vulnerability is confirmed; do not attempt further exploitation.
safety_notes:
  - title: Do not attempt arbitrary write exploitation
    description: This skill is for analysis only; do not attempt to use %n for arbitrary memory writes.
  - title: Use safe format specifiers only
    description: Use %x and %s for detection; avoid %n which can modify memory.
common_mistakes:
  - title: Not checking if user input is the format string
    description: The format string vulnerability only exists if user input controls the format argument.
  - title: Using %n prematurely
    description: %n can modify memory; use %x and %s for safe detection first.
version: 1.0.0
---

# Format String Analysis

This skill guides you through analyzing format string vulnerabilities in binary challenges.

## When to use

- A binary uses printf, sprintf, or similar functions with user-controlled format strings.
- You want to find format string vulnerabilities.
- You see format string functions in disassembly with user input as arguments.

## Key tools

- run_ctf_command for objdump -d, strings for analysis.
- decode_data for decoding any encoded addresses or values.

## Workflow

1. Identify format string function calls in disassembly (printf, sprintf, fprintf).
2. Check if user input is the format string argument.
3. Send format specifiers (%x, %s) to input points.
4. Analyze output differences to confirm the vulnerability.
5. Stop once confirmed; do not attempt %n exploitation.

## Common pitfalls

- Not checking if user input controls the format argument.
- Using %n prematurely instead of safe specifiers (%x, %s).
- Attempting arbitrary write exploitation instead of stopping at confirmation.