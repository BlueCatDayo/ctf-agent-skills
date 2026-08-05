---
name: Flag Verification
identifier: flag-verification
category: common
description: Guide for safely confirming flag values from tool output.
difficulty: easy
applicable_challenge_types:
  - web
  - binary
  - forensics
trigger_keywords:
  - flag
  - verify
  - confirm
  - check
  - validate
required_tools:
  - search_files
  - read_text_file
optional_tools:
  - calculate_file_hash
  - decode_data
prerequisites: []
investigation_steps:
  - title: Search for flag patterns in tool output
    description: Look for flag{...} patterns in the raw output of tools, not in assumptions.
  - title: Verify the flag appears in a reliable source
    description: Confirm the flag was produced by a tool (file read, HTTP response, command output).
  - title: Do not modify the flag value
    description: Report the flag exactly as it appears; do not trim, decode, or transform it.
  - title: Distinguish confirmed from hypothesized
    description: Only report a flag as confirmed if it appeared in verified tool output.
evidence_requirements:
  - title: Flag appears in tool output
    description: The exact flag string must appear in a tool result, file, or program output.
  - title: Source is reliable
    description: The tool output must come from a verified, non-malicious source.
success_criteria:
  - title: Flag confirmed with evidence
    description: The flag is reported with a clear explanation of where and how it was found.
stopping_conditions:
  - title: Flag confirmed
    description: Stop investigating once a flag is confirmed with evidence.
safety_notes:
  - title: Never invent a flag
    description: Do not guess or construct a flag; only report what tool output shows.
  - title: Do not claim unverified candidates
    description: Unverified flag candidates must be reported as possible, not confirmed.
common_mistakes:
  - title: Claiming a flag from skill content
    description: Skills provide guidance, not evidence. A flag is only confirmed from tool output.
  - title: Modifying the flag value
    description: Report the flag exactly as it appears in the output.
version: 1.0.0
---

# Flag Verification

This skill ensures flags are reported safely and accurately.

## When to use

- You believe you have found a flag.
- You need to confirm a flag before reporting.
- You want to avoid false positives.

## Key principle

A flag is only confirmed if the exact flag value appears in verified tool output. Skills provide guidance, not evidence.

## Workflow

1. Find the flag string in tool output (file read, HTTP response, command output).
2. Verify the source is reliable (not a skill suggestion or hypothesis).
3. Report the flag exactly as it appears.
4. Provide evidence explaining where and how it was found.

## Common pitfalls

- Claiming a flag because a skill suggested it.
- Modifying or transforming the flag value before reporting.
- Reporting an unverified candidate as confirmed.
