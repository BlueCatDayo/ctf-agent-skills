---
name: Ret2win Analysis
identifier: ret2win-analysis
category: binary
description: Find win functions and build validated ret2win payload plans.
difficulty: medium
applicable_challenge_types:
  - binary
trigger_keywords:
  - ret2win
  - win function
  - buffer overflow
  - ret
  - pwn
required_tools:
  - pwn_find_win_function
  - pwn_crash_analyze
  - pwn_elf_info
optional_tools:
  - pwn_verify_offset
  - pwn_pack
  - binary_symbols
prerequisites: []
investigation_steps:
  - title: Triage the binary
    description: Identify arch, endianness, protections, and input functions (analyze_binary / binary.triage).
  - title: Find the win function
    description: Use pwn_find_win_function to get the win/flag function address.
  - title: Determine the offset
    description: Use pwn_crash_analyze with cyclic input, then pwn_verify_offset.
  - title: Validate the plan
    description: Confirm architecture, offset, target address, endianness, arguments, and payload length - never invent addresses.
  - title: Build the payload
    description: pwn_pack(target, bits, endianness) appended after the offset; check 16-byte stack alignment on x86-64.
evidence_requirements:
  - title: Address confirmed
    description: The win function address must come from nm/strings tool output.
  - title: Offset confirmed
    description: The overwrite offset must be crash-derived and verified.
success_criteria:
  - title: Payload plan validated
    description: All plan components (arch, offset, address, endianness) are confirmed by tool output.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: No invented addresses
    description: Every address must come from tool output.
  - title: Local binaries only
    description: Crash analysis runs only on files inside the challenge workspace.
common_mistakes:
  - title: Guessing the offset
    description: Always derive and verify the offset with cyclic input.
version: 1.0.0
---

# Ret2win Analysis

## When to use

- Binaries with a win/flag function and a stack overflow sink.

## Key tools

- pwn_find_win_function, pwn_crash_analyze, pwn_verify_offset, pwn_pack.

## Workflow

1. Triage: arch, endianness, protections, input functions.
2. Find the win function address.
3. Crash the binary with cyclic input to get the offset.
4. Verify the offset, then build the payload with pwn_pack.
