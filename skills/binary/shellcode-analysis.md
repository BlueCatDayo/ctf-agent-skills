---
name: Shellcode Analysis
identifier: shellcode-analysis
category: binary
description: Guide for analyzing shellcode in binary challenges.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - shellcode
  - execve
  - /bin/sh
  - spawn shell
  - opcode
  - malicious bytes
required_tools:
  - run_ctf_command
optional_tools:
  - decode_data
prerequisites:
  - static-disassembly-analysis
investigation_steps:
  - title: Identify shellcode in the binary
    description: Look for encoded byte sequences or data that may decode into executable shellcode.
  - title: Analyze byte patterns
    description: Use decode_data or hex tools to convert encoded data and inspect the resulting bytes.
  - title: Look for /bin/sh or exec patterns
    description: Search for /bin/sh strings or syscall patterns (0x3b execve on x86_64).
  - title: Determine shellcode usage
    description: Cross-reference shellcode bytes with code that fetches or executes them.
evidence_requirements:
  - title: Shellcode identified and decoded
    description: The shellcode bytes and any decoding must be documented.
  - title: Shellcode functionality understood
    description: What the shellcode does (spawn shell, connect back, etc.) must be recorded.
success_criteria:
  - title: Shellcode analyzed
    description: The shellcode has been identified, decoded, and its functionality understood.
stopping_conditions:
  - title: Shellcode analysis complete
    description: Stop once the shellcode has been fully analyzed; do not attempt to execute it.
safety_notes:
  - title: Do not execute shellcode
    description: Shellcode analysis is read-only; do not run or inject shellcode.
  - title: Identify bad characters
    description: Knowing which bytes break the shellcode is critical for any further analysis.
common_mistakes:
  - title: Not checking for bad characters
    description: Bad characters (null bytes, newlines) can break shellcode and must be identified.
  - title: Attempting to execute shellcode
    description: Shellcode analysis is read-only; do not run or inject it.
version: 1.0.0
---

# Shellcode Analysis

This skill guides you through analyzing shellcode in binary challenges.

## When to use

- A binary contains embedded or encoded shellcode.
- You want to understand what a shellcode payload does.
- You need to identify bad characters that would break shellcode.

## Key tools

- run_ctf_command for objdump -d, GDB for disassembly.
- decode_data for decoding shellcode bytes if encoded.

## Workflow

1. Identify shellcode bytes in the binary or memory.
2. Decode any encoded shellcode bytes.
3. Analyze what the shellcode does (spawn shell, connect back, etc.).
4. Identify bad characters that would break the shellcode.
5. Stop once analysis is complete; do not execute the shellcode.

## Common pitfalls

- Not checking for bad characters (null bytes, newlines).
- Attempting to execute shellcode instead of analyzing it read-only.
- Not understanding the shellcode actual functionality before proceeding.