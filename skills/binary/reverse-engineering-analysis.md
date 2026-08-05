---
name: Reverse Engineering Analysis
identifier: reverse-engineering-analysis
category: binary
description: Guide for comprehensive reverse engineering analysis of binary challenges.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - reverse engineering
  - RE
  - decompilation
  - Ghidra
  - IDA
  - radare2
  - binary analysis
  - crackme
required_tools:
  - run_ctf_command
optional_tools:
  - decode_data
  - search_files
prerequisites:
  - binary-triage
  - architecture-and-protection-analysis
  - strings-and-symbols-analysis
  - static-disassembly-analysis
investigation_steps:
  - title: Perform complete binary triage
    description: Run file, strings, and hash calculations to understand the binary basics.
  - title: Analyze architecture and protections
    description: Determine the target architecture and all active security protections.
  - title: Extract and analyze strings
    description: Find all readable strings and cross-reference them with function calls.
  - title: Disassemble key functions
    description: Use objdump -d to disassemble the main logic functions.
  - title: Trace program execution
    description: Use GDB to trace execution through key code paths with controlled input.
  - title: Identify the challenge logic
    description: Understand the core challenge logic (password check, license validation, etc.).
  - title: Document the complete analysis
    description: Record all findings, including key addresses, strings, and logic paths.
evidence_requirements:
  - title: Challenge logic understood
    description: The core challenge logic must be documented with supporting tool output.
  - title: Key addresses and strings documented
    description: Critical addresses, function names, and strings must be recorded.
success_criteria:
  - title: Reverse engineering analysis complete
    description: The binary core logic has been fully understood through static and dynamic analysis.
stopping_conditions:
  - title: Challenge logic understood
    description: Stop once the core challenge logic is understood; do not attempt full exploitation.
safety_notes:
  - title: Do not attempt full exploitation
    description: This skill is for analysis only; do not generate or run exploit code.
  - title: Do not execute the binary without controlled input
    description: Always use controlled test input when running the binary dynamically.
common_mistakes:
  - title: Skipping triage steps
    description: Always complete binary triage before diving into disassembly.
  - title: Not documenting findings as you go
    description: Reverse engineering produces a lot of information; document key findings immediately.
version: 1.0.0
---

# Reverse Engineering Analysis

This skill guides you through comprehensive reverse engineering analysis of binary challenges.

## When to use

- You have a binary challenge and need to understand its logic completely.
- You want a systematic approach to reverse engineering.
- You need to find the challenge core logic (password check, license validation, etc.).

## Key tools

- run_ctf_command for file, strings, nm, objdump -d, ldd, readelf, GDB.
- decode_data for decoding any encoded values found in the binary.
- search_files for searching for flag patterns and hardcoded values.

## Workflow

1. Perform complete binary triage (file, strings, hash).
2. Analyze architecture and protections (readelf, checksec).
3. Extract and analyze strings (strings, grep for patterns).
4. Disassemble key functions (objdump -d).
5. Trace program execution with GDB and controlled input.
6. Identify the core challenge logic.
7. Document all findings.

## Common pitfalls

- Skipping triage steps before disassembly.
- Not documenting findings as you go.
- Attempting full exploitation instead of stopping at analysis.