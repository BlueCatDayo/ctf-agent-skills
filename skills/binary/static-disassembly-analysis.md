---
name: Static Disassembly Analysis
identifier: static-disassembly-analysis
category: binary
description: Guide for static disassembly analysis of binary challenges.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - disassembly
  - objdump
  - IDA
  - Ghidra
  - decompilation
  - assembly
  - disassemble
required_tools:
  - run_ctf_command
optional_tools:
  - inspect_file
  - search_files
prerequisites:
  - architecture-and-protection-analysis
  - strings-and-symbols-analysis
investigation_steps:
  - title: Disassemble key functions
    description: Use objdump -d to disassemble the binary and examine key functions (main, win, check).
  - title: Analyze control flow
    description: Trace the execution path through key functions; identify branches and loops.
  - title: Identify dangerous function calls
    description: Look for calls to system, exec, gets, strcpy, sprintf, and other unsafe functions.
  - title: Analyze string references
    description: Cross-reference string addresses with function calls to understand program logic.
  - title: Look for hidden functionality
    description: Check for unused functions, backdoors, or Easter eggs in the disassembly.
evidence_requirements:
  - title: Key functions disassembled
    description: The disassembly of critical functions must be documented.
  - title: Dangerous calls identified
    description: Any calls to unsafe functions must be recorded.
success_criteria:
  - title: Static analysis complete
    description: Key functions have been disassembled and their logic understood.
stopping_conditions:
  - title: Static analysis complete
    description: Stop once the key functions have been fully analyzed.
safety_notes:
  - title: Do not execute the binary
    description: Static analysis only; do not run the binary.
  - title: Start with strings and symbols before disassembly
    description: Use strings-and-symbols-analysis before diving into disassembly.
common_mistakes:
  - title: Jumping to disassembly without strings analysis
    description: Always run strings and nm first; they provide context for disassembly.
  - title: Not cross-referencing strings with code
    description: String addresses help understand what each function does.
version: 1.0.0
---

# Static Disassembly Analysis

This skill guides you through static disassembly analysis of binary files.

## When to use

- You need to understand the logic of a binary without running it.
- You want to find vulnerabilities in the assembly code.
- You are analyzing a binary challenge at a deeper level.

## Key tools

- run_ctf_command for objdump -d, objdump -t, readelf.
- inspect_file for metadata and type information.

## Workflow

1. Run strings and nm first to get context.
2. Disassemble key functions with objdump -d.
3. Analyze control flow and branches.
4. Identify dangerous function calls (system, exec, gets, strcpy).
5. Cross-reference string addresses with function calls.
6. Look for hidden functionality.

## Common pitfalls

- Jumping to disassembly without first running strings and nm.
- Not cross-referencing strings with code.
- Trying to analyze the entire binary instead of focusing on key functions.
