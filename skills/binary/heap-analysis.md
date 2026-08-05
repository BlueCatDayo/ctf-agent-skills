---
name: Heap Analysis
identifier: heap-analysis
category: binary
description: Guide for analyzing heap-based vulnerabilities in binary challenges.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - heap
  - malloc
  - free
  - chunk
  - use-after-free
  - heap overflow
  - double free
required_tools:
  - run_ctf_command
optional_tools:
  - decode_data
prerequisites:
  - static-disassembly-analysis
  - architecture-and-protection-analysis
investigation_steps:
  - title: Identify heap allocation patterns
    description: Look for malloc, calloc, realloc, and free calls in disassembly.
  - title: Analyze allocation sizes
    description: Determine how allocation sizes are calculated and whether they can be controlled or overflowed.
  - title: Check for use-after-free patterns
    description: Look for pointers that are used after being freed.
  - title: Test for heap overflow
    description: Send input that overflows a heap buffer and observe the crash or behavior.
  - title: Analyze heap metadata
    description: If possible, examine heap chunk metadata for corruption indicators.
evidence_requirements:
  - title: Heap vulnerability confirmed
    description: Unexpected heap behavior or crash must be observed in tool output.
  - title: Allocation pattern documented
    description: The heap allocation and deallocation pattern must be recorded.
success_criteria:
  - title: Heap analysis complete
    description: Heap allocation patterns and potential vulnerabilities have been documented.
stopping_conditions:
  - title: Heap analysis complete
    description: Stop once heap allocation patterns and vulnerabilities have been documented.
safety_notes:
  - title: Do not attempt heap exploitation
    description: This skill is for analysis only; do not attempt to exploit heap vulnerabilities.
  - title: Use controlled test input
    description: Send test input that confirms the vulnerability without causing system damage.
common_mistakes:
  - title: Not analyzing allocation size calculations
    description: Integer overflow in size calculations is a common source of heap vulnerabilities.
  - title: Ignoring use-after-free patterns
    description: Use-after-free is a critical heap vulnerability that is often overlooked.
version: 1.0.0
---

# Heap Analysis

This skill guides you through analyzing heap-based vulnerabilities in binary challenges.

## When to use

- A binary uses dynamic memory allocation (malloc, free, calloc).
- You want to find heap-based vulnerabilities.
- You see heap-related function calls in disassembly.

## Key tools

- run_ctf_command for objdump -d for disassembly analysis.
- decode_data for decoding any encoded addresses or values.

## Workflow

1. Identify malloc, calloc, realloc, and free calls in disassembly.
2. Analyze how allocation sizes are calculated.
3. Check for use-after-free patterns.
4. Test for heap overflow with controlled input.
5. Analyze crash output for heap corruption indicators.

## Common pitfalls

- Not analyzing allocation size calculations for integer overflow.
- Ignoring use-after-free patterns.
- Attempting heap exploitation instead of stopping at analysis.