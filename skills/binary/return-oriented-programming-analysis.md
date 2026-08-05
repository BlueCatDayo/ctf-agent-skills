---
name: Return-Oriented Programming Analysis
identifier: return-oriented-programming-analysis
category: binary
description: Guide for analyzing ROP chain possibilities in binary challenges.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - ROP
  - return oriented programming
  - gadget
  - ret2libc
  - ret2reg
  - rop chain
required_tools:
  - run_ctf_command
optional_tools:
  - decode_data
prerequisites:
  - architecture-and-protection-analysis
  - static-disassembly-analysis
investigation_steps:
  - title: Check if ASLR and PIE are enabled
    description: Use readelf and checksec to determine if address space layout randomization and position-independent executables are active.
  - title: Identify useful gadgets
    description: Use objdump -d or ROPgadget (if available) to find pop rdi; ret and similar gadgets.
  - title: Identify useful library functions
    description: Use nm or objdump -t to find system, execve, and other useful functions in linked libraries.
  - title: Check for partial overwrite possibilities
    description: Determine if only the least significant bytes of the return address can be controlled.
  - title: Document ROP chain components
    description: Record all identified gadgets, library functions, and their addresses.
evidence_requirements:
  - title: Gadgets identified
    description: At least one useful ROP gadget must be documented with its address.
  - title: Library functions identified
    description: Useful library functions (system, execve) must be documented with their addresses.
success_criteria:
  - title: ROP analysis complete
    description: All useful gadgets and library functions have been identified and documented.
stopping_conditions:
  - title: ROP analysis complete
    description: Stop once gadgets and library functions have been documented; do not attempt to build a full ROP chain.
safety_notes:
  - title: Do not attempt to build or run ROP chains
    description: This skill is for analysis only; do not attempt to construct or execute ROP chains.
  - title: Document addresses accurately
    description: ROP gadget addresses must be exact; a wrong address will cause failure.
common_mistakes:
  - title: Not checking ASLR and PIE status first
    description: ROP strategy depends entirely on whether addresses are randomized or fixed.
  - title: Attempting to build ROP chains
    description: This skill is for analysis only; stop at documentation.
version: 1.0.0
---

# Return-Oriented Programming Analysis

This skill guides you through analyzing ROP chain possibilities in binary challenges.

## When to use

- A binary has executable code but no writable-executable memory (NX enabled).
- You want to find ROP gadgets and library functions for potential exploitation.
- You have identified a buffer overflow that overwrites the return address.

## Key tools

- run_ctf_command for objdump -d, nm, readelf for analysis.
- decode_data for decoding addresses and gadget values.

## Workflow

1. Check ASLR and PIE status with readelf and checksec.
2. Identify useful gadgets (pop rdi; ret, etc.) in disassembly.
3. Identify useful library functions (system, execve) with nm.
4. Check for partial overwrite possibilities.
5. Document all ROP chain components.

## Common pitfalls

- Not checking ASLR/PIE status before analyzing gadgets.
- Attempting to build ROP chains instead of stopping at documentation.
- Documenting incorrect gadget addresses.