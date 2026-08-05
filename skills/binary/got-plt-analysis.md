---
name: GOT and PLT Analysis
identifier: got-plt-analysis
category: binary
description: Analyze PLT/GOT entries for ret2plt, GOT overwrite, and ret2libc preparation.
difficulty: medium
applicable_challenge_types:
  - binary
trigger_keywords:
  - GOT
  - PLT
  - ret2plt
  - ret2libc
  - relocation
  - JUMP_SLOT
  - dynamic symbol
required_tools:
  - pwn_got_plt
  - binary_readelf
optional_tools:
  - binary_symbols
  - binary_libraries
  - pwn_find_gadgets
prerequisites: []
investigation_steps:
  - title: List relocations
    description: pwn_got_plt shows JUMP_SLOT/GLOB_DAT relocations - the functions reachable via PLT.
  - title: Identify useful targets
    description: Look for puts/printf/system/strlen in the PLT for leaks and calls.
  - title: Check the dynamic section
    description: readelf -d shows NEEDED libraries - a libc file may be provided for ret2libc.
  - title: Plan the chain
    description: Combine PLT calls, GOT entries, and gadgets (pwn_find_gadgets) into a validated plan.
evidence_requirements:
  - title: Entries confirmed
    description: PLT/GOT entries must come from readelf tool output.
  - title: Addresses validated
    description: Addresses used in the chain must come from tool output.
success_criteria:
  - title: Chain planned
    description: A validated leak/call chain is planned from confirmed entries.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: No invented addresses
    description: Every address comes from tool output.
common_mistakes:
  - title: Forgetting partial RELRO
    description: GOT overwrites only work on binaries without full RELRO - check protections first.
version: 1.0.0
---

# GOT and PLT Analysis

## When to use

- Ret2libc/ret2plt challenges, format-string GOT writes, PIE-ASLR bypass via leaks.

## Key tools

- pwn_got_plt, binary_readelf (relocations/dynamic), pwn_find_gadgets.

## Workflow

1. List relocations and dynamic entries.
2. Identify useful PLT functions and GOT targets.
3. Check RELRO before planning a GOT overwrite.
4. Build a validated chain from confirmed addresses.
