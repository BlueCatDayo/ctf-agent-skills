---
name: Architecture and Protection Analysis
identifier: architecture-and-protection-analysis
category: binary
description: Guide for analyzing binary architecture and security protections.
difficulty: medium
applicable_challenge_types:
  - binary
trigger_keywords:
  - architecture
  - protection
  - checksec
  - NX
  - PIE
  - ASLR
  - stack canary
  - RELRO
required_tools:
  - run_ctf_command
optional_tools:
  - inspect_file
  - calculate_file_hash
prerequisites:
  - binary-triage
investigation_steps:
  - title: Identify the binary architecture
    description: Use readelf -h or objdump -f to determine the target architecture (x86, x86_64, ARM).
  - title: Check security protections
    description: Use checksec or readelf to identify NX, PIE, ASLR, stack canary, and RELRO settings.
  - title: Analyze the ELF headers
    description: Use readelf -l to examine program headers and segment permissions.
  - title: Identify the entry point
    description: Use readelf -h or objdump -d to find the entry point and main function.
evidence_requirements:
  - title: Architecture documented
    description: The target architecture must be confirmed.
  - title: Protections identified
    description: All relevant security protections (NX, PIE, ASLR, canary, RELRO) must be recorded.
success_criteria:
  - title: Architecture and protections analyzed
    description: The binary architecture and all relevant security protections have been documented.
stopping_conditions:
  - title: Analysis complete
    description: Stop once the architecture and protections are fully documented.
safety_notes:
  - title: Do not execute the binary
    description: Use analysis tools only; do not run the binary.
common_mistakes:
  - title: Not checking all protection mechanisms
    description: Missing a protection (e.g., stack canary) can lead to incorrect exploit strategies.
  - title: Assuming all binaries are x86_64
    description: Always verify the architecture; ARM, MIPS, and other architectures are common in CTFs.
version: 1.0.0
---

# Architecture and Protection Analysis

This skill guides you through analyzing binary architecture and security protections.

## When to use

- You have a binary file and need to understand its architecture and protections.
- You want to determine the exploit approach based on protection mechanisms.
- You need to identify the target platform.

## Key tools

- run_ctf_command for readelf, objdump, checksec, file.
- inspect_file for metadata and type information.

## Workflow

1. Run `file` to identify the binary format and architecture.
2. Run `readelf -h` to examine ELF headers.
3. Run `readelf -l` to check program headers and segment permissions.
4. Use checksec or manual readelf analysis to identify protections.
5. Document all findings.

## Common pitfalls

- Not checking all protection mechanisms.
- Assuming all binaries are x86_64.
- Skipping program header analysis.
