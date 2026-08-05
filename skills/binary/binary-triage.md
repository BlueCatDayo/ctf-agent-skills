---
name: Binary Triage
identifier: binary-triage
category: binary
description: Guide for initial analysis and triage of binary challenge files.
difficulty: easy
applicable_challenge_types:
  - binary
trigger_keywords:
  - binary
  - triage
  - analyze
  - inspect
  - executable
  - ELF
  - PE
required_tools:
  - run_ctf_command
  - inspect_file
optional_tools:
  - list_files
  - calculate_file_hash
  - search_files
prerequisites: []
investigation_steps:
  - title: Identify the binary type
    description: Use run_ctf_command with file to determine the binary format (ELF, PE, Mach-O).
  - title: Inspect file metadata
    description: Use inspect_file to get size, hash, and type information.
  - title: Extract readable strings
    description: Use run_ctf_command with strings to find readable text in the binary.
  - title: Calculate file hash
    description: Use calculate_file_hash (SHA-256) to identify the binary against known signatures.
  - title: Check for architecture and protections
    description: Use readelf or objdump to identify the target architecture and security features.
evidence_requirements:
  - title: Binary type identified
    description: The file format (ELF, PE, etc.) must be confirmed.
  - title: Architecture identified
    description: The target architecture (x86, x86_64, ARM, etc.) must be documented.
success_criteria:
  - title: Binary triage complete
    description: The binary has been identified, hashed, and its basic properties documented.
stopping_conditions:
  - title: Binary triage complete
    description: Stop once the binary type, architecture, and key properties are known.
safety_notes:
  - title: Do not execute the binary
    description: Inspect binaries with tools, not by running them.
  - title: Stay within workspace
    description: All binary analysis must stay inside the configured workspace.
common_mistakes:
  - title: Running the binary instead of inspecting it
    description: Always use analysis tools first; running unknown binaries is unsafe.
  - title: Not calculating hashes
    description: Hashes help identify known binaries and detect modifications.
version: 1.0.0
---

# Binary Triage

This skill guides you through initial analysis and triage of binary challenge files.

## When to use

- You have a binary file in the challenge.
- You need to understand the binary format and architecture.
- You want to start a binary exploitation challenge.

## Key tools

- run_ctf_command for file, strings, readelf, objdump, nm, ldd, xxd.
- inspect_file for metadata, hash, type information.
- calculate_file_hash for SHA-256 identification.

## Workflow

1. Run `file` to identify the binary format.
2. Run `strings` to find readable text.
3. Run `readelf` or `objdump` to check architecture and protections.
4. Calculate SHA-256 hash for identification.
5. Document findings.

## Common pitfalls

- Running the binary instead of inspecting it with tools.
- Not calculating hashes for identification.
- Skipping string extraction.
