---
name: File Triage
identifier: file-triage
category: common
description: Guide for systematically inspecting and categorizing challenge files.
difficulty: easy
applicable_challenge_types:
  - web
  - binary
  - forensics
trigger_keywords:
  - file
  - triage
  - inspect
  - categorize
  - identify
  - file type
required_tools:
  - list_files
  - inspect_file
  - calculate_file_hash
optional_tools:
  - read_text_file
  - search_files
  - run_ctf_command
prerequisites: []
investigation_steps:
  - title: List all challenge files
    description: Use list_files to get a complete picture of what files are available in the workspace.
  - title: Inspect each file metadata
    description: Run inspect_file on each file to determine type, size, hash, and whether it is text or binary.
  - title: Calculate hashes for comparison
    description: Use calculate_file_hash (SHA-256) to compare files against known signatures or detect duplicates.
  - title: Read text files first
    description: Use read_text_file on files identified as text; skip binary files until needed.
  - title: Search for flag patterns
    description: Use search_files to look for flag{ patterns or other CTF markers.
evidence_requirements:
  - title: File type identified
    description: Each file must have a confirmed type (text, binary, archive, etc.).
  - title: Hashes calculated
    description: SHA-256 hashes should be recorded for all significant files.
success_criteria:
  - title: All files catalogued
    description: Every file in the workspace has been inspected and categorized.
stopping_conditions:
  - title: Flag found or all files inspected
    description: Stop once a flag is confirmed or all files have been triaged.
safety_notes:
  - title: Do not execute unknown binaries
    description: Inspect binary files with tools, not by running them.
  - title: Stay within workspace
    description: All file operations must stay inside the configured workspace.
common_mistakes:
  - title: Skipping binary file inspection
    description: Binary files often contain important strings or embedded data; always inspect them.
  - title: Not calculating hashes
    description: Hashes help detect file modifications and identify known file types.
version: 1.0.0
---

# File Triage

This skill guides you through systematically inspecting and categorizing challenge files.

## When to use

- You have a new challenge folder with unknown files.
- You need to understand what types of files are available.
- You want to find the most promising files to investigate first.

## Key tools

- list_files for recursive file listing with sizes.
- inspect_file for metadata, type, hash, content preview.
- calculate_file_hash for MD5, SHA-1, SHA-256, SHA-512.
- read_text_file for safe text file reading.
- search_files for finding flag patterns or keywords.

## Workflow

1. Run list_files to see everything available.
2. Run inspect_file on each file to determine type.
3. Calculate SHA-256 hashes for all files.
4. Read text files first; inspect binary files with tools.
5. Search for flag patterns or relevant keywords.

## Common pitfalls

- Skipping binary file inspection.
- Not recording hashes for later comparison.
- Reading binary files as text (use inspect_file first).
