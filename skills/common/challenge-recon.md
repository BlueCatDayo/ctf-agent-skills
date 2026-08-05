---
name: Challenge Reconnaissance
identifier: challenge-recon
category: common
description: Guide for initial challenge assessment and information gathering.
difficulty: easy
applicable_challenge_types:
  - web
  - binary
  - forensics
trigger_keywords:
  - recon
  - assess
  - explore
  - overview
  - survey
  - initial
required_tools:
  - list_files
  - inspect_file
  - search_files
optional_tools:
  - read_text_file
  - calculate_file_hash
  - decode_data
  - http_request
  - inspect_webpage
prerequisites: []
investigation_steps:
  - title: Read challenge metadata
    description: Check for challenge.json or description files that specify category, target, and authorization.
  - title: List all available files
    description: Use list_files to understand the challenge structure.
  - title: Identify file types
    description: Use inspect_file on each file to categorize them.
  - title: Search for clues
    description: Use search_files for keywords like flag, password, secret, key, admin.
  - title: Assess the attack surface
    description: Based on file types and challenge description, identify likely vulnerability classes.
evidence_requirements:
  - title: Challenge metadata reviewed
    description: Challenge description, category, and target are documented.
  - title: File inventory complete
    description: All files in the workspace have been listed and categorized.
success_criteria:
  - title: Reconnaissance complete
    description: You have a clear picture of the challenge structure, file types, and likely attack vectors.
stopping_conditions:
  - title: Reconnaissance complete
    description: Stop once you have a complete file inventory and understand the challenge structure.
safety_notes:
  - title: Do not execute unknown files
    description: Inspect binaries with tools, do not run them.
  - title: Confirm authorization
    description: Ensure the challenge is authorized before active exploitation.
common_mistakes:
  - title: Jumping to exploitation too early
    description: Complete reconnaissance before attempting any exploitation.
  - title: Ignoring challenge metadata
    description: challenge.json often contains critical information about the target.
version: 1.0.0
---

# Challenge Reconnaissance

This skill guides you through initial challenge assessment.

## When to use

- Starting a new challenge.
- You need to understand the challenge structure before investigating.
- You want a systematic approach to information gathering.

## Workflow

1. Read challenge metadata (challenge.json, description).
2. List all files with list_files.
3. Inspect each file with inspect_file.
4. Search for clues with search_files.
5. Assess the attack surface based on findings.

## Common pitfalls

- Skipping recon and jumping straight to exploitation.
- Ignoring challenge metadata files.
- Not cataloguing all files before starting investigation.
