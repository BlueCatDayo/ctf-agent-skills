---
name: Source Code Review
identifier: source-code-review
category: common
description: Guide for systematic source code analysis in CTF challenges.
difficulty: medium
applicable_challenge_types:
  - web
  - binary
  - forensics
trigger_keywords:
  - source code
  - review
  - analyze
  - code
  - inspect
  - read
required_tools:
  - read_text_file
  - search_files
optional_tools:
  - list_files
  - inspect_file
  - decode_data
prerequisites: []
investigation_steps:
  - title: Identify source files
    description: Find all source code files (.py, .js, .php, .c, .html, .java, .rb, .go, .rs).
  - title: Read each source file
    description: Use read_text_file to examine source code for logic, comments, and hidden functionality.
  - title: Search for dangerous patterns
    description: Use search_files for eval, exec, system, subprocess, shell, os.system, pickle, yaml.load.
  - title: Check for hardcoded secrets
    description: Search for password, secret, key, token, api_key in source files.
  - title: Review control flow
    description: Trace the main execution path and identify conditional branches.
  - title: Look for hidden functionality
    description: Check for commented-out code, debug endpoints, backdoors, or Easter eggs.
evidence_requirements:
  - title: Source files identified and read
    description: All relevant source files must be examined.
  - title: Dangerous patterns documented
    description: Any dangerous function calls or patterns must be recorded.
success_criteria:
  - title: Source code fully reviewed
    description: All source files have been read and analyzed for vulnerabilities.
stopping_conditions:
  - title: Source review complete
    description: Stop once all source files have been read and analyzed.
safety_notes:
  - title: Do not execute source code
    description: Read source code only; do not run it.
  - title: Watch for obfuscation
    description: Some challenges use obfuscated or minified code; decode before reviewing.
common_mistakes:
  - title: Skipping comments and debug code
    description: Hidden functionality is often in comments or debug branches.
  - title: Not searching for dangerous patterns
    description: eval, exec, and system calls are common vulnerability sources.
version: 1.0.0
---

# Source Code Review

This skill guides you through systematic source code analysis.

## When to use

- Source code files are available in the challenge.
- You need to understand application logic.
- You want to find vulnerabilities in the code.

## Workflow

1. Find all source files with list_files and search_files.
2. Read each file with read_text_file.
3. Search for dangerous patterns (eval, exec, system, subprocess).
4. Search for hardcoded secrets.
5. Review control flow and conditional branches.
6. Look for hidden functionality in comments and debug code.

## Common pitfalls

- Skipping comments and debug code.
- Not searching for dangerous function calls.
- Not checking for obfuscated or minified code.
