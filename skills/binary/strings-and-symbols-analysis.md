---
name: Strings and Symbols Analysis
identifier: strings-and-symbols-analysis
category: binary
description: Guide for analyzing strings and symbols in binary challenges.
difficulty: easy
applicable_challenge_types:
  - binary
trigger_keywords:
  - strings
  - symbols
  - nm
  - function
  - variable
  - flag
  - password
  - secret
required_tools:
  - run_ctf_command
optional_tools:
  - search_files
  - decode_data
prerequisites:
  - binary-triage
investigation_steps:
  - title: Extract all readable strings
    description: Use run_ctf_command with strings to find all readable text in the binary.
  - title: Search for flag patterns in strings
    description: Use search_files or grep the strings output for flag{ patterns.
  - title: Analyze symbol table
    description: Use nm or objdump -t to list exported and imported symbols.
  - title: Identify interesting functions
    description: Look for functions like main, win, login, check, verify, flag, auth.
  - title: Search for hardcoded values
    description: Use strings and grep to find hardcoded passwords, keys, or URLs.
evidence_requirements:
  - title: Strings extracted
    description: All readable strings from the binary must be examined.
  - title: Symbols documented
    description: Key symbols (functions, variables) must be recorded.
success_criteria:
  - title: Strings and symbols analyzed
    description: All readable strings and key symbols have been documented.
stopping_conditions:
  - title: Analysis complete
    description: Stop once strings and symbols have been fully analyzed.
safety_notes:
  - title: Do not execute the binary
    description: Use strings and nm tools; do not run the binary.
common_mistakes:
  - title: Not searching for flag patterns in strings
    description: Always grep strings output for flag{ patterns.
  - title: Ignoring the symbol table
    description: nm and objdump -t reveal function names that guide further analysis.
version: 1.0.0
---

# Strings and Symbols Analysis

This skill guides you through analyzing strings and symbols in binary files.

## When to use

- You have a binary file and need to understand its contents.
- You want to find hardcoded values, functions, or strings.
- You are starting a binary exploitation challenge.

## Key tools

- run_ctf_command for strings, nm, objdump -t.
- search_files for searching strings output for patterns.

## Workflow

1. Run `strings` on the binary to extract readable text.
2. Search strings output for flag patterns and hardcoded values.
3. Run `nm` or `objdump -t` to list symbols.
4. Identify interesting functions (main, win, login, check, flag).
5. Document all findings.

## Common pitfalls

- Not searching strings output for flag patterns.
- Ignoring the symbol table.
- Not looking for hardcoded passwords or keys.
