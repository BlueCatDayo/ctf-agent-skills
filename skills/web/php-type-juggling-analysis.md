---
name: PHP Type Juggling Analysis
identifier: php-type-juggling-analysis
category: web
description: Detect PHP loose comparison (==) type-juggling bypasses with 0e hashes and arrays.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - PHP
  - type juggling
  - loose comparison
  - md5
  - sha1
  - 0e
  - ==
required_tools:
  - read_text_file
  - search_files
optional_tools:
  - http_post
prerequisites: []
investigation_steps:
  - title: Find hash comparisons
    description: Search PHP source for == comparisons of md5/sha1 results and '0e...' strings.
  - title: Test 0e collision
    description: If a hash string starts with 0e followed by digits, PHP == treats it as 0 - verify with an authorized request.
  - title: Test array bypass
    description: Passing an array (e.g. password[]=) makes many hash functions return null - verify behavior.
  - title: Record the comparison
    description: Note the exact code location (file + line) as evidence.
evidence_requirements:
  - title: Code located
    description: The loose comparison must be seen in source or tool output.
  - title: Bypass verified
    description: The altered request must produce a different access result in tool output.
success_criteria:
  - title: Bypass confirmed
    description: A verified 0e or array bypass succeeded in tool output.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: No invented hashes
    description: Only use known 0e-collision strings or arrays; never fabricate hash values.
common_mistakes:
  - title: Assuming == is the issue
    description: Confirm the comparison is loose (==) not strict (===) in the actual source.
version: 1.0.0
---

# PHP Type Juggling Analysis

## When to use

- PHP apps comparing hashes with ==, challenges mentioning 0e strings.

## Key tools

- search_files for '==' and 'md5('/'sha1('.
- http_post to verify a bypass.

## Workflow

1. Locate the loose comparison in source.
2. Identify 0e hashes or array-compatible parameters.
3. Verify with an authorized request.
4. Report only confirmed bypasses.
