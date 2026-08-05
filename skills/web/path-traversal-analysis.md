---
name: Path Traversal Analysis
identifier: path-traversal-analysis
category: web
description: Guide for analyzing path traversal vulnerabilities in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - path traversal
  - directory traversal
  - file read
  - ../
  - file inclusion
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - compare_http_responses
  - decode_data
prerequisites: []
investigation_steps:
  - title: Identify file read functionality
    description: Find parameters that influence file paths on the server.
  - title: Test for path traversal
    description: Send minimal path traversal payloads (../) to file path parameters; use compare_http_responses to detect differences.
  - title: Analyze file read output
    description: Check if file contents are returned in responses.
  - title: Test for restricted file access
    description: Try reading common system files to test if path traversal is possible.
evidence_requirements:
  - title: Path traversal confirmed
    description: File contents must be visible in tool output.
  - title: Vulnerable parameter identified
    description: The parameter that allows path traversal must be documented.
success_criteria:
  - title: Path traversal confirmed with evidence
    description: A path traversal vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: Path traversal confirmed
    description: Stop once path traversal is confirmed; do not attempt to read sensitive system files.
safety_notes:
  - title: Use minimal, targeted payloads only
    description: Do not send large sets of path traversal payloads.
  - title: Do not attempt to read sensitive system files
    description: Only read files within the challenge scope.
  - title: Report only confirmed findings
    description: A path traversal is only confirmed if tool output shows file contents.
common_mistakes:
  - title: Not URL-encoding traversal sequences
    description: Some filters check for ../ but not %2e%2e%2f.
  - title: Ignoring double-encoding
    description: Some filters can be bypassed with double URL encoding.
version: 1.0.0
---

# Path Traversal Analysis

This skill guides you through analyzing path traversal vulnerabilities.

## When to use

- A challenge involves file reading from user-supplied paths.
- You want to find path traversal vulnerabilities.
- Parameters influence file system paths on the server.

## Key tools

- http_request for path traversal payloads to file path parameters.
- inspect_webpage for file path input points.
- compare_http_responses for detecting differences caused by traversal.

## Workflow

1. Identify parameters that influence file paths on the server.
2. Test with minimal path traversal payloads (../).
3. Analyze file read output in responses.
4. If confirmed, stop and report the finding.

## Common pitfalls

- Not URL-encoding traversal sequences.
- Ignoring double-encoding bypasses.
- Attempting to read sensitive system files outside the challenge scope.
