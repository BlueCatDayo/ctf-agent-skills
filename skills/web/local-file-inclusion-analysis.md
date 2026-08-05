---
name: Local File Inclusion Analysis
identifier: local-file-inclusion-analysis
category: web
description: Guide for analyzing local file inclusion vulnerabilities in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - LFI
  - local file inclusion
  - file include
  - include
  - require
  - template
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - compare_http_responses
  - decode_data
prerequisites: []
investigation_steps:
  - title: Identify file inclusion points
    description: Find parameters that control which file is included or rendered by the server.
  - title: Test for LFI with safe payloads
    description: Send minimal LFI payloads (e.g., known file paths); use compare_http_responses to detect differences.
  - title: Analyze inclusion output
    description: Check if file contents are included in responses.
  - title: Test for log poisoning
    description: Try injecting into logs that are later included by the application.
evidence_requirements:
  - title: LFI confirmed
    description: File contents must be visible in tool output.
  - title: Inclusion point identified
    description: The parameter that controls file inclusion must be documented.
success_criteria:
  - title: LFI confirmed with evidence
    description: A local file inclusion vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: LFI confirmed
    description: Stop once LFI is confirmed; do not attempt further exploitation.
safety_notes:
  - title: Use minimal, targeted payloads only
    description: Do not send large sets of LFI payloads.
  - title: Do not attempt to read sensitive system files
    description: Only read files within the challenge scope.
  - title: Report only confirmed findings
    description: An LFI is only confirmed if tool output shows file contents.
common_mistakes:
  - title: Confusing LFI with RFI
    description: LFI includes local files; RFI includes remote files. They are different vulnerabilities.
  - title: Not testing log poisoning
    description: Log poisoning is a common LFI vector that is often overlooked.
version: 1.0.0
---

# Local File Inclusion Analysis

This skill guides you through analyzing local file inclusion vulnerabilities.

## When to use

- A challenge involves server-side file inclusion (PHP include/require, Python import, etc.).
- You want to find LFI vulnerabilities.
- Parameters control which file is included by the server.

## Key tools

- http_request for LFI payloads to file path parameters.
- inspect_webpage for inclusion points.
- compare_http_responses for detecting differences caused by inclusion.

## Workflow

1. Identify parameters that control file inclusion on the server.
2. Test with minimal LFI payloads.
3. Analyze file contents in responses.
4. If confirmed, stop and report the finding.

## Common pitfalls

- Confusing LFI with RFI (remote file inclusion).
- Not testing log poisoning as an LFI vector.
- Attempting to read sensitive system files outside the challenge scope.
