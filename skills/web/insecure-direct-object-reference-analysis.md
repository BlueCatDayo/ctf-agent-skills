---
name: Insecure Direct Object Reference Analysis
identifier: insecure-direct-object-reference-analysis
category: web
description: Guide for analyzing IDOR vulnerabilities in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - IDOR
  - direct object reference
  - object ID
  - resource ID
  - user ID
  - account ID
required_tools:
  - http_request
  - compare_http_responses
optional_tools:
  - manage_http_session
  - inspect_webpage
prerequisites: []
investigation_steps:
  - title: Identify resource IDs in requests
    description: Find all parameters that reference objects (user IDs, file IDs, account numbers).
  - title: Test IDOR by modifying IDs
    description: Try accessing other users or objects resources by modifying the ID parameter.
  - title: Compare responses
    description: Use compare_http_responses to detect differences between authorized and unauthorized access.
  - title: Test sequential IDs
    description: Try incrementing or decrementing numeric IDs to access other resources.
evidence_requirements:
  - title: IDOR confirmed
    description: Access to another user or object data must be visible in tool output.
  - title: Vulnerable parameter identified
    description: The parameter that allows IDOR must be documented.
success_criteria:
  - title: IDOR confirmed with evidence
    description: An insecure direct object reference vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: IDOR confirmed
    description: Stop once IDOR is confirmed; do not attempt to access more resources than necessary.
safety_notes:
  - title: Only test within the challenge scope
    description: Do not access resources outside the challenge.
  - title: Use read-only testing
    description: Prefer GET requests; avoid modifying other users data.
common_mistakes:
  - title: Not comparing responses systematically
    description: Always compare responses to distinguish authorized from unauthorized access.
  - title: Testing only one ID value
    description: Try multiple ID values (sequential, random, other user IDs).
version: 1.0.0
---

# Insecure Direct Object Reference Analysis

This skill guides you through analyzing IDOR vulnerabilities.

## When to use

- A challenge has resource IDs in URLs or parameters.
- You want to find IDOR vulnerabilities.
- Parameters reference objects (users, files, accounts).

## Key tools

- http_request for requests with modified IDs.
- compare_http_responses for detecting differences in responses.
- manage_http_session for managing multiple user sessions.

## Workflow

1. Identify resource IDs in request parameters.
2. Test by modifying IDs to access other resources.
3. Compare responses to detect unauthorized access.
4. If confirmed, stop and report the finding.

## Common pitfalls

- Not comparing responses systematically.
- Testing only one ID value.
- Modifying other users data instead of reading it.
