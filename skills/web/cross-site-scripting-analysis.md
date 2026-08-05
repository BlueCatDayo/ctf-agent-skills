---
name: Cross-Site Scripting Analysis
identifier: cross-site-scripting-analysis
category: web
description: Guide for analyzing XSS vulnerabilities in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - XSS
  - cross-site scripting
  - script injection
  - HTML injection
  - JavaScript injection
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - compare_http_responses
  - extract_web_elements
prerequisites: []
investigation_steps:
  - title: Identify user input points
    description: Find all parameters that influence page content (forms, URL params, headers, cookies).
  - title: Test for reflected XSS
    description: Send minimal, safe XSS payloads to input points; use compare_http_responses to detect reflection.
  - title: Test for stored XSS
    description: If the application stores input, submit a safe payload and check if it is reflected later.
  - title: Analyze response encoding
    description: Check if input is properly encoded or sanitized in responses.
evidence_requirements:
  - title: XSS confirmed
    description: Script injection must be visible in tool output (not just in a skill suggestion).
  - title: Input point identified
    description: The vulnerable parameter must be documented.
success_criteria:
  - title: XSS confirmed with evidence
    description: An XSS vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: XSS confirmed
    description: Stop once XSS is confirmed; do not attempt further exploitation.
safety_notes:
  - title: Use minimal, safe payloads only
    description: Do not send malicious JavaScript payloads.
  - title: Report only confirmed findings
    description: XSS is only confirmed if tool output shows script injection.
common_mistakes:
  - title: Confusing XSS with SSTI
    description: XSS is client-side; SSTI is server-side. They are different vulnerabilities.
  - title: Not checking for output encoding
    description: Proper encoding prevents XSS; check if input is encoded in responses.
version: 1.0.0
---

# Cross-Site Scripting Analysis

This skill guides you through analyzing XSS vulnerabilities.

## When to use

- A challenge involves user input reflected in HTML pages.
- You want to find XSS vulnerabilities.
- Input points influence page content.

## Key tools

- http_request for safe XSS payloads to input points.
- inspect_webpage for input points and reflected content.
- compare_http_responses for detecting differences caused by injection.

## Workflow

1. Identify all user input points (forms, URL params, headers, cookies).
2. Test for reflected XSS with minimal, safe payloads.
3. Test for stored XSS if input is persisted.
4. Analyze response encoding and sanitization.
5. If confirmed, stop and report the finding.

## Common pitfalls

- Confusing XSS with SSTI (they are different).
- Not checking for output encoding in responses.
- Sending malicious payloads instead of safe, minimal ones.
