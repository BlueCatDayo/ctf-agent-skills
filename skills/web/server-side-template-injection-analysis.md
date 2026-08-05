---
name: Server-Side Template Injection Analysis
identifier: server-side-template-injection-analysis
category: web
description: Guide for analyzing server-side template injection vulnerabilities in web challenges.
difficulty: hard
applicable_challenge_types:
  - web
trigger_keywords:
  - SSTI
  - template injection
  - Jinja
  - Twig
  - template
  - render
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - compare_http_responses
  - decode_data
prerequisites: []
investigation_steps:
  - title: Identify template rendering points
    description: Find all user inputs that are rendered in templates or passed to template engines.
  - title: Test for SSTI with safe payloads
    description: Send minimal, safe template injection payloads; use compare_http_responses to detect differences.
  - title: Analyze response differences
    description: Check if template rendering differences reveal SSTI.
  - title: Confirm with tool output
    description: Only report SSTI if tool output shows template rendering artifacts.
evidence_requirements:
  - title: SSTI confirmed
    description: Template rendering artifacts must be visible in tool output.
  - title: Input point identified
    description: The vulnerable parameter must be documented.
success_criteria:
  - title: SSTI confirmed with evidence
    description: A server-side template injection vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: SSTI confirmed
    description: Stop once SSTI is confirmed; do not attempt further exploitation.
safety_notes:
  - title: Use minimal, safe payloads only
    description: Do not send destructive template injection payloads.
  - title: Report only confirmed findings
    description: SSTI is only confirmed if tool output shows template rendering artifacts.
common_mistakes:
  - title: Confusing SSTI with XSS
    description: SSTI occurs server-side; XSS occurs client-side. They are different vulnerabilities.
  - title: Not comparing responses carefully
    description: SSTI differences can be subtle; use compare_http_responses.
version: 1.0.0
---

# Server-Side Template Injection Analysis

This skill guides you through analyzing SSTI vulnerabilities.

## When to use

- A challenge involves template rendering (Jinja, Twig, etc.).
- You want to find server-side template injection vulnerabilities.
- User input is passed to a template engine.

## Key tools

- http_request for targeted payloads to input points.
- inspect_webpage for template rendering points.
- compare_http_responses for subtle differences in responses.

## Workflow

1. Identify template rendering points in the application.
2. Test with minimal, safe SSTI payloads.
3. Compare responses to detect rendering differences.
4. Confirm findings with tool output.

## Common pitfalls

- Confusing SSTI with XSS (they are different).
- Not comparing responses carefully enough.
- Using destructive payloads instead of safe, minimal ones.
