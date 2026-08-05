---
name: Server-Side Request Forgery Analysis
identifier: server-side-request-forgery-analysis
category: web
description: Guide for analyzing SSRF vulnerabilities in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - SSRF
  - server-side request
  - fetch URL
  - proxy
  - webhook
  - internal network
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - compare_http_responses
  - manage_http_session
prerequisites: []
investigation_steps:
  - title: Identify URL fetch functionality
    description: Find parameters that control server-side HTTP requests (webhooks, proxies, URL fetchers).
  - title: Test for SSRF with safe targets
    description: Send requests to internal endpoints (e.g., http://127.0.0.1, http://localhost) to test if the server fetches them.
  - title: Analyze response differences
    description: Use compare_http_responses to detect differences that indicate SSRF.
  - title: Test for metadata endpoint access
    description: Try accessing cloud metadata endpoints (only if explicitly authorized in the challenge).
evidence_requirements:
  - title: SSRF confirmed
    description: Internal server response must be visible in tool output.
  - title: URL fetch point identified
    description: The parameter that controls server-side requests must be documented.
success_criteria:
  - title: SSRF confirmed with evidence
    description: A server-side request forgery vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: SSRF confirmed
    description: Stop once SSRF is confirmed; do not attempt further exploitation.
safety_notes:
  - title: Only test authorized targets
    description: Do not test SSRF against targets outside the challenge scope.
  - title: Use safe, minimal payloads
    description: Do not send large sets of SSRF payloads.
  - title: Report only confirmed findings
    description: SSRF is only confirmed if tool output shows an internal server response.
common_mistakes:
  - title: Testing against non-authorized targets
    description: Only test SSRF against targets explicitly authorized in the challenge.
  - title: Not comparing responses carefully
    description: SSRF differences can be subtle; use compare_http_responses.
version: 1.0.0
---

# Server-Side Request Forgery Analysis

This skill guides you through analyzing SSRF vulnerabilities.

## When to use

- A challenge involves server-side URL fetching.
- You want to find SSRF vulnerabilities.
- Parameters control server-side HTTP requests.

## Key tools

- http_request for requests to internal endpoints from the server perspective.
- inspect_webpage for URL fetch functionality.
- compare_http_responses for detecting differences caused by SSRF.

## Workflow

1. Identify parameters that control server-side HTTP requests.
2. Test with safe internal targets (localhost, 127.0.0.1).
3. Compare responses to detect SSRF.
4. If confirmed, stop and report the finding.

## Common pitfalls

- Testing against non-authorized targets.
- Not comparing responses carefully enough.
- Sending large sets of SSRF payloads instead of minimal, targeted ones.
