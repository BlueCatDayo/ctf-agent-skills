---
name: Web Reconnaissance
identifier: web-reconnaissance
category: web
description: Guide for systematic web application reconnaissance in CTF challenges.
difficulty: easy
applicable_challenge_types:
  - web
trigger_keywords:
  - web
  - reconnaissance
  - discover
  - enumerate
  - map
  - endpoints
  - directories
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - extract_web_elements
  - compare_http_responses
  - manage_http_session
  - run_ctf_command
prerequisites: []
investigation_steps:
  - title: Identify the target
    description: Confirm the target URL and ensure it is an authorized CTF challenge.
  - title: Perform a safe GET request
    description: Use http_request with GET to the target URL and inspect the response.
  - title: Inspect the webpage
    description: Use inspect_webpage to extract title, technologies, forms, scripts, and API routes.
  - title: Extract links and endpoints
    description: Use extract_web_elements to find all links and possible API endpoints.
  - title: Compare authenticated vs unauthenticated responses
    description: Use compare_http_responses to identify differences that reveal hidden functionality.
  - title: Map the application structure
    description: Document all discovered endpoints, forms, and parameters.
evidence_requirements:
  - title: Target URL verified as authorized
    description: The target must be confirmed as an authorized CTF challenge before testing.
  - title: Endpoints documented
    description: All discovered endpoints and their response characteristics must be recorded.
success_criteria:
  - title: Reconnaissance complete
    description: A complete map of the web application has been created.
stopping_conditions:
  - title: Reconnaissance complete
    description: Stop once all endpoints and functionality have been mapped.
safety_notes:
  - title: Start with low-impact requests
    description: Use GET, HEAD, and OPTIONS before any state-changing requests.
  - title: Do not flood the target
    description: Avoid sending large numbers of requests in a short time.
  - title: Confirm authorization
    description: Only test targets the user identifies as authorized CTF challenges.
common_mistakes:
  - title: Skipping recon and jumping to exploitation
    description: Always map the application before attempting exploitation.
  - title: Not comparing authenticated and unauthenticated responses
    description: Differences often reveal hidden functionality.
version: 1.0.0
---

# Web Reconnaissance

This skill guides you through systematic web application reconnaissance.

## When to use

- Starting a new web challenge.
- You need to understand the application structure.
- You want to map all endpoints and functionality.

## Key tools

- http_request for safe GET/POST/HEAD/OPTIONS requests.
- inspect_webpage for title, technologies, forms, scripts, API routes.
- extract_web_elements for links, forms, inputs, hidden fields.
- compare_http_responses for authenticated vs unauthenticated comparisons.

## Workflow

1. Confirm the target is an authorized CTF challenge.
2. Send a safe GET request to the target URL.
3. Use inspect_webpage to extract page structure.
4. Use extract_web_elements to find links and endpoints.
5. Compare authenticated and unauthenticated responses.
6. Document all discovered endpoints and parameters.

## Common pitfalls

- Skipping recon and jumping straight to exploitation.
- Not comparing authenticated and unauthenticated responses.
- Sending too many requests too quickly.
