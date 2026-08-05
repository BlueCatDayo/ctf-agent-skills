---
name: Path and Endpoint Discovery
identifier: path-and-endpoint-discovery
category: web
description: Guide for discovering hidden paths and API endpoints in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - endpoint
  - path
  - API
  - route
  - directory
  - hidden
  - discover
  - enum
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - extract_web_elements
  - compare_http_responses
  - search_files
prerequisites: []
investigation_steps:
  - title: Extract API routes from page
    description: Use inspect_webpage to find possible API routes from script references and inline code.
  - title: Extract all links
    description: Use extract_web_elements to find all links and form actions.
  - title: Test common API paths
    description: Use http_request to probe common API paths like /api, /api/v1, /admin, /debug.
  - title: Compare responses
    description: Use compare_http_responses to detect differences between existing and non-existing paths.
  - title: Check for directory listing
    description: Try accessing directories without trailing slashes or with /index.html omitted.
evidence_requirements:
  - title: Endpoints documented
    description: All discovered endpoints and their response characteristics must be recorded.
  - title: Hidden endpoints found
    description: At least one previously unknown endpoint must be discovered.
success_criteria:
  - title: Endpoint discovery complete
    description: All accessible endpoints have been discovered and documented.
stopping_conditions:
  - title: Endpoint discovery complete
    description: Stop once all endpoints have been found and tested.
safety_notes:
  - title: Do not use automated directory brute-forcing
    description: Test common paths manually; do not send large wordlists.
  - title: Respect rate limits
    description: Space out requests to avoid overwhelming the target.
common_mistakes:
  - title: Not comparing responses systematically
    description: Always compare responses to distinguish real endpoints from 404s.
  - title: Only testing the main page
    description: Hidden endpoints are often found in linked resources, not the main page.
version: 1.0.0
---

# Path and Endpoint Discovery

This skill guides you through discovering hidden paths and API endpoints.

## When to use

- You need to find hidden API endpoints or directories.
- A web challenge has multiple pages or resources.
- You want to map the full application surface.

## Key tools

- inspect_webpage for API routes and script references.
- extract_web_elements for all links and form actions.
- http_request for manual path probing.
- compare_http_responses for distinguishing real endpoints from 404s.

## Workflow

1. Extract API routes from the page with inspect_webpage.
2. Find all links with extract_web_elements.
3. Test common API paths manually with http_request.
4. Compare responses to distinguish real endpoints from 404s.
5. Check for directory listing and hidden resources.

## Common pitfalls

- Not comparing responses systematically.
- Only testing the main page URL.
- Using automated brute-forcing instead of manual testing.
