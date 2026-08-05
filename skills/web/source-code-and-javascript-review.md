---
name: Source Code and JavaScript Review
identifier: source-code-and-javascript-review
category: web
description: Guide for reviewing client-side JavaScript and source code in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - javascript
  - JS
  - client-side
  - source code
  - review
  - frontend
  - script
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - extract_web_elements
  - decode_data
  - run_ctf_command
prerequisites: []
investigation_steps:
  - title: Extract all scripts
    description: Use inspect_webpage or extract_web_elements to find all JavaScript files and inline scripts.
  - title: Fetch JavaScript files
    description: Use http_request to download external JS files referenced by the page.
  - title: Review inline scripts
    description: Inspect inline script content for sensitive logic, hidden endpoints, or encoded data.
  - title: Search for secrets in JS
    description: Use search_files or decode_data to find API keys, endpoints, or tokens in JavaScript.
  - title: Analyze client-side validation
    description: Check if security checks are only performed client-side and can be bypassed.
  - title: Look for hidden endpoints
    description: Search for API routes, debug endpoints, or hidden functionality in JS code.
evidence_requirements:
  - title: JavaScript files retrieved
    description: All referenced JS files must be downloaded and reviewed.
  - title: Sensitive logic documented
    description: Any client-side security logic or hidden endpoints must be recorded.
success_criteria:
  - title: JavaScript fully reviewed
    description: All JavaScript code has been examined for vulnerabilities and hidden functionality.
stopping_conditions:
  - title: JavaScript review complete
    description: Stop once all JS files and inline scripts have been reviewed.
safety_notes:
  - title: Do not execute JavaScript
    description: Review JavaScript code only; do not run it in a browser.
  - title: Client-side checks are not security
    description: Always verify security on the server side; client-side checks can be bypassed.
common_mistakes:
  - title: Not fetching external JS files
    description: External scripts often contain critical logic or hidden endpoints.
  - title: Ignoring inline scripts
    description: Inline scripts may contain sensitive data or hidden functionality.
version: 1.0.0
---

# Source Code and JavaScript Review

This skill guides you through reviewing client-side JavaScript and source code.

## When to use

- JavaScript files are available or referenced by the web challenge.
- You need to understand client-side logic.
- You want to find hidden endpoints or API routes.

## Key tools

- inspect_webpage for scripts and API routes.
- extract_web_elements for script tags and inline scripts.
- http_request for downloading external JS files.
- decode_data for decoding encoded content in JS.

## Workflow

1. Extract all scripts from the page with inspect_webpage.
2. Download external JS files with http_request.
3. Review inline scripts for sensitive logic.
4. Search for API keys, endpoints, or tokens in JS code.
5. Analyze client-side validation for bypass opportunities.
6. Look for hidden endpoints in JS code.

## Common pitfalls

- Not fetching external JavaScript files.
- Ignoring inline scripts.
- Trusting client-side security checks.
