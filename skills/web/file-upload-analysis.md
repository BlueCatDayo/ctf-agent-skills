---
name: File Upload Analysis
identifier: file-upload-analysis
category: web
description: Guide for analyzing file upload functionality in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - upload
  - file upload
  - multipart
  - file type
  - extension
  - mime
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - extract_web_elements
  - compare_http_responses
  - manage_http_session
prerequisites: []
investigation_steps:
  - title: Find the upload form
    description: Use inspect_webpage and extract_web_elements to locate file upload forms.
  - title: Analyze upload restrictions
    description: Check for file type restrictions, size limits, and server-side validation.
  - title: Test for extension bypass
    description: Try common extension bypass techniques (double extensions, case changes, null bytes).
  - title: Test for content-type bypass
    description: Try sending files with mismatched content-type headers.
  - title: Compare responses
    description: Use compare_http_responses to detect differences in upload handling.
evidence_requirements:
  - title: Upload mechanism documented
    description: The upload form, restrictions, and handling must be recorded.
  - title: Bypass attempts documented
    description: All upload bypass attempts and their results must be recorded.
success_criteria:
  - title: File upload analyzed
    description: The file upload mechanism has been fully analyzed for weaknesses.
stopping_conditions:
  - title: File upload analyzed
    description: Stop once the upload mechanism has been fully tested.
safety_notes:
  - title: Do not upload malicious files
    description: Only test with safe, minimal payloads; do not upload actual malware.
  - title: Do not attempt to overwrite critical files
    description: Only test upload functionality within the challenge scope.
common_mistakes:
  - title: Not testing extension bypasses
    description: Double extensions and case changes are common bypass techniques.
  - title: Ignoring server-side validation
    description: Client-side restrictions can often be bypassed; always test server-side validation.
version: 1.0.0
---

# File Upload Analysis

This skill guides you through analyzing file upload functionality.

## When to use

- A challenge has a file upload feature.
- You want to find file upload vulnerabilities.
- You need to test upload restrictions.

## Key tools

- http_request for file upload requests.
- inspect_webpage for upload forms.
- extract_web_elements for upload input fields.
- compare_http_responses for comparing upload responses.

## Workflow

1. Find the upload form with inspect_webpage and extract_web_elements.
2. Analyze upload restrictions (file type, size, validation).
3. Test for extension bypass techniques.
4. Test for content-type header manipulation.
5. Compare responses to detect differences.

## Common pitfalls

- Not testing extension bypasses.
- Ignoring server-side validation (client-side can be bypassed).
- Uploading actual malicious files instead of safe test payloads.
