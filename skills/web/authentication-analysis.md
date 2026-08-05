---
name: Authentication Analysis
identifier: authentication-analysis
category: web
description: Guide for analyzing authentication mechanisms in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - auth
  - login
  - password
  - session
  - cookie
  - token
  - credential
  - register
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - extract_web_elements
  - compare_http_responses
  - manage_http_session
  - decode_data
prerequisites: []
investigation_steps:
  - title: Identify the login mechanism
    description: Find the login form, endpoint, and parameters using inspect_webpage and extract_web_elements.
  - title: Analyze the login form
    description: Check for username, password, CSRF token, and other fields.
  - title: Test for common weaknesses
    description: Check for default credentials, visible password rules, and client-side validation only.
  - title: Inspect session handling
    description: Use manage_http_session to examine cookies and session tokens.
  - title: Analyze token generation
    description: Use decode_data if tokens appear encoded; check for predictable patterns.
  - title: Test registration flow
    description: If registration is available, test for weak password policies and information disclosure.
evidence_requirements:
  - title: Login mechanism identified
    description: The login endpoint, parameters, and form fields must be documented.
  - title: Session handling analyzed
    description: Cookie attributes, session token format, and expiration must be recorded.
success_criteria:
  - title: Authentication mechanism understood
    description: The authentication flow has been fully mapped and weaknesses identified.
stopping_conditions:
  - title: Authentication mechanism understood
    description: Stop once the login flow and session handling are fully documented.
safety_notes:
  - title: Do not brute-force credentials
    description: Testing for default credentials is allowed; do not send large credential lists.
  - title: Use generated test credentials only
    description: Do not use real personal credentials in CTF challenges.
common_mistakes:
  - title: Ignoring CSRF tokens
    description: Missing CSRF tokens are a common weakness; always check for them.
  - title: Not inspecting cookie attributes
    description: HttpOnly, Secure, and SameSite attributes affect session security.
version: 1.0.0
---

# Authentication Analysis

This skill guides you through analyzing authentication mechanisms.

## When to use

- A challenge involves login, registration, or session management.
- You need to understand how authentication works.
- You want to find authentication weaknesses.

## Key tools

- http_request for login/registration requests.
- inspect_webpage for login forms and fields.
- extract_web_elements for form inputs and hidden fields.
- manage_http_session for cookie inspection.
- decode_data for token decoding.

## Workflow

1. Find the login form with inspect_webpage and extract_web_elements.
2. Analyze form fields (username, password, CSRF token).
3. Test for common weaknesses (default creds, client-side only validation).
4. Inspect session cookies with manage_http_session.
5. Analyze token format for predictability.
6. Test registration flow for weaknesses.

## Common pitfalls

- Ignoring CSRF tokens.
- Not inspecting cookie attributes (HttpOnly, Secure, SameSite).
- Brute-forcing credentials instead of analyzing the mechanism.
