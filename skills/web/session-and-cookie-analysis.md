---
name: Session and Cookie Analysis
identifier: session-and-cookie-analysis
category: web
description: Guide for analyzing session management and cookie security.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - session
  - cookie
  - cookie security
  - session token
  - JWT
  - session fixation
  - session hijacking
required_tools:
  - http_request
  - manage_http_session
optional_tools:
  - inspect_webpage
  - extract_web_elements
  - decode_data
prerequisites: []
investigation_steps:
  - title: Examine session cookies
    description: Use manage_http_session show to inspect cookies received from the server.
  - title: Analyze cookie attributes
    description: Check for HttpOnly, Secure, SameSite, and Domain attributes.
  - title: Test session fixation
    description: Try setting a known session cookie before login and check if it persists after authentication.
  - title: Analyze session token format
    description: Use decode_data if tokens appear encoded; check for predictability.
  - title: Test cookie scope
    description: Try sending cookies to different paths or subdomains.
  - title: Check for session termination
    description: Verify that sessions are properly invalidated on logout.
evidence_requirements:
  - title: Cookie attributes documented
    description: All cookie attributes (HttpOnly, Secure, SameSite, Domain, Path) must be recorded.
  - title: Session behavior verified
    description: Session creation, persistence, and termination behavior must be confirmed.
success_criteria:
  - title: Session mechanism understood
    description: The session management mechanism has been fully analyzed.
stopping_conditions:
  - title: Session analysis complete
    description: Stop once all cookie and session attributes have been documented.
safety_notes:
  - title: Do not hijack other users sessions
    description: Session analysis should be passive; do not use other users session tokens.
  - title: Mask sensitive cookie values
    description: Use manage_http_session show to safely display cookie values.
common_mistakes:
  - title: Ignoring cookie attributes
    description: HttpOnly and Secure flags are critical for cookie security.
  - title: Not testing session termination
    description: Sessions that are not properly invalidated are a common weakness.
version: 1.0.0
---

# Session and Cookie Analysis

This skill guides you through analyzing session management and cookie security.

## When to use

- A challenge involves login sessions or cookies.
- You want to find session management weaknesses.
- You need to understand how sessions are handled.

## Key tools

- http_request for requests with and without cookies.
- manage_http_session for cookie inspection and management.
- decode_data for token decoding.

## Workflow

1. Examine session cookies with manage_http_session show.
2. Analyze cookie attributes (HttpOnly, Secure, SameSite).
3. Test session fixation by setting a known cookie before login.
4. Analyze session token format for predictability.
5. Test cookie scope (path, domain).
6. Verify session termination on logout.

## Common pitfalls

- Ignoring cookie security attributes.
- Not testing session termination.
- Using other users session tokens actively.
