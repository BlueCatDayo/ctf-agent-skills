---
name: JWT Analysis
identifier: jwt-analysis
category: web
description: Decode and analyze JSON Web Tokens for weak claims, expiry, and algorithm handling.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - JWT
  - token
  - bearer
  - eyJ
  - Authorization
  - claims
required_tools:
  - analyze_headers
  - manage_cookies
optional_tools:
  - decode_data
  - http_request
prerequisites: []
investigation_steps:
  - title: Locate the token
    description: Find JWTs in Authorization headers, cookies, or JavaScript (manage_cookies / analyze_headers / analyze_javascript_*).
  - title: Decode header and payload
    description: Use decode_data with JWT encoding to read alg, typ, and all claims.
  - title: Check claims
    description: Look for role/admin/permission claims, missing exp, and user identity fields.
  - title: Test algorithm handling
    description: Only with the authorized target, verify whether alg:none or HS256 confusion is accepted by replaying a modified token.
evidence_requirements:
  - title: Token observed
    description: The JWT must appear in tool output.
  - title: Claims decoded
    description: Header/payload contents must be decoded from the actual token.
success_criteria:
  - title: Weakness confirmed with replay
    description: A modified token produces a changed access result in tool output.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: Decoder only
    description: Decoding a JWT never verifies the signature - do not claim signature acceptance without testing.
  - title: Verify before claiming
    description: Never report a JWT bypass without a tool-verified access change.
common_mistakes:
  - title: Inventing claims
    description: Never guess claim values - decode the actual token.
  - title: Assuming alg:none works
    description: alg:none is only a weakness if the server actually accepts unsigned tokens.
version: 1.0.0
---

# JWT Analysis

## When to use

- Tokens in Authorization headers, cookies, or JavaScript.
- Role/permission-based access control.

## Key tools

- decode_data (encoding=jwt) to decode header/payload.
- analyze_headers / manage_cookies to locate tokens.
- http_request to replay modified tokens on the authorized target.

## Workflow

1. Find the token in headers/cookies/JS.
2. Decode it; record alg, exp, and role claims.
3. Flag missing exp, alg:none, or HS256 confusion hypotheses.
4. Verify any bypass with a request; report only confirmed access.
