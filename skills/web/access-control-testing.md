---
name: Access Control Testing
identifier: access-control-testing
category: web
description: Guide for testing access control and authorization in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - access control
  - authorization
  - role
  - admin
  - permission
  - privilege
  - RBAC
required_tools:
  - http_request
  - compare_http_responses
optional_tools:
  - manage_http_session
  - inspect_webpage
  - extract_web_elements
prerequisites: []
investigation_steps:
  - title: Identify user roles
    description: Find different user roles (admin, user, guest) through registration or documentation.
  - title: Test horizontal privilege escalation
    description: Try accessing another user's resources with your own credentials.
  - title: Test vertical privilege escalation
    description: Try accessing admin endpoints as a regular user.
  - title: Compare responses
    description: Use compare_http_responses to detect differences in access-denied vs access-granted responses.
  - title: Test IDOR patterns
    description: Try incrementing or modifying resource IDs in requests.
evidence_requirements:
  - title: Access control differences documented
    description: Different responses for different roles must be recorded.
  - title: Unauthorized access confirmed
    description: Any successful unauthorized access must be verified with tool output.
success_criteria:
  - title: Access control weaknesses identified
    description: At least one access control weakness has been confirmed.
stopping_conditions:
  - title: Access control tested
    description: Stop once all identified roles and endpoints have been tested.
safety_notes:
  - title: Only test authorized endpoints
    description: Do not test endpoints outside the scope of the challenge.
  - title: Do not modify other users' data
    description: Read-only testing is preferred; avoid destructive actions.
common_mistakes:
  - title: Not comparing responses systematically
    description: Always compare authenticated vs unauthenticated and user vs admin responses.
  - title: Testing only one role
    description: Test all identified roles and user levels.
version: 1.0.0
---

# Access Control Testing

This skill guides you through testing access control and authorization.

## When to use

- A challenge has different user roles or permission levels.
- You want to find authorization bypass vulnerabilities.
- You need to test for IDOR or privilege escalation.

## Key tools

- http_request for requests as different users.
- compare_http_responses for cross-role comparison.
- manage_http_session for multiple sessions.

## Workflow

1. Identify user roles through registration or documentation.
2. Test horizontal privilege escalation (access another user's data).
3. Test vertical privilege escalation (access admin endpoints as a regular user).
4. Compare responses to identify access control differences.
5. Test IDOR patterns by modifying resource IDs.

## Common pitfalls

- Not comparing responses systematically.
- Testing only one user role.
- Modifying other users' data instead of reading it.
