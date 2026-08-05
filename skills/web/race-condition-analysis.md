---
name: Race Condition Analysis
identifier: race-condition-analysis
category: web
description: Identify race-condition patterns in single-use or state-mutating endpoints.
difficulty: hard
applicable_challenge_types:
  - web
trigger_keywords:
  - race
  - concurrent
  - coupon
  - balance
  - redeem
  - claim
  - single use
required_tools:
  - http_post
  - compare_http_responses
optional_tools:
  - extract_forms_from_page
prerequisites: []
investigation_steps:
  - title: Identify state-changing endpoints
    description: Look for single-use actions: coupon redemption, balance transfer, claims, checkout.
  - title: Baseline one request
    description: Send one request and record the state change.
  - title: Concurrent duplicates
    description: Send a small number (2-5) of concurrent identical requests on the authorized target and compare how many succeed.
  - title: Confirm with evidence
    description: A race is confirmed only when output shows the state mutated more times than allowed.
evidence_requirements:
  - title: Endpoint identified
    description: The state-changing endpoint must be documented.
  - title: Response comparison
    description: Status codes/state changes for the concurrent requests must be recorded.
success_criteria:
  - title: Race confirmed
    description: Tool output shows more successful mutations than permitted.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: Bounded concurrency
    description: Keep concurrency minimal (2-5 requests); no load testing or flooding.
common_mistakes:
  - title: Load testing
    description: Large-scale concurrent traffic is DoS behavior and out of scope.
version: 1.0.0
---

# Race Condition Analysis

## When to use

- Coupon/balance/claim/order endpoints, single-use tokens.

## Key tools

- http_post for the state-changing request.
- compare_http_responses to record differences.

## Workflow

1. Find a single-use endpoint.
2. Baseline one request.
3. Send 2-5 concurrent duplicates.
4. Confirm only with recorded state changes.
