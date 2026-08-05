---
name: SQL Injection Test Skill
identifier: test-sql-injection
category: web
description: Test skill for SQL injection analysis in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - sql
  - injection
  - database
  - query
required_tools:
  - http_request
optional_tools:
  - compare_http_responses
prerequisites: []
investigation_steps:
  - title: Find input points
    description: Locate forms and parameters that feed database queries.
  - title: Test with safe payloads
    description: Send a single quote and compare responses.
evidence_requirements:
  - title: Injection confirmed
    description: A database error must appear in tool output.
success_criteria:
  - title: Vulnerability confirmed
    description: SQL injection verified with tool output evidence.
stopping_conditions:
  - title: Confirmed
    description: Stop once confirmed.
safety_notes:
  - title: Minimal payloads only
    description: Use targeted payloads; never destructive queries.
common_mistakes:
  - title: Payload spraying
    description: Do not send large payload sets.
version: 1.0.0
---

# SQL Injection Test Skill

Used by the Stage 4 test suite to verify skill loading and routing.

## Workflow

1. Find input points.
2. Test with a single quote.
3. Compare responses.
