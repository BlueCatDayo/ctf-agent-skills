---
name: SQL Injection Analysis
identifier: sql-injection-analysis
category: web
description: Guide for analyzing SQL injection vulnerabilities in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - SQL
  - injection
  - SQLi
  - database
  - query
  - mysql
  - PostgreSQL
  - SQLite
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - extract_web_elements
  - compare_http_responses
  - decode_data
prerequisites: []
investigation_steps:
  - title: Identify user input points
    description: Find all forms, URL parameters, headers, and cookies that influence database queries.
  - title: Test for error-based SQLi
    description: Send single quotes and SQL error-inducing payloads to input points; use compare_http_responses to detect differences.
  - title: Analyze error messages
    description: Check if database error messages are visible in responses.
  - title: Test for UNION-based SQLi
    description: If error-based SQLi is confirmed, test for UNION-based injection to extract data.
  - title: Use safe, targeted payloads
    description: Only use minimal, targeted payloads; do not spray random SQL injection strings.
evidence_requirements:
  - title: SQL injection confirmed
    description: A database error or data leak must be observed in tool output.
  - title: Input point identified
    description: The vulnerable parameter or form field must be documented.
success_criteria:
  - title: SQL injection confirmed with evidence
    description: A SQL injection vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: SQL injection confirmed
    description: Stop once a SQL injection is confirmed; do not attempt further exploitation.
safety_notes:
  - title: Use minimal, targeted payloads only
    description: Do not send large sets of SQL injection payloads.
  - title: Do not attempt destructive queries
    description: Never send DROP, DELETE, or UPDATE payloads.
  - title: Report only confirmed findings
    description: A SQL injection is only confirmed if tool output shows a database error or data leak.
common_mistakes:
  - title: Spraying random payloads
    description: Use targeted, minimal payloads; do not send large sets of SQL injection strings.
  - title: Ignoring error messages
    description: Database error messages in responses are the primary indicator of SQL injection.
version: 1.0.0
---

# SQL Injection Analysis

This skill guides you through analyzing SQL injection vulnerabilities.

## When to use

- A challenge involves database-driven web applications.
- You want to find SQL injection vulnerabilities.
- Input points interact with a database.

## Key tools

- http_request for targeted payloads to input points.
- inspect_webpage for forms and input fields.
- compare_http_responses for detecting differences caused by injection.

## Workflow

1. Identify all user input points (forms, URL params, headers, cookies).
2. Test for error-based SQLi with minimal payloads (single quotes, SQL errors).
3. Analyze error messages in responses.
4. If confirmed, test for UNION-based injection with safe, targeted payloads.
5. Stop once SQL injection is confirmed.

## Common pitfalls

- Spraying random SQL injection payloads instead of using targeted, minimal ones.
- Ignoring database error messages in responses.
- Attempting destructive queries (DROP, DELETE, UPDATE).
