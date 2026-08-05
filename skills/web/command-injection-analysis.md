---
name: Command Injection Analysis
identifier: command-injection-analysis
category: web
description: Guide for analyzing command injection vulnerabilities in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - command injection
  - OS command
  - shell injection
  - exec
  - system
  - shell
  - ping
  - whoami
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - compare_http_responses
  - run_ctf_command
prerequisites: []
investigation_steps:
  - title: Identify user input points
    description: Find all parameters that influence system commands or shell execution.
  - title: Test for command injection
    description: Send safe, targeted payloads (e.g., semicolons, pipes) to input points; use compare_http_responses to detect differences.
  - title: Analyze command output
    description: Check if command output is visible in responses.
  - title: Use minimal payloads
    description: Only use safe, targeted payloads; do not spray random command injection strings.
evidence_requirements:
  - title: Command injection confirmed
    description: Command output must be visible in tool output.
  - title: Input point identified
    description: The vulnerable parameter must be documented.
success_criteria:
  - title: Command injection confirmed with evidence
    description: A command injection vulnerability has been confirmed with tool output evidence.
stopping_conditions:
  - title: Command injection confirmed
    description: Stop once a command injection is confirmed; do not attempt further exploitation.
safety_notes:
  - title: Use minimal, targeted payloads only
    description: Do not send large sets of command injection payloads.
  - title: Do not attempt destructive commands
    description: Never send commands that could modify or delete files.
  - title: Report only confirmed findings
    description: A command injection is only confirmed if tool output shows command output.
common_mistakes:
  - title: Spraying random payloads
    description: Use targeted, minimal payloads; do not send large sets of command injection strings.
  - title: Ignoring subtle output differences
    description: Use compare_http_responses to detect small differences in responses.
version: 1.0.0
---

# Command Injection Analysis

This skill guides you through analyzing command injection vulnerabilities.

## When to use

- A challenge involves system command execution from user input.
- You want to find command injection vulnerabilities.
- Input points interact with the operating system.

## Key tools

- http_request for targeted payloads to input points.
- inspect_webpage for forms and input fields.
- compare_http_responses for detecting differences caused by injection.

## Workflow

1. Identify all user input points (forms, URL params, headers, cookies).
2. Test for command injection with minimal, safe payloads.
3. Analyze command output in responses.
4. If confirmed, stop and report the finding.

## Common pitfalls

- Spraying random command injection payloads.
- Ignoring subtle output differences between responses.
- Attempting destructive commands.
