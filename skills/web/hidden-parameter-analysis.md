---
name: Hidden Parameter Analysis
identifier: hidden-parameter-analysis
category: web
description: Guide for analyzing hidden form fields and parameters in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - hidden
  - parameter
  - form field
  - hidden input
  - tamper
  - modify
  - bypass
required_tools:
  - http_request
  - extract_web_elements
optional_tools:
  - compare_http_responses
  - manage_http_session
prerequisites: []
investigation_steps:
  - title: Extract all form fields
    description: Use extract_web_elements with element_type=forms to find all form inputs.
  - title: Identify hidden fields
    description: Use extract_web_elements with element_type=hidden_inputs to find hidden parameters.
  - title: Analyze hidden field values
    description: Check if hidden field values are predictable, encoded, or sensitive.
  - title: Test parameter tampering
    description: Modify hidden field values and observe server responses.
  - title: Compare responses
    description: Use compare_http_responses to detect differences caused by parameter changes.
evidence_requirements:
  - title: Hidden fields documented
    description: All hidden form fields and their values must be recorded.
  - title: Tampering results documented
    description: Server responses to parameter modifications must be recorded.
success_criteria:
  - title: Hidden parameters analyzed
    description: All hidden parameters have been identified and tested for tampering.
stopping_conditions:
  - title: Hidden parameters tested
    description: Stop once all hidden fields have been analyzed and tampered with safely.
safety_notes:
  - title: Do not modify production data
    description: Only test hidden parameters in CTF challenges, not real applications.
  - title: Use compare_http_responses to detect changes
    description: Subtle differences in responses often reveal hidden parameter effects.
common_mistakes:
  - title: Ignoring hidden fields
    description: Hidden form fields often contain critical data like prices, roles, or flags.
  - title: Not comparing responses after tampering
    description: Always compare responses to detect the effect of parameter changes.
version: 1.0.0
---

# Hidden Parameter Analysis

This skill guides you through analyzing hidden form fields and parameters.

## When to use

- A challenge has forms with hidden input fields.
- You want to find parameters that can be tampered with.
- You need to discover hidden functionality in forms.

## Key tools

- extract_web_elements for hidden inputs and form fields.
- http_request for modified form submissions.
- compare_http_responses for before/after comparison.

## Workflow

1. Extract all form fields with extract_web_elements.
2. Identify hidden inputs with extract_web_elements hidden_inputs.
3. Analyze hidden field values for predictability or sensitivity.
4. Modify hidden field values and observe server responses.
5. Compare responses to detect the effect of changes.

## Common pitfalls

- Ignoring hidden form fields.
- Not comparing responses after parameter tampering.
- Assuming hidden fields are always safe.
