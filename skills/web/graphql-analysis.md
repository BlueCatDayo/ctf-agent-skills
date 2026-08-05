---
name: GraphQL Analysis
identifier: graphql-analysis
category: web
description: Detect GraphQL endpoints and misconfigurations such as enabled introspection and weak mutation authorization.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - GraphQL
  - introspection
  - __schema
  - __typename
  - mutation
  - /graphql
required_tools:
  - discover_api_endpoints
  - http_post
  - analyze_javascript_url
optional_tools:
  - search_javascript_file
prerequisites: []
investigation_steps:
  - title: Find the endpoint
    description: Probe /graphql and search JavaScript for graphql references.
  - title: Test introspection
    description: Send a harmless { __schema { types { name } } } query and record the response.
  - title: Enumerate fields
    description: If introspection is enabled, list types/fields with targeted queries; avoid dumping the full schema.
  - title: Check mutation authorization
    description: Compare a privileged mutation with and without credentials.
evidence_requirements:
  - title: Endpoint confirmed
    description: The GraphQL endpoint responds to a query in tool output.
  - title: Introspection result
    description: Schema/type information must appear in a tool result.
success_criteria:
  - title: Misconfiguration confirmed
    description: Introspection enabled or an unauthenticated privileged mutation succeeded in tool output.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: No DoS queries
    description: Avoid recursive/expensive queries (billion-laughs style) - DoS is out of scope.
common_mistakes:
  - title: Assuming introspection is enabled
    description: Confirm with a tool result before reporting.
version: 1.0.0
---

# GraphQL Analysis

## When to use

- /graphql endpoints, Apollo/Relay apps, __typename strings in JS.

## Key tools

- discover_api_endpoints / analyze_javascript_url to find the endpoint.
- http_post with JSON GraphQL queries.

## Workflow

1. Locate the GraphQL endpoint.
2. Probe introspection with a small query.
3. Enumerate types only if introspection is enabled.
4. Compare mutation access with/without credentials.
5. Report only confirmed misconfigurations.
