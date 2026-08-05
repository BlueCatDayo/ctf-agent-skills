---
name: JavaScript Secrets Analysis
identifier: javascript-secrets-analysis
category: web
description: Extract endpoints, API keys, tokens, source maps, and client-side authz logic from JavaScript.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - JavaScript
  - API key
  - secret
  - token
  - source map
  - endpoint
  - minified
required_tools:
  - analyze_javascript_url
  - extract_javascript_from_page
optional_tools:
  - analyze_javascript_file
  - beautify_javascript
  - search_javascript_file
prerequisites: []
investigation_steps:
  - title: Collect scripts
    description: Use extract_javascript_from_page to list script URLs, then analyze_javascript_url on each.
  - title: Beautify minified code
    description: Run beautify_javascript before searching for endpoints and secrets.
  - title: Extract surfaces
    description: Look for endpoints, API base URLs, fetch/XHR calls, GraphQL and WebSocket URLs, hidden routes.
  - title: Check source maps
    description: sourceMappingURL references may reveal original source - fetch the .map file.
  - title: Review authz logic
    description: Client-side role checks (isAdmin, localStorage tokens) are surfaces, not evidence of server acceptance.
evidence_requirements:
  - title: Match with context
    description: Endpoints/secrets must be reported with the file name and line context.
  - title: Verified by request
    description: Candidate endpoints must respond before being reported as real.
success_criteria:
  - title: Surface mapped
    description: Endpoints, secrets, and authz logic are extracted with context.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: Never trust JS secrets blindly
    description: A key in JavaScript is only meaningful if the server honors it - verify.
  - title: Cap output
    description: Return only relevant matches; do not dump whole scripts.
common_mistakes:
  - title: Reporting unverified endpoints
    description: Probe candidates before reporting them as discovered surfaces.
version: 1.0.0
---

# JavaScript Secrets Analysis

## When to use

- Any challenge with client-side code, minified bundles, or API calls.

## Key tools

- analyze_javascript_url / analyze_javascript_file.
- beautify_javascript and search_javascript_file for targeted searches.

## Workflow

1. Collect script URLs from the page.
2. Analyze each script for endpoints/secrets/maps.
3. Beautify and re-search for hidden routes and authz logic.
4. Verify candidate endpoints with small requests.
