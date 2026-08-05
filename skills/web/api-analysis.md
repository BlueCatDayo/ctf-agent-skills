---
name: API Analysis
identifier: api-analysis
category: web
description: Guide for analyzing REST APIs in web challenges.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - API
  - REST
  - endpoint
  - JSON
  - GraphQL
  - swagger
  - OpenAPI
required_tools:
  - http_request
  - inspect_webpage
optional_tools:
  - extract_web_elements
  - compare_http_responses
  - manage_http_session
prerequisites: []
investigation_steps:
  - title: Discover API endpoints
    description: Use inspect_webpage to find API routes; check for OpenAPI/Swagger documentation.
  - title: Test API methods
    description: Try GET, POST, PUT, PATCH, DELETE, OPTIONS on discovered endpoints.
  - title: Analyze request/response formats
    description: Check if the API accepts and returns JSON, form data, or other formats.
  - title: Test authentication on API endpoints
    description: Try accessing API endpoints with and without authentication.
  - title: Test for common API vulnerabilities
    description: Check for broken object-level authorization, excessive data exposure, and mass assignment.
evidence_requirements:
  - title: API endpoints documented
    description: All discovered API endpoints and their methods must be recorded.
  - title: API behavior analyzed
    description: Request/response formats and authentication requirements must be documented.
success_criteria:
  - title: API analysis complete
    description: The API has been fully documented and tested for common vulnerabilities.
stopping_conditions:
  - title: API analysis complete
    description: Stop once all API endpoints have been discovered and tested.
safety_notes:
  - title: Do not send destructive API requests
    description: Avoid DELETE, PUT, PATCH requests unless the challenge explicitly allows them.
  - title: Test authentication on all endpoints
    description: Some API endpoints may have different authentication requirements.
common_mistakes:
  - title: Not testing all HTTP methods
    description: An endpoint may behave differently with different HTTP methods.
  - title: Ignoring API documentation
    description: OpenAPI/Swagger docs often reveal hidden endpoints and parameters.
version: 1.0.0
---

# API Analysis

This skill guides you through analyzing REST APIs in web challenges.

## When to use

- A challenge has a REST API or web service.
- You want to discover and test API endpoints.
- You need to understand the API structure and behavior.

## Key tools

- http_request for requests to API endpoints with different methods.
- inspect_webpage for API routes and documentation.
- extract_web_elements for API references in the page.
- compare_http_responses for comparing responses across methods and auth states.

## Workflow

1. Discover API endpoints with inspect_webpage and extract_web_elements.
2. Test all HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS) on each endpoint.
3. Analyze request/response formats.
4. Test authentication on all endpoints.
5. Check for common API vulnerabilities.

## Common pitfalls

- Not testing all HTTP methods on each endpoint.
- Ignoring API documentation (OpenAPI/Swagger).
- Sending destructive API requests without authorization.
