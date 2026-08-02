# SQL Injection Fast Triage

## When to use

Use when an authorized CTF web challenge contains login forms, search fields,
numeric IDs, filters, or parameters that may reach a database query.

## Checklist

1. Record the normal request and response.
2. Identify every controllable parameter.
3. Change only one parameter at a time.
4. Check for database errors, response differences, redirects, or timing changes.
5. Determine whether the input is string, numeric, or another SQL context.
6. Use the smallest non-destructive proof possible.
7. Confirm the flag from the actual server response.

## Useful evidence

- HTTP status
- Response length
- Error message
- Redirect location
- Response timing
- Returned database content

## Common false positives

- Generic server errors are not proof of SQL injection.
- Different response sizes may come from random tokens.
- A slow response may be caused by network latency.

## Success criteria

Only report SQL injection when the behavior is repeatable.
Only report a flag when it appears in confirmed challenge output.
