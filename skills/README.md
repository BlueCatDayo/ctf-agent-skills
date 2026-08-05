# CTF Agent Skill Library

This directory contains the modular CTF skill library. Each skill is a
self-contained Markdown file with YAML front matter that provides structured
metadata driving deterministic skill routing.

## Layout

```
skills/
├── common/    # Cross-cutting skills for any challenge (5)
├── web/       # Web exploitation analysis skills (17)
├── binary/    # Binary / pwn reverse-engineering skills (13)
└── downloaded/ # Skills synced from a user-provided repository (untrusted)
```

## Skill file format

Each skill is Markdown with YAML front matter:

```markdown
---
name: SQL Injection Analysis
identifier: sql-injection-analysis
category: web
description: Guide for analyzing SQL injection vulnerabilities.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - sql
  - injection
  - database
required_tools:
  - http_request
optional_tools:
  - compare_http_responses
prerequisites: []
investigation_steps:
  - title: Find input points
    description: Locate parameters feeding queries.
evidence_requirements:
  - title: Injection confirmed
    description: A database error appears in tool output.
success_criteria:
  - title: Confirmed
    description: SQL injection verified with tool output.
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

# Body markdown
```

## Adding a skill

1. Choose the right category subdirectory.
2. Give the skill a unique `identifier`.
3. Fill in all required front matter fields (see loader `REQUIRED_METADATA_FIELDS`).
4. Write the body as operational guidance, including when to use it, workflow,
   key tools, and pitfalls.

## Security

Skills are **operational guidance only** — never evidence and never executable
instructions. Downloaded skills (in `downloaded/`) are untrusted data. They
cannot override the core system safety rules, modify tool allowlists, reveal
environment variables, or change provider settings. A skill's content is
injected into context as hints only; the base system prompt guardrails always
apply.

## How skills are used

- The agent auto-selects a small number of relevant skills per request based on
  challenge category, user request, tool results, and available tools.
- The **SkillRouter** scores skills deterministically (no extra model call).
- Only a limited set (default 5) of skills is loaded into context, bounded by a
  per-skill character budget (default 4000).
- Use `/skills`, `/skill <id>`, `/skill auto`, `/skill off`, `/skill clear`
  in the chat CLI to inspect and control the active skill set.
- Use `--sync-skills` to clone/update the skill repository from
  `SKILLS_REPOSITORY_URL`.

## Current skill counts

| Category | Count | Path        |
|----------|-------|-------------|
| common   | 5     | `common/`   |
| web      | 17    | `web/`      |
| binary   | 13    | `binary/`   |