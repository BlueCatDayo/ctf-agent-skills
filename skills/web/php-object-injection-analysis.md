---
name: PHP Object Injection Analysis
identifier: php-object-injection-analysis
category: web
description: Detect unserialize() on user-controlled data and magic-method gadget indicators.
difficulty: hard
applicable_challenge_types:
  - web
trigger_keywords:
  - unserialize
  - serialize
  - PHP object
  - __wakeup
  - __destruct
  - __toString
  - phar
required_tools:
  - search_files
  - read_text_file
optional_tools:
  - http_post
prerequisites: []
investigation_steps:
  - title: Find unserialize
    description: Search PHP source for unserialize() and identify whether input is user-controlled.
  - title: Identify magic methods
    description: Look for __wakeup, __destruct, __toString, __call gadgets in included classes.
  - title: Assess gadget chain
    description: Only craft a serialized object when source confirms a usable gadget.
  - title: Verify
    description: Send the payload to the authorized target and record the effect.
evidence_requirements:
  - title: Sink located
    description: unserialize() on user-controlled data must be seen in source.
  - title: Gadget present
    description: A magic method usable in the chain must be confirmed in source.
success_criteria:
  - title: Effect confirmed
    description: Tool output shows the gadget effect (file read, output, or flag).
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: Requires a gadget
    description: Never blind-send serialized payloads without a confirmed gadget.
common_mistakes:
  - title: Blind payload spraying
    description: Sending random serialized objects is not evidence-driven.
version: 1.0.0
---

# PHP Object Injection Analysis

## When to use

- unserialize() in source, phar:// references, magic-method classes.

## Key tools

- search_files for unserialize( and magic methods.
- read_text_file to review the gadget chain.

## Workflow

1. Confirm unserialize on user input.
2. Map magic-method gadgets in included classes.
3. Craft only when a chain is confirmed.
4. Verify the effect on the authorized target.
