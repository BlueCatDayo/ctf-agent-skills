---
name: Buffer Overflow Test Skill
identifier: test-buffer-overflow
category: binary
description: Test skill for stack buffer overflow analysis.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - overflow
  - buffer
  - stack
required_tools:
  - run_ctf_command
optional_tools:
  - decode_data
prerequisites:
  - test-static-analysis
investigation_steps:
  - title: Find unsafe functions
    description: Look for gets and strcpy in disassembly.
  - title: Determine buffer size
    description: Measure the stack frame buffer.
evidence_requirements:
  - title: Overflow confirmed
    description: Crash must appear in tool output.
success_criteria:
  - title: Overflow analyzed
    description: Buffer size documented.
stopping_conditions:
  - title: Confirmed
    description: Stop once confirmed.
safety_notes:
  - title: No full exploitation
    description: Analysis only.
common_mistakes:
  - title: Missing unsafe calls
    description: Check all string functions.
version: 1.0.0
---

# Buffer Overflow Test Skill

Used by the Stage 4 test suite.

## Workflow

1. Find unsafe functions.
2. Measure buffer size.
