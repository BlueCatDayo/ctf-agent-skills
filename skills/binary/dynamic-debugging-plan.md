---
name: Dynamic Debugging Plan
identifier: dynamic-debugging-plan
category: binary
description: Guide for planning and executing dynamic analysis of binary challenges.
difficulty: hard
applicable_challenge_types:
  - binary
trigger_keywords:
  - debug
  - GDB
  - dynamic
  - runtime
  - trace
  - breakpoint
  - step
required_tools:
  - run_ctf_command
optional_tools:
  - inspect_file
  - search_files
prerequisites:
  - static-disassembly-analysis
  - architecture-and-protection-analysis
investigation_steps:
  - title: Plan the debugging session
    description: Based on static analysis, identify key functions and addresses to break on.
  - title: Set breakpoints at key functions
    description: Use GDB to set breakpoints at main, win, check, and other interesting functions.
  - title: Run the binary with controlled input
    description: Provide test input and observe program behavior at breakpoints.
  - title: Examine registers and memory
    description: At each breakpoint, examine register values and memory contents.
  - title: Step through critical code paths
    description: Use step and next commands to trace execution through key logic.
  - title: Document findings
    description: Record register values, memory contents, and execution flow at each step.
evidence_requirements:
  - title: Debugging session documented
    description: Breakpoints, register values, and memory contents must be recorded.
  - title: Execution flow traced
    description: The program execution path through key functions must be documented.
success_criteria:
  - title: Dynamic analysis complete
    description: Key functions have been debugged and their runtime behavior understood.
stopping_conditions:
  - title: Dynamic analysis complete
    description: Stop once the runtime behavior of key functions has been documented.
safety_notes:
  - title: Use controlled input only
    description: Do not send malicious input that could crash the system.
  - title: Do not modify the binary
    description: Dynamic analysis should be read-only; do not patch the binary unless required.
common_mistakes:
  - title: Not planning the debugging session
    description: Always plan breakpoints based on static analysis before starting.
  - title: Not documenting register and memory state
    description: Register and memory state at breakpoints is critical for understanding behavior.
version: 1.0.0
---

# Dynamic Debugging Plan

This skill guides you through planning and executing dynamic analysis of binary challenges.

## When to use

- You need to understand binary behavior at runtime.
- Static analysis is insufficient to solve the challenge.
- You want to trace execution through key functions.

## Key tools

- run_ctf_command for GDB with controlled input.
- inspect_file for metadata and type information.

## Workflow

1. Plan the debugging session based on static analysis.
2. Set breakpoints at key functions (main, win, check).
3. Run the binary with controlled input.
4. Examine registers and memory at each breakpoint.
5. Step through critical code paths.
6. Document all findings.

## Common pitfalls

- Not planning breakpoints before starting.
- Not documenting register and memory state at breakpoints.
- Sending uncontrolled input that crashes the program.
