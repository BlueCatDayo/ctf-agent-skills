---
name: Crash and Offset Analysis
identifier: crash-offset-analysis
category: binary
description: Determine buffer-overflow overwrite offsets with cyclic patterns and controlled crashes.
difficulty: medium
applicable_challenge_types:
  - binary
trigger_keywords:
  - offset
  - cyclic
  - crash
  - segfault
  - buffer overflow
required_tools:
  - pwn_crash_analyze
  - pwn_cyclic
  - pwn_cyclic_find
optional_tools:
  - pwn_verify_offset
  - pwn_pack
prerequisites: []
investigation_steps:
  - title: Generate cyclic input
    description: Use pwn_cyclic to generate a pattern longer than the expected buffer.
  - title: Run the local binary
    description: pwn_crash_analyze feeds the pattern to the challenge binary on stdin with a timeout.
  - title: Capture the crash
    description: Record the exit code, signal, and faulting address from tool output.
  - title: Determine the offset
    description: Map the crash bytes back to an offset (ASCII pattern search, or pwntools cyclic_find when installed).
  - title: Verify
    description: pwn_verify_offset reruns with a marker at the offset and checks the fault address.
  - title: Store the result
    description: Record the confirmed offset in evidence memory.
evidence_requirements:
  - title: Crash captured
    description: The crash must be observed in tool output.
  - title: Offset verified
    description: The offset must be confirmed by a marker-based rerun.
success_criteria:
  - title: Offset confirmed
    description: A verified overwrite offset is recorded in evidence.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: Workspace only
    description: Only run challenge binaries inside the configured challenge directory.
  - title: Timeouts
    description: Local runs use short timeouts; never crash unrelated system programs.
common_mistakes:
  - title: Repeating crashes
    description: Run the crash analysis once, then verify; avoid unnecessary repeats.
version: 1.0.0
---

# Crash and Offset Analysis

## When to use

- Stack buffer overflow challenges where the offset is unknown.

## Key tools

- pwn_cyclic, pwn_crash_analyze, pwn_verify_offset.

## Workflow

1. Generate cyclic input.
2. Run the binary with the input (stdin, timeout).
3. Capture the crash output.
4. Compute the offset.
5. Verify with a marker.
6. Record the offset in evidence.
