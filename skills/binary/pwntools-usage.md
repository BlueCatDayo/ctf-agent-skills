---
name: Pwntools Usage
identifier: pwntools-usage
category: binary
description: Use optional pwntools for process/session interaction, packing, and cyclic offsets.
difficulty: medium
applicable_challenge_types:
  - binary
trigger_keywords:
  - pwntools
  - process
  - remote
  - sendline
  - recv
  - pwn
  - interactive
required_tools:
  - pwn_status
  - pwn_session_start
optional_tools:
  - pwn_session_send
  - pwn_session_recv
  - pwn_session_wait_prompt
  - pwn_session_close
prerequisites: []
investigation_steps:
  - title: Check availability
    description: pwn_status reports whether pwntools is installed and a session is active.
  - title: Start a session
    description: Local: pwn_session_start local=<binary in workspace>. Remote: pwn_session_start host=<user-provided host> port=<user-provided port>.
  - title: Interact
    description: pwn_session_send / pwn_session_recv / pwn_session_wait_prompt with timeouts.
  - title: Close cleanly
    description: Always pwn_session_close after the interaction.
evidence_requirements:
  - title: Output recorded
    description: Every received message must be recorded in evidence.
  - title: Target authorized
    description: Remote connections require the user-provided authorized host and port.
success_criteria:
  - title: Interaction completed
    description: The session exchanged the needed messages and was closed cleanly.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: No arbitrary targets
    description: Never connect to hosts not provided by the user as the authorized CTF target.
  - title: Timeouts
    description: All interactions use timeouts; no infinite waits.
common_mistakes:
  - title: Leaving sessions open
    description: Always close sessions after use.
version: 1.0.0
---

# Pwntools Usage

## When to use

- Interacting with a local challenge binary or a user-provided remote CTF service.

## Key tools

- pwn_status, pwn_session_start, pwn_session_send, pwn_session_recv, pwn_session_close.

## Workflow

1. Check pwntools availability.
2. Start a local or remote session (remote only with user-provided host/port).
3. Send/receive with timeouts, recording all output.
4. Close the session cleanly.
