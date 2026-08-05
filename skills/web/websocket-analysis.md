---
name: WebSocket Analysis
identifier: websocket-analysis
category: web
description: Detect WebSocket endpoints and message-driven challenge logic.
difficulty: medium
applicable_challenge_types:
  - web
trigger_keywords:
  - WebSocket
  - ws://
  - wss://
  - socket
  - Upgrade
  - Sec-WebSocket
required_tools:
  - analyze_javascript_url
optional_tools:
  - http_request
  - pwn_session_start
prerequisites: []
investigation_steps:
  - title: Find WebSocket URLs
    description: Search JavaScript and page source for ws:// or wss:// URLs and new WebSocket() calls.
  - title: Connect
    description: Use a user-provided client or the optional pwntools remote runner to connect.
  - title: Map the protocol
    description: Send one benign message at a time and record responses; look for state-machine logic.
  - title: Solve the state machine
    description: Only after mapping responses, craft the message sequence the challenge expects.
evidence_requirements:
  - title: URL confirmed
    description: The WebSocket URL must appear in tool output.
  - title: Messages recorded
    description: Server responses must be recorded before drawing conclusions.
success_criteria:
  - title: Challenge logic mapped
    description: The message protocol is understood and responses are recorded.
stopping_conditions:
  - title: Flag confirmed
    description: Stop when the flag appears in a successful tool result.
safety_notes:
  - title: No flooding
    description: Keep interactions targeted; do not flood the socket.
common_mistakes:
  - title: Guessing the protocol
    description: Never guess message formats - record actual responses first.
version: 1.0.0
---

# WebSocket Analysis

## When to use

- WebSocket URLs in JS, socket.io apps, real-time challenge logic.

## Key tools

- analyze_javascript_url / extract_web_elements for discovery.
- pwn_session_start (remote) with the user-provided host and port.

## Workflow

1. Find ws://wss:// URLs in JavaScript.
2. Connect and record initial messages.
3. Interact one message at a time.
4. Solve the message-driven logic with recorded evidence.
