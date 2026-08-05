"""Stage 7 WebSocket challenge specialist.

Analyzes evidence for WebSocket-based challenge logic: WebSocket URLs,
connection endpoints, and message-driven state machines.  The specialist
is analysis-only; interactive sessions require a user-provided client or
the optional pwntools remote runner.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..base import EvidenceSnapshot, Specialist

SIGNALS = [
    "websocket", "ws://", "wss://", "socket", "ws connection", "upgrade",
    "sec-websocket", "socket.io", "ws endpoint", "web socket",
]


class WebSocketSpecialist(Specialist):
    """Evidence-driven WebSocket analysis."""

    name = "web.websocket"
    category = "web"
    description = "Detect WebSocket endpoints and message-based challenge logic."
    signals = SIGNALS

    def run(self, evidence: EvidenceSnapshot, profile: Optional[Dict[str, Any]] = None) -> "SpecialistResult":
        from ..base import SpecialistResult

        confirmed: List[str] = []
        rejected: List[str] = []
        steps: List[str] = []
        text = evidence.text()

        ws_urls = self._websocket_urls(text)
        if ws_urls:
            confirmed.append(f"WebSocket URL(s) found: {', '.join(ws_urls[:4])}")

        if "upgrade" in text.lower() or "sec-websocket" in text.lower():
            confirmed.append("HTTP Upgrade / Sec-WebSocket headers observed - WebSocket handshake surface.")

        steps.append(
            "Connect to the WebSocket endpoint with an authorized client (browser "
            "console or the optional pwntools remote runner) and record the initial "
            "server messages."
        )
        steps.append(
            "Map the message protocol: send one benign message at a time and record "
            "responses; look for state-machine challenges (guess/order/riddle logic)."
        )
        steps.append(
            "Never flood the socket with messages; keep interactions targeted and "
            "documented."
        )

        if not ws_urls:
            rejected.append("No WebSocket URL found in evidence yet.")
            steps.append(
                "Search JavaScript (analyze_javascript_*) and page scripts for "
                "'ws://' / 'wss://' or 'WebSocket(' calls."
            )

        return self._result(
            evidence, profile,
            hypothesis="Challenge logic may be served over WebSocket.",
            confirmed=confirmed, rejected=rejected, steps=steps,
            next_specialist="web.api_analysis",
            summary="WebSocket: " + ("endpoints found" if ws_urls else "none yet"),
        )

    def _websocket_urls(self, text: str) -> List[str]:
        seen: List[str] = []
        for m in re.finditer(r"(wss?://[A-Za-z0-9_.\-:~/?#\[\]@!$&'()*+,;=%]+)", text):
            url = m.group(1)
            if url not in seen:
                seen.append(url)
            if len(seen) >= 4:
                break
        return seen
