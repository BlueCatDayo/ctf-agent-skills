"""Conversation history manager."""

from typing import Dict, List


class ConversationHistory:
    """Manages the turn-by-turn conversation history."""

    def __init__(self):
        self._messages: List[Dict[str, str]] = []

    def add_user_message(self, content: str) -> None:
        """Append a user message to the history."""
        self._messages.append({"role": "user", "content": content})

    def add_assistant_message(self, content: str) -> None:
        """Append an assistant message to the history."""
        self._messages.append({"role": "assistant", "content": content})

    def get_messages(self) -> List[Dict[str, str]]:
        """Return a copy of the full message history."""
        return list(self._messages)

    def clear(self) -> None:
        """Remove all messages from history."""
        self._messages.clear()

    def length(self) -> int:
        """Return the number of messages in history."""
        return len(self._messages)

    def last_n(self, n: int) -> List[Dict[str, str]]:
        """Return the last N messages from the history."""
        return list(self._messages[-n:]) if n > 0 else []
