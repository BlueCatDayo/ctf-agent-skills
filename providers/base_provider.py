"""Abstract base class for LLM provider adapters."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class ProviderError(Exception):
    """Base exception for provider-related errors."""
    pass


class InvalidAPIKeyError(ProviderError):
    """Raised when the API key is invalid or missing."""
    pass


class UnsupportedModelError(ProviderError):
    """Raised when the requested model is not supported."""
    pass


class ProviderUnavailableError(ProviderError):
    """Raised when the provider service is unreachable."""
    pass


class RateLimitError(ProviderError):
    """Raised when the API rate limit has been exceeded."""
    pass


class PaymentRequiredError(ProviderError):
    """Raised when the account requires payment to access the model."""
    pass


class TimeoutError(ProviderError):
    """Raised when the request times out."""
    pass


class EmptyResponseError(ProviderError):
    """Raised when the model returns an empty response."""
    pass


# Internal tool-call format used across the agent
ToolCall = Dict[str, Any]
ToolCallResult = Dict[str, Any]


class BaseProvider(ABC):
    """Abstract base for LLM provider adapters."""

    def __init__(self, api_key: str, model: str, timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs: Any,
    ) -> str:
        """Send a chat request and return the model's response as a string."""
        raise NotImplementedError

    @abstractmethod
    def chat_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> Tuple[str, List[ToolCall]]:
        """Send a chat request with tool definitions.

        Returns a tuple of (text_response, tool_calls).
        tool_calls is a list of dicts with 'name' and 'arguments' keys.
        """
        raise NotImplementedError

    @abstractmethod
    def validate_connection(self) -> bool:
        """Check if the provider is reachable and credentials are valid."""
        raise NotImplementedError

    def _check_api_key(self) -> None:
        """Raise InvalidAPIKeyError if the key looks invalid."""
        if not self.api_key or not self.api_key.strip():
            raise InvalidAPIKeyError("API key is empty or not set.")

    def _check_model(self, supported_models: List[str]) -> None:
        """Raise UnsupportedModelError if model is not in the supported list."""
        if self.model not in supported_models:
            raise UnsupportedModelError(
                f"Model '{self.model}' is not supported. "
                f"Supported models: {', '.join(supported_models)}"
            )
