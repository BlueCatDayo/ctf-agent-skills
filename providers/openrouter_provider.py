"""OpenRouter provider adapter."""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

import requests

from .base_provider import (
    BaseProvider,
    EmptyResponseError,
    InvalidAPIKeyError,
    PaymentRequiredError,
    ProviderUnavailableError,
    RateLimitError,
    TimeoutError,
    UnsupportedModelError,
)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"

# Known free/available models on OpenRouter
DEFAULT_SUPPORTED_MODELS = [
    "ling-3.0",
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "anthropic/claude-3.5-sonnet",
    "google/gemini-2.0-flash",
    "meta-llama/llama-3.1-8b-instruct",
]


class OpenRouterProvider(BaseProvider):
    """Adapter for the OpenRouter API."""

    def __init__(self, api_key: str, model: str = "ling-3.0", timeout: int = 30):
        super().__init__(api_key, model, timeout)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": os.environ.get("APP_URL", "https://localhost"),
            "X-Title": "CTF-Agent",
            "Content-Type": "application/json",
        })

    def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs: Any,
    ) -> str:
        """Send a chat completion request via OpenRouter."""
        self._check_api_key()

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 4096),
        }

        try:
            response = self.session.post(
                OPENROUTER_API_URL,
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Request to OpenRouter timed out after {self.timeout}s.")
        except requests.exceptions.ConnectionError:
            raise ProviderUnavailableError("Cannot connect to OpenRouter API.")
        except requests.exceptions.RequestException as e:
            raise ProviderUnavailableError(f"Network error contacting OpenRouter: {e}")

        # Handle HTTP-level errors
        if response.status_code == 401:
            raise InvalidAPIKeyError("Invalid or expired OpenRouter API key.")
        if response.status_code == 402:
            raise PaymentRequiredError("Payment required for this model or account.")
        if response.status_code == 429:
            raise RateLimitError("OpenRouter rate limit exceeded.")
        if response.status_code == 404 and "model" in response.text.lower():
            raise UnsupportedModelError(f"Model '{self.model}' is not available on OpenRouter.")
        if response.status_code >= 500:
            raise ProviderUnavailableError(f"OpenRouter server error: HTTP {response.status_code}")

        response.raise_for_status()

        data = response.json()

        # Extract content
        choices = data.get("choices", [])
        if not choices:
            raise EmptyResponseError("OpenRouter returned no choices in the response.")

        content = choices[0].get("message", {}).get("content", "").strip()
        if not content:
            raise EmptyResponseError("OpenRouter returned an empty message content.")

        return content

    def chat_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Send a chat request with tool definitions via OpenRouter.

        Returns (text_response, tool_calls).
        """
        self._check_api_key()

        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 4096),
        }

        try:
            response = self.session.post(
                OPENROUTER_API_URL,
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Request to OpenRouter timed out after {self.timeout}s.")
        except requests.exceptions.ConnectionError:
            raise ProviderUnavailableError("Cannot connect to OpenRouter API.")
        except requests.exceptions.RequestException as e:
            raise ProviderUnavailableError(f"Network error contacting OpenRouter: {e}")

        if response.status_code == 401:
            raise InvalidAPIKeyError("Invalid or expired OpenRouter API key.")
        if response.status_code == 402:
            raise PaymentRequiredError("Payment required for this model or account.")
        if response.status_code == 429:
            raise RateLimitError("OpenRouter rate limit exceeded.")
        if response.status_code >= 500:
            raise ProviderUnavailableError(f"OpenRouter server error: HTTP {response.status_code}")

        response.raise_for_status()
        data = response.json()

        choices = data.get("choices", [])
        if not choices:
            raise EmptyResponseError("OpenRouter returned no choices in the response.")

        message = choices[0].get("message", {})
        content = message.get("content", "").strip() if message else ""

        # Extract tool calls from the OpenRouter format
        tool_calls = []
        raw_tool_calls = message.get("tool_calls", []) if message else []
        for tc in raw_tool_calls:
            func = tc.get("function", {})
            try:
                args = json.loads(func.get("arguments", "{}"))
            except (json.JSONDecodeError, TypeError):
                args = {}
            tool_calls.append({
                "name": func.get("name", ""),
                "arguments": args,
                "id": tc.get("id", ""),
            })

        return content, tool_calls

    def validate_connection(self) -> bool:
        """Validate the OpenRouter connection by listing available models."""
        self._check_api_key()
        try:
            response = self.session.get(
                OPENROUTER_MODELS_URL,
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError:
            raise ProviderUnavailableError("Cannot connect to OpenRouter API.")
        except requests.exceptions.Timeout:
            raise TimeoutError("Connection to OpenRouter timed out.")

        if response.status_code == 401:
            raise InvalidAPIKeyError("Invalid OpenRouter API key.")
        if response.status_code == 429:
            raise RateLimitError("OpenRouter rate limit exceeded.")
        response.raise_for_status()
        return True

    def _check_api_key(self) -> None:
        """Raise InvalidAPIKeyError if the key is empty."""
        if not self.api_key or not self.api_key.strip():
            raise InvalidAPIKeyError("OpenRouter API key is empty or not set.")
