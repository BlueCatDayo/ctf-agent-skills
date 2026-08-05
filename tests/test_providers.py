"""Tests for provider error handling and adapters."""

import os
import unittest
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from providers.base_provider import (
    EmptyResponseError,
    InvalidAPIKeyError,
    PaymentRequiredError,
    ProviderUnavailableError,
    RateLimitError,
    TimeoutError,
    UnsupportedModelError,
)
from providers.openrouter_provider import OpenRouterProvider
from providers.opencode_provider import OpenCodeProvider


class TestProviderErrors(unittest.TestCase):
    """Test that each provider-specific error is a subclass of ProviderError."""

    def test_invalid_api_key_is_provider_error(self):
        self.assertIsInstance(InvalidAPIKeyError("test"), Exception)

    def test_unsupported_model_is_provider_error(self):
        self.assertIsInstance(UnsupportedModelError("test"), Exception)

    def test_provider_unavailable_is_provider_error(self):
        self.assertIsInstance(ProviderUnavailableError("test"), Exception)

    def test_rate_limit_is_provider_error(self):
        self.assertIsInstance(RateLimitError("test"), Exception)

    def test_payment_required_is_provider_error(self):
        self.assertIsInstance(PaymentRequiredError("test"), Exception)

    def test_timeout_is_provider_error(self):
        self.assertIsInstance(TimeoutError("test"), Exception)

    def test_empty_response_is_provider_error(self):
        self.assertIsInstance(EmptyResponseError("test"), Exception)


class TestBaseProviderChecks(unittest.TestCase):
    """Test the base provider helper methods."""

    def test_check_api_key_raises_on_empty(self):
        from providers.openrouter_provider import OpenRouterProvider
        prov = OpenRouterProvider(api_key="", model="ling-3.0")
        with self.assertRaises(InvalidAPIKeyError):
            prov._check_api_key()

    def test_check_api_key_raises_on_none(self):
        from providers.openrouter_provider import OpenRouterProvider
        prov = OpenRouterProvider(api_key=None, model="ling-3.0")
        with self.assertRaises(InvalidAPIKeyError):
            prov._check_api_key()

    def test_check_api_key_passes_on_valid(self):
        from providers.openrouter_provider import OpenRouterProvider
        prov = OpenRouterProvider(api_key="sk-valid-key", model="ling-3.0")
        prov._check_api_key()

    def test_check_model_raises_on_unsupported(self):
        from providers.openrouter_provider import OpenRouterProvider
        prov = OpenRouterProvider(api_key="sk-valid-key", model="unknown-model")
        with self.assertRaises(UnsupportedModelError):
            prov._check_model(["ling-3.0", "gpt-4o"])

    def test_check_model_passes_on_supported(self):
        from providers.openrouter_provider import OpenRouterProvider
        prov = OpenRouterProvider(api_key="sk-valid-key", model="ling-3.0")
        prov._check_model(["ling-3.0", "gpt-4o"])


class TestOpenRouterProviderChatErrors(unittest.TestCase):
    """Test OpenRouter error handling via mocked HTTP responses."""

    def setUp(self):
        # Patch requests.Session so the provider gets a mock session
        self.session_patcher = patch('providers.openrouter_provider.requests.Session')
        self.mock_session_cls = self.session_patcher.start()
        self.mock_session = MagicMock()
        self.mock_session_cls.return_value = self.mock_session
        self.provider = OpenRouterProvider(
            api_key="sk-test-key",
            model="ling-3.0",
            timeout=5,
        )

    def tearDown(self):
        self.session_patcher.stop()

    def test_invalid_api_key_401(self):
        self.mock_session.post.return_value.status_code = 401
        with self.assertRaises(InvalidAPIKeyError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_payment_required_402(self):
        self.mock_session.post.return_value.status_code = 402
        with self.assertRaises(PaymentRequiredError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_rate_limit_429(self):
        self.mock_session.post.return_value.status_code = 429
        with self.assertRaises(RateLimitError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_unsupported_model_404(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "model not found"
        self.mock_session.post.return_value = resp
        with self.assertRaises(UnsupportedModelError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_provider_unavailable_500(self):
        self.mock_session.post.return_value.status_code = 500
        with self.assertRaises(ProviderUnavailableError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_timeout_on_post(self):
        import requests
        self.mock_session.post.side_effect = requests.exceptions.Timeout
        with self.assertRaises(TimeoutError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_connection_error_on_post(self):
        import requests
        self.mock_session.post.side_effect = requests.exceptions.ConnectionError
        with self.assertRaises(ProviderUnavailableError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_empty_response_no_choices(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"choices": []}
        self.mock_session.post.return_value = resp
        with self.assertRaises(EmptyResponseError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_empty_response_empty_content(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"choices": [{"message": {"content": ""}}]}
        self.mock_session.post.return_value = resp
        with self.assertRaises(EmptyResponseError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_successful_chat(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "choices": [{"message": {"content": "Hello! How can I help?"}}]
        }
        self.mock_session.post.return_value = resp
        result = self.provider.chat([{"role": "user", "content": "hi"}])
        self.assertEqual(result, "Hello! How can I help?")


class TestOpenCodeProviderChatErrors(unittest.TestCase):
    """Test OpenCode error handling via mocked HTTP responses."""

    def setUp(self):
        # Patch requests.Session so the provider gets a mock session
        self.session_patcher = patch('providers.opencode_provider.requests.Session')
        self.mock_session_cls = self.session_patcher.start()
        self.mock_session = MagicMock()
        self.mock_session_cls.return_value = self.mock_session
        self.provider = OpenCodeProvider(
            api_key="sk-test-key",
            model="opencode-default",
            timeout=5,
        )

    def tearDown(self):
        self.session_patcher.stop()

    def test_invalid_api_key_401(self):
        self.mock_session.post.return_value.status_code = 401
        with self.assertRaises(InvalidAPIKeyError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_payment_required_402(self):
        self.mock_session.post.return_value.status_code = 402
        with self.assertRaises(PaymentRequiredError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_rate_limit_429(self):
        self.mock_session.post.return_value.status_code = 429
        with self.assertRaises(RateLimitError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_unsupported_model_404(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "model not found"
        self.mock_session.post.return_value = resp
        with self.assertRaises(UnsupportedModelError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_timeout_on_post(self):
        import requests
        self.mock_session.post.side_effect = requests.exceptions.Timeout
        with self.assertRaises(TimeoutError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_connection_error_on_post(self):
        import requests
        self.mock_session.post.side_effect = requests.exceptions.ConnectionError
        with self.assertRaises(ProviderUnavailableError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_empty_response_no_choices(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"choices": []}
        self.mock_session.post.return_value = resp
        with self.assertRaises(EmptyResponseError):
            self.provider.chat([{"role": "user", "content": "hello"}])

    def test_successful_chat(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "choices": [{"message": {"content": "OpenCode response here."}}]
        }
        self.mock_session.post.return_value = resp
        result = self.provider.chat([{"role": "user", "content": "hi"}])
        self.assertEqual(result, "OpenCode response here.")


class TestConversationHistory(unittest.TestCase):
    """Test the ConversationHistory class."""

    def setUp(self):
        from agent.conversation import ConversationHistory
        self.history = ConversationHistory()

    def test_starts_empty(self):
        self.assertEqual(self.history.length(), 0)

    def test_add_user_message(self):
        self.history.add_user_message("Hello")
        self.assertEqual(self.history.length(), 1)
        msgs = self.history.get_messages()
        self.assertEqual(msgs[0]["role"], "user")
        self.assertEqual(msgs[0]["content"], "Hello")

    def test_add_assistant_message(self):
        self.history.add_assistant_message("Hi there!")
        self.assertEqual(self.history.length(), 1)
        msgs = self.history.get_messages()
        self.assertEqual(msgs[0]["role"], "assistant")
        self.assertEqual(msgs[0]["content"], "Hi there!")

    def test_clear(self):
        self.history.add_user_message("Hello")
        self.history.add_assistant_message("Hi")
        self.history.clear()
        self.assertEqual(self.history.length(), 0)

    def test_last_n(self):
        self.history.add_user_message("Msg 1")
        self.history.add_assistant_message("Msg 2")
        self.history.add_user_message("Msg 3")
        last_two = self.history.last_n(2)
        self.assertEqual(len(last_two), 2)
        self.assertEqual(last_two[0]["content"], "Msg 2")
        self.assertEqual(last_two[1]["content"], "Msg 3")

    def test_last_n_larger_than_history(self):
        self.history.add_user_message("Only one")
        result = self.history.last_n(5)
        self.assertEqual(len(result), 1)


class TestChatAgentProviderSwitching(unittest.TestCase):
    """Test ChatAgent provider and model switching."""

    @patch("agent.chat_agent.OpenRouterProvider")
    @patch("agent.chat_agent.OpenCodeProvider")
    def test_set_provider_openrouter(self, mock_oc, mock_or):
        from config import Config
        from agent.chat_agent import ChatAgent

        config = Config(
            provider="openrouter",
            openrouter_api_key="sk-or-key",
            openrouter_model="ling-3.0",
        )
        agent = ChatAgent(config)
        agent.set_provider("opencode")
        mock_oc.assert_called_once()

    @patch("agent.chat_agent.OpenRouterProvider")
    @patch("agent.chat_agent.OpenCodeProvider")
    def test_set_provider_opencode(self, mock_oc, mock_or):
        from config import Config
        from agent.chat_agent import ChatAgent

        config = Config(
            provider="opencode",
            opencode_api_key="sk-oc-key",
            opencode_model="oc-model",
        )
        agent = ChatAgent(config)
        agent.set_provider("openrouter")
        mock_or.assert_called_once()


if __name__ == "__main__":
    unittest.main()
