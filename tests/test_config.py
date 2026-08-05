"""Tests for configuration management."""

import os
import unittest
from unittest.mock import patch

# Ensure project root is on the path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config


class TestConfigFromEnv(unittest.TestCase):
    """Test Config.from_env() with various environment setups."""

    def setUp(self):
        """Clear relevant env vars before each test."""
        for var in [
            "LLM_PROVIDER", "OPENROUTER_API_KEY", "OPENROUTER_MODEL",
            "OPENCODE_API_KEY", "OPENCODE_MODEL", "MODEL_TIMEOUT",
            "CTF_WORKSPACE", "MAX_AGENT_STEPS", "TOOL_TIMEOUT_SECONDS",
            "MAX_TOOL_OUTPUT_CHARS", "ALLOW_LOCALHOST_TARGETS",
            "ALLOW_PRIVATE_TARGETS", "HTTP_TIMEOUT_SECONDS",
            "MAX_HTTP_BODY_CHARS", "MAX_REDIRECTS", "HTTP_USER_AGENT",
            "SKILLS_DIRECTORY", "ENABLE_SKILLS", "MAX_ACTIVE_SKILLS",
            "MAX_SKILL_CONTEXT_CHARS", "SKILL_AUTO_SELECTION",
            "SKILL_MIN_SCORE", "SKILLS_REPOSITORY_URL",
            "SKILLS_REPOSITORY_BRANCH", "SKILLS_SYNC_DIRECTORY",
            "ENABLE_AUTONOMOUS_MODE", "MAX_TOOL_RETRIES",
            "TOOL_RETRY_DELAY_SECONDS", "ENABLE_SESSION_MEMORY",
            "MAX_EVIDENCE_ENTRIES",
        ]:
            os.environ.pop(var, None)

    def test_defaults(self):
        """With no env vars set, defaults should apply."""
        config = Config.from_env()
        self.assertEqual(config.provider, "openrouter")
        self.assertEqual(config.openrouter_model, "ling-3.0")
        self.assertEqual(config.opencode_model, "opencode-default")
        self.assertEqual(config.model_timeout, 30)
        self.assertEqual(config.active_model, "ling-3.0")

    def test_skill_defaults(self):
        """Skill config defaults should apply with no env vars."""
        config = Config.from_env()
        self.assertEqual(config.skills_directory, "skills")
        self.assertTrue(config.enable_skills)
        self.assertEqual(config.max_active_skills, 5)
        self.assertEqual(config.max_skill_context_chars, 4000)
        self.assertTrue(config.skill_auto_selection)
        self.assertEqual(config.skill_min_score, 0.3)
        self.assertEqual(config.skills_repository_url, "")
        self.assertEqual(config.skills_repository_branch, "main")
        self.assertEqual(config.skills_sync_directory, "skills/downloaded")

    def test_skill_env_overrides(self):
        """Skill env vars should override defaults."""
        os.environ["SKILLS_DIRECTORY"] = "my-skills"
        os.environ["ENABLE_SKILLS"] = "false"
        os.environ["MAX_ACTIVE_SKILLS"] = "3"
        os.environ["MAX_SKILL_CONTEXT_CHARS"] = "2000"
        os.environ["SKILL_AUTO_SELECTION"] = "false"
        os.environ["SKILL_MIN_SCORE"] = "0.5"
        os.environ["SKILLS_REPOSITORY_URL"] = "https://github.com/x/skills"
        os.environ["SKILLS_REPOSITORY_BRANCH"] = "dev"
        os.environ["SKILLS_SYNC_DIRECTORY"] = "custom/downloaded"
        config = Config.from_env()
        self.assertEqual(config.skills_directory, "my-skills")
        self.assertFalse(config.enable_skills)
        self.assertEqual(config.max_active_skills, 3)
        self.assertEqual(config.max_skill_context_chars, 2000)
        self.assertFalse(config.skill_auto_selection)
        self.assertEqual(config.skill_min_score, 0.5)
        self.assertEqual(config.skills_repository_url, "https://github.com/x/skills")
        self.assertEqual(config.skills_repository_branch, "dev")
        self.assertEqual(config.skills_sync_directory, "custom/downloaded")

    def test_skill_dataclass_defaults(self):
        """Skill fields on a plain Config() instance."""
        config = Config()
        self.assertTrue(config.enable_skills)
        self.assertEqual(config.max_active_skills, 5)
        self.assertEqual(config.skill_min_score, 0.3)

    def test_stage6_defaults(self):
        """Stage 6 config defaults should apply with no env vars."""
        config = Config.from_env()
        self.assertTrue(config.enable_autonomous_mode)
        self.assertEqual(config.max_tool_retries, 2)
        self.assertEqual(config.tool_retry_delay, 0.5)
        self.assertTrue(config.enable_session_memory)
        self.assertEqual(config.max_evidence_entries, 200)

    def test_stage6_env_overrides(self):
        """Stage 6 env vars should override defaults."""
        os.environ["ENABLE_AUTONOMOUS_MODE"] = "false"
        os.environ["MAX_TOOL_RETRIES"] = "5"
        os.environ["TOOL_RETRY_DELAY_SECONDS"] = "1.5"
        os.environ["ENABLE_SESSION_MEMORY"] = "false"
        os.environ["MAX_EVIDENCE_ENTRIES"] = "50"
        config = Config.from_env()
        self.assertFalse(config.enable_autonomous_mode)
        self.assertEqual(config.max_tool_retries, 5)
        self.assertEqual(config.tool_retry_delay, 1.5)
        self.assertFalse(config.enable_session_memory)
        self.assertEqual(config.max_evidence_entries, 50)

    def test_stage6_dataclass_defaults(self):
        """Stage 6 fields on a plain Config() instance."""
        config = Config()
        self.assertTrue(config.enable_autonomous_mode)
        self.assertEqual(config.max_tool_retries, 2)
        self.assertTrue(config.enable_session_memory)

    def test_custom_provider(self):
        """LLM_PROVIDER should override the default."""
        os.environ["LLM_PROVIDER"] = "opencode"
        config = Config.from_env()
        self.assertEqual(config.provider, "opencode")

    def test_custom_openrouter_model(self):
        """OPENROUTER_MODEL should be respected."""
        os.environ["OPENROUTER_MODEL"] = "custom-model-v1"
        config = Config.from_env()
        self.assertEqual(config.openrouter_model, "custom-model-v1")
        self.assertEqual(config.active_model, "custom-model-v1")

    def test_custom_opencode_model(self):
        """OPENCODE_MODEL should be respected."""
        os.environ["LLM_PROVIDER"] = "opencode"
        os.environ["OPENCODE_MODEL"] = "custom-oc-model"
        config = Config.from_env()
        self.assertEqual(config.opencode_model, "custom-oc-model")
        self.assertEqual(config.active_model, "custom-oc-model")

    def test_custom_timeout(self):
        """MODEL_TIMEOUT should be parsed as int."""
        os.environ["MODEL_TIMEOUT"] = "60"
        config = Config.from_env()
        self.assertEqual(config.model_timeout, 60)

    def test_ctf_workspace_default(self):
        """CTF_WORKSPACE should default to challenges."""
        config = Config.from_env()
        self.assertEqual(config.ctf_workspace, "challenges")

    def test_ctf_workspace_custom(self):
        """CTF_WORKSPACE should be read from env."""
        os.environ["CTF_WORKSPACE"] = "custom_challenges"
        config = Config.from_env()
        self.assertEqual(config.ctf_workspace, "custom_challenges")

    def test_max_agent_steps_default(self):
        """MAX_AGENT_STEPS should default to 10."""
        config = Config.from_env()
        self.assertEqual(config.max_agent_steps, 10)

    def test_max_agent_steps_custom(self):
        """MAX_AGENT_STEPS should be read from env."""
        os.environ["MAX_AGENT_STEPS"] = "25"
        config = Config.from_env()
        self.assertEqual(config.max_agent_steps, 25)

    def test_tool_timeout_seconds_default(self):
        """TOOL_TIMEOUT_SECONDS should default to 30."""
        config = Config.from_env()
        self.assertEqual(config.tool_timeout_seconds, 30)

    def test_tool_timeout_seconds_custom(self):
        """TOOL_TIMEOUT_SECONDS should be read from env."""
        os.environ["TOOL_TIMEOUT_SECONDS"] = "45"
        config = Config.from_env()
        self.assertEqual(config.tool_timeout_seconds, 45)

    def test_max_tool_output_chars_default(self):
        """MAX_TOOL_OUTPUT_CHARS should default to 4096."""
        config = Config.from_env()
        self.assertEqual(config.max_tool_output_chars, 4096)

    def test_max_tool_output_chars_custom(self):
        """MAX_TOOL_OUTPUT_CHARS should be read from env."""
        os.environ["MAX_TOOL_OUTPUT_CHARS"] = "8192"
        config = Config.from_env()
        self.assertEqual(config.max_tool_output_chars, 8192)

    def test_http_defaults_restrictive(self):
        """HTTP security defaults should be restrictive."""
        config = Config.from_env()
        self.assertFalse(config.allow_localhost_targets)
        self.assertFalse(config.allow_private_targets)
        self.assertEqual(config.http_timeout_seconds, 10)
        self.assertEqual(config.max_http_body_chars, 3000)
        self.assertEqual(config.max_redirects, 5)
        self.assertIn("CTF-Agent", config.http_user_agent)

    def test_http_env_overrides(self):
        """HTTP env vars should override defaults."""
        os.environ["ALLOW_LOCALHOST_TARGETS"] = "true"
        os.environ["ALLOW_PRIVATE_TARGETS"] = "1"
        os.environ["HTTP_TIMEOUT_SECONDS"] = "20"
        os.environ["MAX_HTTP_BODY_CHARS"] = "5000"
        os.environ["MAX_REDIRECTS"] = "8"
        os.environ["HTTP_USER_AGENT"] = "custom-agent/1.0"
        config = Config.from_env()
        self.assertTrue(config.allow_localhost_targets)
        self.assertTrue(config.allow_private_targets)
        self.assertEqual(config.http_timeout_seconds, 20)
        self.assertEqual(config.max_http_body_chars, 5000)
        self.assertEqual(config.max_redirects, 8)
        self.assertEqual(config.http_user_agent, "custom-agent/1.0")

    def test_api_keys_from_env(self):
        """API keys should be read from env vars."""
        os.environ["OPENROUTER_API_KEY"] = "sk-or-test-key-123"
        config = Config.from_env()
        self.assertEqual(config.openrouter_api_key, "sk-or-test-key-123")

    def test_opencode_api_key(self):
        """OpenCode API key should be read from env."""
        os.environ["OPENCODE_API_KEY"] = "sk-oc-test-key-456"
        config = Config.from_env()
        self.assertEqual(config.opencode_api_key, "sk-oc-test-key-456")

    def test_get_api_key_openrouter(self):
        """get_api_key returns the OpenRouter key when provider is openrouter."""
        config = Config(
            provider="openrouter",
            openrouter_api_key="sk-or-key",
            opencode_api_key="sk-oc-key",
        )
        self.assertEqual(config.get_api_key(), "sk-or-key")

    def test_get_api_key_opencode(self):
        """get_api_key returns the OpenCode key when provider is opencode."""
        config = Config(
            provider="opencode",
            openrouter_api_key="sk-or-key",
            opencode_api_key="sk-oc-key",
        )
        self.assertEqual(config.get_api_key(), "sk-oc-key")

    def test_get_model_openrouter(self):
        """get_model returns the OpenRouter model when provider is openrouter."""
        config = Config(
            provider="openrouter",
            openrouter_model="ling-3.0",
            opencode_model="oc-model",
        )
        self.assertEqual(config.get_model(), "ling-3.0")

    def test_get_model_opencode(self):
        """get_model returns the OpenCode model when provider is opencode."""
        config = Config(
            provider="opencode",
            openrouter_model="ling-3.0",
            opencode_model="oc-model",
        )
        self.assertEqual(config.get_model(), "oc-model")

    def test_validate_missing_api_key(self):
        """Validation should fail when API key is missing."""
        config = Config(provider="openrouter")
        errors = config.validate()
        self.assertIn("No API key", errors[0])

    def test_validate_unsupported_provider(self):
        """Validation should fail for an unsupported provider."""
        config = Config(provider="fakeprovider")
        errors = config.validate()
        self.assertTrue(any("Unsupported provider" in e for e in errors))

    def test_validate_valid_config(self):
        """Validation should pass with all required fields set."""
        config = Config(
            provider="openrouter",
            openrouter_api_key="sk-test-key",
            openrouter_model="ling-3.0",
        )
        errors = config.validate()
        self.assertEqual(errors, [])


class TestConfigDataclass(unittest.TestCase):
    """Test Config as a plain dataclass."""

    def test_default_active_model(self):
        """active_model defaults to ling-3.0."""
        config = Config()
        self.assertEqual(config.active_model, "ling-3.0")

    def test_field_overrides(self):
        """Explicit field values should be preserved."""
        config = Config(
            provider="opencode",
            opencode_model="my-model",
            model_timeout=60,
        )
        self.assertEqual(config.provider, "opencode")
        self.assertEqual(config.opencode_model, "my-model")
        self.assertEqual(config.model_timeout, 60)
