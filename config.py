"""Configuration management using environment variables."""

import os
from dataclasses import dataclass, field
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class Config:
    """Holds all configuration for the CTF Agent."""

    # Provider selection
    provider: str = field(default="openrouter")
    # Model names per provider
    openrouter_model: str = field(default="ling-3.0")
    opencode_model: str = field(default="opencode-default")
    # API keys
    openrouter_api_key: Optional[str] = None
    opencode_api_key: Optional[str] = None
    # Timeout in seconds for model requests
    model_timeout: int = field(default=30)
    # Active model (resolved from provider + env)
    active_model: str = field(default="ling-3.0")
    # Authorized challenge workspace directory
    ctf_workspace: str = field(default="challenges")
    # Maximum number of agent tool-execution steps per request
    max_agent_steps: int = field(default=10)
    # Timeout in seconds for command execution tools
    tool_timeout_seconds: int = field(default=30)
    # Maximum output characters per tool result
    max_tool_output_chars: int = field(default=4096)
    # HTTP tools: allow requests to localhost/private networks
    allow_localhost_targets: bool = field(default=False)
    allow_private_targets: bool = field(default=False)
    # HTTP tools: request timeout in seconds
    http_timeout_seconds: int = field(default=10)
    # HTTP tools: maximum response body characters shown
    max_http_body_chars: int = field(default=3000)
    # HTTP tools: maximum number of redirects to follow
    max_redirects: int = field(default=5)
    # HTTP tools: user agent string
    http_user_agent: str = field(
        default="CTF-Agent/1.0 (educational; authorized targets only)"
    )
    # Skill system: directory of skill markdown files
    skills_directory: str = field(default="skills")
    # Skill system: master switch
    enable_skills: bool = field(default=True)
    # Skill system: maximum number of active skills loaded into context
    max_active_skills: int = field(default=5)
    # Skill system: maximum context characters per skill
    max_skill_context_chars: int = field(default=4000)
    # Skill system: auto-select skills from the current context
    skill_auto_selection: bool = field(default=True)
    # Skill system: minimum deterministic score for auto-selection
    skill_min_score: float = field(default=0.3)
    # Skill sync: GitHub repository URL (empty = disabled)
    skills_repository_url: str = field(default="")
    # Skill sync: branch to fetch
    skills_repository_branch: str = field(default="main")
    # Skill sync: local directory for downloaded skills
    skills_sync_directory: str = field(default="skills/downloaded")
    # Stage 6: master switch for autonomous reasoning (plan/evidence/memory/report)
    enable_autonomous_mode: bool = field(default=True)
    # Stage 6: maximum retries for transient tool failures (timeouts/network)
    max_tool_retries: int = field(default=2)
    # Stage 6: delay in seconds between tool retries
    tool_retry_delay: float = field(default=0.5)
    # Stage 6: master switch for session memory
    enable_session_memory: bool = field(default=True)
    # Stage 6: maximum evidence entries kept per session
    max_evidence_entries: int = field(default=200)
    # Stage 7: master switch for specialist workflows
    enable_specialists: bool = field(default=True)
    # Stage 7: minimum relevance score for a specialist to be suggested
    specialist_min_score: float = field(default=0.25)
    # Stage 7: maximum specialists suggested per selection
    max_specialist_suggestions: int = field(default=3)
    # Stage 7: maximum explicit specialist executions per challenge
    max_specialist_calls: int = field(default=12)
    # Stage 7: maximum HTTP requests per challenge
    max_http_requests: int = field(default=40)
    # Stage 7: maximum command executions per challenge
    max_command_executions: int = field(default=30)
    # Stage 7: maximum identical actions within the duplicate window
    max_duplicate_actions: int = field(default=3)
    # Stage 7: duplicate-action detection window in seconds
    duplicate_action_window: int = field(default=90)
    # Stage 7: global challenge timeout in seconds (0 = disabled)
    global_challenge_timeout_seconds: int = field(default=1800)
    # Stage 7: optional pwntools integration (spec 9)
    enable_pwntools: bool = field(default=False)

    @classmethod
    def from_env(cls) -> "Config":
        """Build Config from environment variables."""
        provider = os.environ.get("LLM_PROVIDER", "openrouter").strip().lower()
        openrouter_model = os.environ.get("OPENROUTER_MODEL", "ling-3.0").strip()
        opencode_model = os.environ.get("OPENCODE_MODEL", "opencode-default").strip()
        openrouter_api_key = os.environ.get("OPENROUTER_API_KEY")
        opencode_api_key = os.environ.get("OPENCODE_API_KEY")
        model_timeout = int(os.environ.get("MODEL_TIMEOUT", "30"))
        ctf_workspace = os.environ.get("CTF_WORKSPACE", "challenges").strip()
        max_agent_steps = int(os.environ.get("MAX_AGENT_STEPS", "10"))
        tool_timeout_seconds = int(os.environ.get("TOOL_TIMEOUT_SECONDS", "30"))
        max_tool_output_chars = int(os.environ.get("MAX_TOOL_OUTPUT_CHARS", "4096"))
        allow_localhost_targets = os.environ.get("ALLOW_LOCALHOST_TARGETS", "false").strip().lower() in ("1", "true", "yes")
        allow_private_targets = os.environ.get("ALLOW_PRIVATE_TARGETS", "false").strip().lower() in ("1", "true", "yes")
        http_timeout_seconds = int(os.environ.get("HTTP_TIMEOUT_SECONDS", "10"))
        max_http_body_chars = int(os.environ.get("MAX_HTTP_BODY_CHARS", "3000"))
        max_redirects = int(os.environ.get("MAX_REDIRECTS", "5"))
        http_user_agent = os.environ.get(
            "HTTP_USER_AGENT",
            "CTF-Agent/1.0 (educational; authorized targets only)",
        )
        skills_directory = os.environ.get("SKILLS_DIRECTORY", "skills").strip()
        enable_skills = os.environ.get("ENABLE_SKILLS", "true").strip().lower() in ("1", "true", "yes")
        max_active_skills = int(os.environ.get("MAX_ACTIVE_SKILLS", "5"))
        max_skill_context_chars = int(os.environ.get("MAX_SKILL_CONTEXT_CHARS", "4000"))
        skill_auto_selection = os.environ.get("SKILL_AUTO_SELECTION", "true").strip().lower() in ("1", "true", "yes")
        skill_min_score = float(os.environ.get("SKILL_MIN_SCORE", "0.3"))
        skills_repository_url = os.environ.get("SKILLS_REPOSITORY_URL", "").strip()
        skills_repository_branch = os.environ.get("SKILLS_REPOSITORY_BRANCH", "main").strip()
        skills_sync_directory = os.environ.get("SKILLS_SYNC_DIRECTORY", "skills/downloaded").strip()
        enable_autonomous_mode = os.environ.get("ENABLE_AUTONOMOUS_MODE", "true").strip().lower() in ("1", "true", "yes")
        max_tool_retries = int(os.environ.get("MAX_TOOL_RETRIES", "2"))
        tool_retry_delay = float(os.environ.get("TOOL_RETRY_DELAY_SECONDS", "0.5"))
        enable_session_memory = os.environ.get("ENABLE_SESSION_MEMORY", "true").strip().lower() in ("1", "true", "yes")
        max_evidence_entries = int(os.environ.get("MAX_EVIDENCE_ENTRIES", "200"))
        enable_specialists = os.environ.get("ENABLE_SPECIALISTS", "true").strip().lower() in ("1", "true", "yes")
        specialist_min_score = float(os.environ.get("SPECIALIST_MIN_SCORE", "0.25"))
        max_specialist_suggestions = int(os.environ.get("MAX_SPECIALIST_SUGGESTIONS", "3"))
        max_specialist_calls = int(os.environ.get("MAX_SPECIALIST_CALLS", "12"))
        max_http_requests = int(os.environ.get("MAX_HTTP_REQUESTS", "40"))
        max_command_executions = int(os.environ.get("MAX_COMMAND_EXECUTIONS", "30"))
        max_duplicate_actions = int(os.environ.get("MAX_DUPLICATE_ACTIONS", "3"))
        duplicate_action_window = int(os.environ.get("DUPLICATE_ACTION_WINDOW", "90"))
        global_challenge_timeout_seconds = int(os.environ.get("GLOBAL_CHALLENGE_TIMEOUT_SECONDS", "1800"))
        enable_pwntools = os.environ.get("ENABLE_PWNTOOLS", "false").strip().lower() in ("1", "true", "yes")

        # Resolve active model
        if provider == "openrouter":
            active_model = openrouter_model
        elif provider == "opencode":
            active_model = opencode_model
        else:
            active_model = openrouter_model

        return cls(
            provider=provider,
            openrouter_model=openrouter_model,
            opencode_model=opencode_model,
            openrouter_api_key=openrouter_api_key,
            opencode_api_key=opencode_api_key,
            model_timeout=model_timeout,
            active_model=active_model,
            ctf_workspace=ctf_workspace,
            max_agent_steps=max_agent_steps,
            tool_timeout_seconds=tool_timeout_seconds,
            max_tool_output_chars=max_tool_output_chars,
            allow_localhost_targets=allow_localhost_targets,
            allow_private_targets=allow_private_targets,
            http_timeout_seconds=http_timeout_seconds,
            max_http_body_chars=max_http_body_chars,
            max_redirects=max_redirects,
            http_user_agent=http_user_agent,
            skills_directory=skills_directory,
            enable_skills=enable_skills,
            max_active_skills=max_active_skills,
            max_skill_context_chars=max_skill_context_chars,
            skill_auto_selection=skill_auto_selection,
            skill_min_score=skill_min_score,
            skills_repository_url=skills_repository_url,
            skills_repository_branch=skills_repository_branch,
            skills_sync_directory=skills_sync_directory,
            enable_autonomous_mode=enable_autonomous_mode,
            max_tool_retries=max_tool_retries,
            tool_retry_delay=tool_retry_delay,
            enable_session_memory=enable_session_memory,
            max_evidence_entries=max_evidence_entries,
            enable_specialists=enable_specialists,
            specialist_min_score=specialist_min_score,
            max_specialist_suggestions=max_specialist_suggestions,
            max_specialist_calls=max_specialist_calls,
            max_http_requests=max_http_requests,
            max_command_executions=max_command_executions,
            max_duplicate_actions=max_duplicate_actions,
            duplicate_action_window=duplicate_action_window,
            global_challenge_timeout_seconds=global_challenge_timeout_seconds,
            enable_pwntools=enable_pwntools,
        )

    def get_api_key(self) -> Optional[str]:
        """Return the API key for the currently configured provider."""
        if self.provider == "openrouter":
            return self.openrouter_api_key
        elif self.provider == "opencode":
            return self.opencode_api_key
        return None

    def get_model(self) -> str:
        """Return the model name for the currently configured provider."""
        if self.provider == "openrouter":
            return self.openrouter_model
        elif self.provider == "opencode":
            return self.opencode_model
        return self.openrouter_model

    def validate(self) -> list[str]:
        """Return a list of validation errors. Empty list means valid."""
        errors = []
        if self.provider not in ("openrouter", "opencode"):
            errors.append(f"Unsupported provider: {self.provider}")
        if not self.get_api_key():
            errors.append(f"No API key set for provider '{self.provider}'")
        if not self.get_model():
            errors.append(f"No model configured for provider '{self.provider}'")
        return errors
