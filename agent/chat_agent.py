"""Main conversational AI agent with tool-calling support."""

import json
import sys
from typing import Any, Dict, List, Optional

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


class ChatAgent:
    """Conversational AI agent that delegates to a provider adapter."""

    def __init__(self, config: "Config"):
        from config import Config
        self.config = config
        self.provider = self._create_provider()
        self._history = None
        self._tool_registry = None
        self._skill_registry = None
        self._skill_router = None
        self._init_stage6()
        self._init_stage7()

    # ------------------------------------------------------------------
    # Stage 6: autonomous reasoning components
    # ------------------------------------------------------------------

    def _init_stage6(self) -> None:
        """Initialize planner, memory, evidence, and workflow components."""
        from agent.evidence import EvidenceLog
        from agent.memory import SessionMemory
        from agent.planner import Planner
        from agent.workflow import WorkflowManager

        self._memory = SessionMemory(
            max_entries=getattr(self.config, "max_evidence_entries", 200)
        )
        self._evidence = EvidenceLog(
            max_entries=getattr(self.config, "max_evidence_entries", 200)
        )
        self._planner = Planner(max_steps=10)
        self._workflow = WorkflowManager()
        self._challenge_type = ""
        self._challenge_confidence = 0.0
        self._challenge_reasons: List[str] = []
        self._plan = []
        self._last_progress: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Stage 7: specialist workflows and resource limits
    # ------------------------------------------------------------------

    def _init_stage7(self) -> None:
        """Initialize the specialist router and resource limits."""
        from specialists.limits import ResourceLimits
        from specialists.router import SpecialistRouter

        self._limits = ResourceLimits(
            max_specialist_calls=getattr(self.config, "max_specialist_calls", 12),
            max_http_requests=getattr(self.config, "max_http_requests", 40),
            max_command_executions=getattr(self.config, "max_command_executions", 30),
            max_retries=getattr(self.config, "max_tool_retries", 2),
            max_output_chars=getattr(self.config, "max_tool_output_chars", 4096),
            per_tool_timeout=getattr(self.config, "tool_timeout_seconds", 30),
            global_timeout_seconds=getattr(self.config, "global_challenge_timeout_seconds", 1800),
            max_duplicate_actions=getattr(self.config, "max_duplicate_actions", 3),
            duplicate_window=getattr(self.config, "duplicate_action_window", 90),
        )

        self._specialist_router = SpecialistRouter(
            min_score=getattr(self.config, "specialist_min_score", 0.25),
            max_suggestions=getattr(self.config, "max_specialist_suggestions", 3),
        )
        self._specialist_recommendations = []
        self._used_specialists: List[str] = []

    @property
    def specialists_enabled(self) -> bool:
        """Return True when Stage 7 specialists are enabled."""
        return bool(getattr(self.config, "enable_specialists", True))

    def _register_specialists(self) -> None:
        """Register all specialist modules into the router."""
        if not self.specialists_enabled:
            return
        from specialists.binary import BINARY_SPECIALISTS
        from specialists.web import WEB_SPECIALISTS

        for cls in WEB_SPECIALISTS + BINARY_SPECIALISTS:
            self._specialist_router.register(
                cls(min_score=getattr(self.config, "specialist_min_score", 0.25))
            )

    def _evidence_snapshot(self) -> Any:
        """Build an evidence snapshot for the specialist router."""
        from specialists.base import EvidenceSnapshot
        return EvidenceSnapshot(self._evidence.items() if self._evidence else [])

    def _specialist_profile(self) -> Dict[str, Any]:
        """Build the challenge profile used by specialist scoring."""
        profile: Dict[str, Any] = {}
        if getattr(self, "_challenge_type", ""):
            profile["challenge_type"] = self._challenge_type
        if getattr(self, "_last_user_message", ""):
            profile["user_request"] = self._last_user_message
        files = self._memory.get("files") if self.memory_enabled else []
        if files:
            profile["file_path"] = files[-1] if isinstance(files[-1], str) else str(files[-1])
        return profile

    def _update_specialist_recommendations(self) -> None:
        """Re-rank specialist suggestions from current evidence."""
        if not self.specialists_enabled:
            self._specialist_recommendations = []
            return
        try:
            self._specialist_recommendations = self._specialist_router.select(
                self._evidence_snapshot(),
                profile=self._specialist_profile(),
                used=self._used_specialists,
            )
        except Exception:
            self._specialist_recommendations = []

    def _specialist_context_prompt(self) -> str:
        """Render top specialist suggestions as a prompt section."""
        if not self.specialists_enabled or not self._specialist_recommendations:
            return ""
        lines = ["## Specialist Guidance"]
        for rank in self._specialist_recommendations[:2]:
            lines.append(
                f"- {rank.specialist.name} (score {rank.score:.2f}): "
                f"{rank.specialist.description} [{rank.reason}]"
            )
        return "\n".join(lines)

    def stage7_command(self, raw_command: str) -> str:
        """Handle Stage 7 slash commands.

        /specialists            - list specialists and current recommendations
        /specialists <name>     - run one specialist explicitly (counted)
        /limits                 - show resource usage and limits
        """
        if not self._specialist_router.all() and self.specialists_enabled:
            self._register_specialists()
        parts = raw_command.strip().split(None, 1)
        command = parts[0].lower()

        if command == "/limits":
            usage = self._limits.usage()
            lines = ["## Resource Limits", self._limits.summary()]
            for key, val in usage["limits"].items():
                lines.append(f"- {key}: {val}")
            return "\n".join(lines)

        if command == "/specialists":
            if not self.specialists_enabled:
                return "Specialists are disabled (set ENABLE_SPECIALISTS=true)."
            if len(parts) > 1 and parts[1].strip():
                return self._run_specialist_command(parts[1].strip())
            lines = ["## Specialist Recommendations"]
            if not self._specialist_recommendations:
                self._update_specialist_recommendations()
            if not self._specialist_recommendations:
                lines.append("(no specialists match current evidence - inspect the challenge first)")
            for rank in self._specialist_recommendations:
                lines.append(
                    f"- {rank.specialist.name} (score {rank.score:.2f}): "
                    f"{rank.specialist.description} [{rank.reason}]"
                )
            lines.append("")
            lines.append(self._specialist_router.list_specialists())
            return "\n".join(lines)

        return "Unknown Stage 7 command. Usage: /specialists [name] | /limits"

    def _run_specialist_command(self, name: str) -> str:
        """Run one specialist explicitly and return its report."""
        specialist = self._specialist_router.get(name)
        if specialist is None:
            return (
                f"Unknown specialist: {name}. Use /specialists to list available "
                "specialists."
            )
        allowed, reason = self._limits.check_specialist()
        if not allowed:
            return f"{reason}\n\nStrongest evidence so far:\n{self._evidence_prompt()}"
        self._limits.record_specialist_call()
        if name not in self._used_specialists:
            self._used_specialists.append(name)
        try:
            result = specialist.run(self._evidence_snapshot(), self._specialist_profile())
        except Exception as e:
            return f"Specialist {name} failed: {e}"
        self._update_specialist_recommendations()
        return result.to_report()

    def _check_limits_before_tool(self, name: str, arguments: Dict[str, Any]) -> Optional[str]:
        """Return an error message when a tool is blocked by resource limits."""
        allowed, reason = self._limits.check_tool(name, arguments)
        if not allowed:
            return reason
        return None

    def _record_limit_blocked(self, name: str, arguments: Dict[str, Any], reason: str) -> None:
        """Record a blocked tool as evidence so the model sees the reason."""
        result = type(
            "R",
            (),
            {
                "success": False,
                "output": "",
                "error": reason,
                "truncated": False,
                "timed_out": False,
            },
        )()
        self._evidence.record(name, arguments, result)

    @property
    def limits(self) -> Any:
        """Access the resource limits tracker."""
        return self._limits

    @property
    def autonomous_enabled(self) -> bool:
        """Return True when Stage 6 autonomous mode is enabled."""
        return bool(getattr(self.config, "enable_autonomous_mode", True))

    @property
    def memory_enabled(self) -> bool:
        """Return True when session memory is enabled."""
        return bool(getattr(self.config, "enable_session_memory", True))

    def start_investigation(self, user_message: str) -> None:
        """Begin an autonomous investigation for a new user request.

        Detects the challenge type from the request and generates an
        investigation plan before any tool executes.
        """
        if not self.autonomous_enabled:
            return
        self._last_user_message = user_message

        # Stage 7: start fresh limits and register specialists once
        self._limits.start_challenge()
        if not self._specialist_router.all():
            self._register_specialists()

        observations = self._observations_from_history()
        ctype, confidence, reasons = self._workflow.detect_challenge_type(
            user_request=user_message,
            observations=observations,
        )
        self._challenge_type = ctype
        self._challenge_confidence = confidence
        self._challenge_reasons = reasons

        available = self._available_tool_names()
        self._plan = self._planner.new_plan(ctype, available)

        self._update_specialist_recommendations()

        if self.memory_enabled and ctype:
            self._memory.add_note(
                f"Challenge type: {ctype} (confidence {confidence:.0%})"
            )

    def _observations_from_history(self) -> List[str]:
        """Collect recent tool outputs from history for detection signals."""
        messages = self.get_history() or []
        observations = []
        for m in messages[-8:]:
            if m.get("role") == "tool":
                content = str(m.get("content", ""))
                if content:
                    observations.append(content[:600])
        return observations

    def _create_provider(self):
        """Instantiate the correct provider based on configuration."""
        api_key = self.config.get_api_key()
        model = self.config.get_model()
        timeout = self.config.model_timeout

        if self.config.provider == "openrouter":
            return OpenRouterProvider(api_key, model, timeout)
        elif self.config.provider == "opencode":
            return OpenCodeProvider(api_key, model, timeout)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    def set_tool_registry(self, registry: Any) -> None:
        """Attach a tool registry for tool-calling support."""
        self._tool_registry = registry

    # ------------------------------------------------------------------
    # Skill system integration
    # ------------------------------------------------------------------

    def init_skills(self) -> None:
        """Initialize the skill registry and router from configuration.

        No-op when skills are disabled via config.enable_skills.
        """
        if not getattr(self.config, "enable_skills", True):
            self._skill_registry = None
            self._skill_router = None
            return

        from tools.skill_registry import SkillRegistry
        from tools.skill_router import SkillRouter

        self._skill_registry = SkillRegistry(
            getattr(self.config, "skills_directory", "skills")
        )
        self._skill_registry.load_all()
        self._skill_router = SkillRouter(
            skill_dir=getattr(self.config, "skills_directory", "skills"),
            max_active_skills=getattr(self.config, "max_active_skills", 5),
            min_score=getattr(self.config, "skill_min_score", 0.3),
            auto_selection=getattr(self.config, "skill_auto_selection", True),
        )

    def get_skill_registry(self):
        """Return the skill registry (or None when disabled)."""
        if self._skill_registry is None:
            self.init_skills()
        return self._skill_registry

    def get_skill_router(self):
        """Return the skill router (or None when disabled)."""
        if self._skill_router is None:
            self.init_skills()
        return self._skill_router

    def skill_summary(self) -> str:
        """Return a human-readable summary of the loaded skill library."""
        registry = self.get_skill_registry()
        if registry is None:
            return "Skills are disabled."
        return registry.startup_summary()

    def skill_command(self, raw_command: str) -> str:
        """Handle skill-related slash commands.

        Supported forms:
          /skills            - list loaded skills by category
          /skill <id>        - manually activate a skill
          /skill auto        - enable auto selection
          /skill off         - disable skill usage
          /skill clear       - clear manual selections
        """
        registry = self.get_skill_registry()
        router = self.get_skill_router()
        if registry is None or router is None:
            return "Skills are disabled (set ENABLE_SKILLS=true in configuration)."

        parts = raw_command.strip().split(None, 1)
        if not parts:
            return "Usage: /skills | /skill <id> | /skill auto | /skill off | /skill clear"
        command = parts[0].lower()
        rest = parts[1].strip() if len(parts) > 1 else ""

        if command == "/skills":
            return self._format_skill_list(registry)

        if command == "/skill":
            if not rest:
                return "Usage: /skill <identifier> | /skill auto | /skill off | /skill clear"
            arg = rest.lower()
            if arg == "auto":
                router.set_mode(True)
                return "Skill auto-selection enabled. Skills will be chosen from context."
            if arg == "off":
                router.set_mode(False)
                router.clear_manual()
                return "Skill usage disabled. No skills will be injected."
            if arg == "clear":
                router.clear_manual()
                return "Manual skill selections cleared."
            ok, msg = router.activate_skill(rest, registry)
            return msg

        return "Unknown skill command. Try /skills or /skill <identifier>."

    def _format_skill_list(self, registry) -> str:
        """Format the skill library listing."""
        lines = ["Skill library:", "-" * 50]
        for category in ("common", "web", "binary"):
            metas = registry.list_skills_by_category(category)
            if not metas:
                continue
            lines.append(f"{category.capitalize()} ({len(metas)}):")
            for m in sorted(metas, key=lambda x: x.identifier):
                active = ""
                router = self._skill_router
                if router and m.identifier in router.active_identifiers:
                    active = " [active]"
                lines.append(f"  {m.identifier:45s} - {m.description[:70]}{active}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _skill_context(self) -> str:
        """Build the skill context for the current conversation.

        Uses the router to select skills from the latest user message.
        Returns an empty string when skills are disabled or nothing matches.
        """
        registry = self.get_skill_registry()
        router = self.get_skill_router()
        if registry is None or router is None:
            return ""

        if not getattr(self.config, "skill_auto_selection", True) and not router.active_identifiers:
            return ""

        # Gather context from the conversation and tool registry
        messages = self.get_history() or []
        user_text = " ".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )
        tool_text = " ".join(
            str(m.get("content", ""))[:500]
            for m in messages
            if m.get("role") == "tool"
        )

        filenames: List[str] = []
        extensions: List[str] = []

        # Build context signal from tool results
        observations: List[str] = []
        for m in messages:
            if m.get("role") == "tool":
                content = str(m.get("content", ""))
                if content:
                    observations.append(content[:500])

        max_chars = getattr(self.config, "max_skill_context_chars", 4000)
        available_tools = self._available_tool_names()

        selection = router.select_skills(
            registry,
            challenge_category=self._detect_category(),
            user_request=user_text,
            filenames=filenames,
            file_extensions=extensions,
            http_observations=observations,
            tool_results=observations,
            challenge_description=user_text,
            available_tools=available_tools,
        )

        return router.build_context(selection.selected, max_chars=max_chars)

    def _detect_category(self) -> str:
        """Best-effort challenge category detection from recent messages."""
        messages = self.get_history() or []
        text = " ".join(
            str(m.get("content", "")) for m in messages[-6:]
        ).lower()
        binary_hits = ["binary", "exploit", "pwn", "reverse", "elf", "gdb", "disassembly"]
        web_hits = ["web", "http", "url", "website", "login", "injection", "xss"]
        if any(h in text for h in web_hits) and not any(h in text for h in binary_hits):
            return "web"
        if any(h in text for h in binary_hits):
            return "binary"
        return ""

    def _messages_with_system_prompt(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Prepend the agent system prompt (with skill + Stage 6 context) to the message list."""
        from agent.prompts import (
            get_system_prompt,
            SKILL_CONTEXT_PLACEHOLDER,
            ACTIVE_SKILLS_PLACEHOLDER,
            CHALLENGE_PROFILE_PLACEHOLDER,
            INVESTIGATION_PLAN_PLACEHOLDER,
            SESSION_MEMORY_PLACEHOLDER,
            EVIDENCE_LOG_PLACEHOLDER,
            SPECIALIST_CONTEXT_PLACEHOLDER,
        )
        prompt = get_system_prompt()
        skill_context = self._skill_context()
        active_summary = self._active_skills_summary()
        prompt = prompt.replace(ACTIVE_SKILLS_PLACEHOLDER, active_summary)
        prompt = prompt.replace(SKILL_CONTEXT_PLACEHOLDER, skill_context)
        prompt = prompt.replace(SPECIALIST_CONTEXT_PLACEHOLDER, self._specialist_context_prompt())

        if self.autonomous_enabled:
            prompt = prompt.replace(
                CHALLENGE_PROFILE_PLACEHOLDER, self._challenge_profile_prompt()
            )
            prompt = prompt.replace(
                INVESTIGATION_PLAN_PLACEHOLDER, self._planner.to_prompt()
            )
            prompt = prompt.replace(
                SESSION_MEMORY_PLACEHOLDER, self._memory_prompt()
            )
            prompt = prompt.replace(
                EVIDENCE_LOG_PLACEHOLDER, self._evidence_prompt()
            )
        else:
            prompt = prompt.replace(CHALLENGE_PROFILE_PLACEHOLDER, "")
            prompt = prompt.replace(INVESTIGATION_PLAN_PLACEHOLDER, "")
            prompt = prompt.replace(SESSION_MEMORY_PLACEHOLDER, "")
            prompt = prompt.replace(EVIDENCE_LOG_PLACEHOLDER, "")

        return [{"role": "system", "content": prompt}] + list(messages)

    # ------------------------------------------------------------------
    # Stage 6: prompt section builders
    # ------------------------------------------------------------------

    def _challenge_profile_prompt(self) -> str:
        """Render the detected challenge profile as a prompt section."""
        if not self._challenge_type:
            return "## Challenge Profile\n(no challenge type detected yet)"
        reasons = ", ".join(self._challenge_reasons) if self._challenge_reasons else "(no signals)"
        return (
            f"## Challenge Profile\n"
            f"Type: {self._challenge_type} (confidence {self._challenge_confidence:.0%})\n"
            f"Signals: {reasons}"
        )

    def _memory_prompt(self) -> str:
        """Render the session memory as a prompt section."""
        if not self.memory_enabled:
            return "## Session Memory\n(disabled)"
        return self._memory.to_prompt(max_chars=2000)

    def _evidence_prompt(self) -> str:
        """Render the evidence log as a prompt section."""
        return self._evidence.to_prompt(max_chars=2500)

    def _progress_summary(self) -> Dict[str, Any]:
        """Evaluate investigation progress after the latest tool executions."""
        progress = self._workflow.evaluate_progress(self._planner, self._evidence)
        self._last_progress = progress
        return progress

    def _active_skills_summary(self) -> str:
        """Return a short summary of which skills are active and why."""
        registry = self.get_skill_registry()
        router = self.get_skill_router()
        if registry is None or router is None:
            return ""
        if not getattr(self.config, "skill_auto_selection", True) and not router.active_identifiers:
            return ""
        lines = ["## Active Skills"]
        selection = router.select_skills(
            registry,
            challenge_category=self._detect_category(),
            user_request=" ".join(
                str(m.get("content", "")) for m in (self.get_history() or [])
                if m.get("role") == "user"
            ),
            available_tools=self._available_tool_names(),
        )
        if not selection.selected:
            return ""
        for sel in selection.selected:
            lines.append(f"- {sel.skill.metadata.identifier} (score {sel.score:.2f}: {sel.reason})")
        return "\n".join(lines)

    def _available_tool_names(self) -> List[str]:
        if self._tool_registry is None:
            return []
        try:
            return [t["name"] for t in self._tool_registry.list_tools()]
        except Exception:
            return []

    def send_message(self, user_message: str) -> str:
        """Send a user message and return the assistant's response.

        If a tool registry is attached, the agent will use tool calling.
        Otherwise, falls back to plain chat.
        """
        if self._tool_registry is not None:
            return self._send_message_with_tools(user_message)
        return self._send_plain_message(user_message)

    def _send_plain_message(self, user_message: str) -> str:
        """Send a message without tool calling (Stage 1 behaviour)."""
        from agent.conversation import ConversationHistory

        if not hasattr(self, "_history") or self._history is None:
            self._history = ConversationHistory()

        self._history.add_user_message(user_message)
        messages = self._messages_with_system_prompt(self._history.get_messages())

        try:
            response = self.provider.chat(messages)
        except InvalidAPIKeyError:
            raise
        except UnsupportedModelError:
            raise
        except ProviderUnavailableError:
            raise
        except RateLimitError:
            raise
        except PaymentRequiredError:
            raise
        except TimeoutError:
            raise
        except EmptyResponseError:
            raise

        self._history.add_assistant_message(response)
        return response

    def _send_message_with_tools(self, user_message: str) -> str:
        """Send a message with tool-calling support.

        Runs an agent loop: the model may request tool calls, which are
        executed and their results fed back until the model produces a
        final text response or the step limit is reached.

        Stage 6 additions:
        - an investigation plan is generated before execution;
        - transient tool failures are retried automatically;
        - every tool result is recorded to the evidence log and memory;
        - progress is evaluated after each tool execution;
        - the final response is a structured report (findings/evidence/
          flag status/next step).
        """
        from agent.conversation import ConversationHistory

        if self._history is None:
            self._history = ConversationHistory()

        self._history.add_user_message(user_message)
        self.start_investigation(user_message)

        max_steps = getattr(self.config, "max_agent_steps", 10)
        tool_defs = self._ordered_tool_definitions()

        for step in range(max_steps):
            messages = self._messages_with_system_prompt(self._history.get_messages())

            try:
                text, tool_calls = self.provider.chat_with_tools(
                    messages, tools=tool_defs
                )
            except (InvalidAPIKeyError, UnsupportedModelError,
                    ProviderUnavailableError, RateLimitError,
                    PaymentRequiredError, TimeoutError, EmptyResponseError):
                raise
            except Exception as e:
                return f"Provider error during tool call: {e}"

            # If the model returned text (even alongside tool calls),
            # add it to the conversation so it has context.
            if text.strip():
                self._history.add_assistant_message(text)

            # If no tool calls, we are done — return the text response.
            if not tool_calls:
                return self._finalize_response(text.strip() if text.strip() else "(No response)")

            # Process each tool call
            for tc in tool_calls:
                name = tc.get("name", "")
                arguments = tc.get("arguments", {})
                tool_id = tc.get("id", "")

                # Normalize arguments: ensure they are dicts
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except (json.JSONDecodeError, TypeError):
                        arguments = {}

                if not isinstance(arguments, dict):
                    arguments = {}

                # Log tool usage to console
                arg_summary = ", ".join(
                    f"{k}={v!r}" for k, v in list(arguments.items())[:3]
                )
                if len(arguments) > 3:
                    arg_summary += ", ..."
                print(f"[TOOL] {name}: {arg_summary}")

                # Stage 7: enforce resource limits before executing.
                limit_error = self._check_limits_before_tool(name, arguments)
                if limit_error:
                    self._record_limit_blocked(name, arguments, limit_error)
                    print(f"[LIMIT] {name}: {limit_error}")
                    tool_result_message = {
                        "role": "tool",
                        "content": json.dumps({
                            "success": False,
                            "tool": name,
                            "output": "",
                            "error": limit_error,
                            "truncated": False,
                            "timed_out": False,
                        }),
                        "tool_call_id": tool_id,
                    }
                    self._history.add_assistant_message(
                        text if text.strip() else f"[Tool call blocked: {name}]"
                    )
                    self._history._messages.append(tool_result_message)
                    continue

                # Execute the tool (Stage 6: with retry for transient failures)
                result = self._execute_tool_with_retry(name, arguments)
                self._limits.record_action(name, arguments)

                # Stage 6: record evidence + memory and update the plan
                self._record_tool_result(name, arguments, result)
                # Stage 7: re-rank specialist recommendations from new evidence
                self._update_specialist_recommendations()

                # Format tool result for the provider
                tool_result_message = {
                    "role": "tool",
                    "content": json.dumps({
                        "success": result.success,
                        "tool": result.tool,
                        "output": result.output,
                        "error": result.error,
                        "truncated": result.truncated,
                        "timed_out": result.timed_out,
                    }),
                    "tool_call_id": tool_id,
                }
                self._history.add_assistant_message(
                    text if text.strip() else f"[Tool call: {name}]"
                )
                self._history._messages.append(tool_result_message)

            # After processing all tool calls, loop back to let the model
            # reason about the results.
            # Check if we've hit the step limit
            if step + 1 >= max_steps:
                return self._finalize_response(
                    "(Maximum tool steps reached. Please review findings above.)"
                )

        # Fallback
        return self._finalize_response("Agent step limit reached.")

    # ------------------------------------------------------------------
    # Stage 6: tool execution helpers
    # ------------------------------------------------------------------

    def _ordered_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions with recommended tools listed first.

        Automatic tool selection: tools recommended for the current
        challenge type and evidence are placed at the top of the tool list
        so the model sees them first.  All tools remain available.
        """
        definitions = self._tool_registry.get_definitions()
        if not self.autonomous_enabled or not self._challenge_type:
            return definitions
        recommended = self._workflow.recommended_tools(
            self._challenge_type,
            used_tools=self._planner.used_tools(),
            available_tools=[d["function"]["name"] for d in definitions],
        )
        if not recommended:
            return definitions
        rec_set = set(recommended)
        front = [d for d in definitions if d["function"]["name"] in rec_set]
        back = [d for d in definitions if d["function"]["name"] not in rec_set]
        return front + back

    def _execute_tool_with_retry(self, name: str, arguments: Dict[str, Any]):
        """Execute a tool, retrying transient failures (timeouts/network)."""
        from tools.retry import execute_with_retry
        return execute_with_retry(
            self._tool_registry,
            name,
            arguments,
            workspace_root=self.config.ctf_workspace,
            max_retries=getattr(self.config, "max_tool_retries", 2),
            delay=getattr(self.config, "tool_retry_delay", 0.5),
            logger=print,
        )

    def _record_tool_result(self, name: str, arguments: Dict[str, Any], result) -> None:
        """Record a tool result into the evidence log, memory, and plan."""
        self._evidence.record(name, arguments, result)
        if self.memory_enabled:
            self._memory.remember_tool_result(name, arguments, result.output)
        self._planner.mark_tool_used(name)
        self._progress_summary()

    # ------------------------------------------------------------------
    # Stage 6: structured reporting
    # ------------------------------------------------------------------

    def _finalize_response(self, text: str) -> str:
        """Append the structured investigation report to the model response."""
        if not self.autonomous_enabled or not self._evidence.has_items():
            return text
        report = self._build_structured_report()
        specialist = self._specialist_section()
        if specialist:
            report = f"{report}\n\n---\n{specialist}"
        return f"{text}\n\n---\n{report}"

    def _specialist_section(self) -> str:
        """Render the recommended-next-specialist section (Stage 7).

        If a flag is already confirmed, the section says so instead of
        recommending more work.
        """
        if not self.specialists_enabled:
            return ""
        flag_status, flag_value = self._evidence.flag_status()
        if flag_status == "Confirmed":
            return (
                "## Specialist Guidance\n"
                f"Flag confirmed (`{flag_value}`) - stop investigating and report it."
            )
        if not self._specialist_recommendations:
            return ""
        lines = ["## Specialist Guidance"]
        for rank in self._specialist_recommendations[:2]:
            lines.append(
                f"- Recommended specialist: {rank.specialist.name} "
                f"(score {rank.score:.2f})"
            )
            steps = " ".join(rank.specialist.run(
                self._evidence_snapshot(), self._specialist_profile()
            ).recommended_steps[:2]) if rank.specialist else ""
            if steps:
                lines.append(f"  First low-risk step: {steps[:200]}")
        lines.append(
            "- Use /specialists <name> to run one, or /limits to check resource usage."
        )
        return "\n".join(lines)

    def _build_structured_report(self) -> str:
        """Build the structured final report from evidence, plan, and memory."""
        from agent.evidence import format_structured_report

        findings = self._evidence.confirmed_findings(limit=10)
        evidence_lines = self._evidence.report_lines(limit=8)
        flag_status, flag_value = self._evidence.flag_status()
        next_step = self._planner.next_recommended_step()
        if next_step:
            next_text = f"{next_step.order + 1}. {next_step.title}: {next_step.description}"
        else:
            next_text = "No further planned steps — review findings or ask for manual verification."
        return format_structured_report(
            findings,
            evidence_lines,
            flag_status,
            flag_value,
            next_text,
        )

    def stage6_command(self, raw_command: str) -> str:
        """Handle Stage 6 slash commands.

        /plan      - show the current investigation plan
        /memory    - show session memory
        /evidence  - show the evidence log
        /status    - show challenge type, progress, and flag status
        """
        command = raw_command.strip().lower()
        if command == "/plan":
            return self._planner.to_prompt()
        if command == "/memory":
            return self._memory_prompt() if self.memory_enabled else "Session memory is disabled."
        if command == "/evidence":
            return self._evidence_prompt()
        if command == "/status":
            return self._status_prompt()
        return (
            "Unknown Stage 6 command. Usage: /plan | /memory | /evidence | /status"
        )

    def _status_prompt(self) -> str:
        """Render a session status summary."""
        progress = self._last_progress or self._progress_summary()
        flag_status, flag_value = self._evidence.flag_status()
        lines = [
            "## Session Status",
            f"Challenge type: {self._challenge_type or '(not detected)'} "
            f"(confidence {self._challenge_confidence:.0%})",
            self._planner.summary(),
            self._evidence.summary(),
            self._memory.summary(),
            f"Flag status: {flag_status}" + (f" (`{flag_value}`)" if flag_value else ""),
            f"More investigation required: {progress.get('more_investigation_required', False)}",
            f"Reason: {progress.get('reason', '')}",
        ]
        return "\n".join(lines)

    def reset_conversation(self) -> None:
        """Clear the conversation history and Stage 6 session state."""
        if self._history is not None:
            self._history.clear()
        if self.autonomous_enabled:
            self._memory.clear()
            self._evidence.clear()
            self._planner.clear()
            self._plan = []
            self._challenge_type = ""
            self._challenge_confidence = 0.0
            self._challenge_reasons = []
            self._last_progress = {}
        # Stage 7: reset limits and specialist state
        self._limits.reset()
        self._used_specialists = []
        self._specialist_recommendations = []

    def set_provider(self, provider_name: str) -> None:
        """Switch the active provider and recreate it."""
        self.config.provider = provider_name
        self.provider = self._create_provider()

    def set_model(self, model_name: str) -> None:
        """Switch the active model."""
        self.config.active_model = model_name
        if self.config.provider == "openrouter":
            self.config.openrouter_model = model_name
        elif self.config.provider == "opencode":
            self.config.opencode_model = model_name
        self.provider.model = model_name

    def get_history(self):
        """Return the conversation history."""
        if self._history is not None:
            return self._history.get_messages()
        return []
