"""Stage 6 planner - generates investigation steps before tool execution.

The planner builds an ordered plan of investigation steps for the detected
challenge type.  Each step lists the tools that can address it (filtered to
tools available in the registry).  Steps transition pending -> done as the
agent uses their tools; progress is evaluated after every tool execution.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .workflow import WORKFLOWS


@dataclass
class InvestigationStep:
    """A single planned investigation step."""

    id: str
    order: int
    title: str
    description: str
    tools: List[str] = field(default_factory=list)
    status: str = "pending"  # pending | done

    def is_done(self) -> bool:
        return self.status == "done"


class Planner:
    """Generates and tracks an ordered investigation plan."""

    def __init__(self, max_steps: int = 10):
        self._max_steps = max_steps
        self._steps: List[InvestigationStep] = []
        self._used_tools: List[str] = []

    # ------------------------------------------------------------------
    # Plan generation
    # ------------------------------------------------------------------

    def new_plan(
        self,
        challenge_type: str,
        available_tools: Optional[List[str]] = None,
        user_request: str = "",
        max_steps: Optional[int] = None,
    ) -> List[InvestigationStep]:
        """Generate a fresh investigation plan for a challenge type.

        Steps are derived from the workflow definitions and filtered to
        tools available in the registry.  The plan is capped at
        ``max_steps`` (defaults to the planner's configured cap).
        """
        available = set(available_tools or [])
        cap = max_steps if max_steps is not None else self._max_steps
        steps: List[InvestigationStep] = []
        for wf_step in WORKFLOWS.get(challenge_type, WORKFLOWS["misc"]):
            if len(steps) >= cap:
                break
            tools = [t for t in wf_step["tools"] if t in available]
            step = InvestigationStep(
                id=f"s{len(steps) + 1}",
                order=len(steps),
                title=wf_step["title"],
                description=wf_step.get("description", ""),
                tools=tools,
            )
            # Steps with no usable tools cannot be addressed by tool use;
            # they are informational/report steps and start as complete.
            if not tools:
                step.status = "done"
            steps.append(step)
        self._steps = steps
        self._used_tools = []
        return steps

    def clear(self) -> None:
        """Clear the current plan."""
        self._steps = []
        self._used_tools = []

    # ------------------------------------------------------------------
    # Status tracking
    # ------------------------------------------------------------------

    def mark_tool_used(self, tool_name: str) -> None:
        """Record that a tool was used.

        Every pending step whose tools include *tool_name* is marked done
        (a step is considered addressed when any of its tools ran).
        """
        if tool_name not in self._used_tools:
            self._used_tools.append(tool_name)
        for step in self._steps:
            if step.status == "pending" and tool_name in step.tools:
                step.status = "done"

    def steps(self) -> List[InvestigationStep]:
        """Return a copy of the plan steps."""
        return list(self._steps)

    def pending_steps(self) -> List[InvestigationStep]:
        """Return steps that have not been addressed yet."""
        return [s for s in self._steps if not s.is_done()]

    def done_steps(self) -> List[InvestigationStep]:
        """Return steps that have been addressed."""
        return [s for s in self._steps if s.is_done()]

    def used_tools(self) -> List[str]:
        """Return the tools used so far (in order)."""
        return list(self._used_tools)

    def completed_count(self) -> int:
        """Return the number of completed steps."""
        return sum(1 for s in self._steps if s.is_done())

    def total_count(self) -> int:
        """Return the total number of plan steps."""
        return len(self._steps)

    def is_complete(self) -> bool:
        """Return True when every plan step has been addressed."""
        return bool(self._steps) and all(s.is_done() for s in self._steps)

    def next_recommended_step(self) -> Optional[InvestigationStep]:
        """Return the next pending step (or None when complete/empty)."""
        for step in self._steps:
            if not step.is_done():
                return step
        return None

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def to_prompt(self) -> str:
        """Render the plan as a compact prompt section."""
        lines = ["## Investigation Plan"]
        if not self._steps:
            lines.append("(no active plan - start an investigation first)")
            return "\n".join(lines)
        for step in self._steps:
            marker = "[x]" if step.is_done() else "[ ]"
            tools = ", ".join(step.tools) if step.tools else "(report step)"
            lines.append(f"{marker} {step.order + 1}. {step.title} - tools: {tools}")
        return "\n".join(lines)

    def summary(self) -> str:
        """Return a one-line summary of the plan."""
        total = self.total_count()
        done = self.completed_count()
        if total == 0:
            return "Plan: empty (no investigation started)"
        return f"Plan: {done}/{total} steps complete, {len(self.pending_steps())} remaining"

    def describe_step(self, step: InvestigationStep) -> str:
        """Describe a single step (title + description)."""
        return f"{step.order + 1}. {step.title}: {step.description}"
