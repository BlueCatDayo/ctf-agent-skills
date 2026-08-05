"""Tool registry — stores metadata, validates arguments, and dispatches execution."""

import inspect
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .workspace import WorkspaceError


@dataclass
class ToolMetadata:
    """Metadata for a single tool."""

    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    required: List[str] = field(default_factory=list)
    timeout_seconds: int = 30
    available: bool = True
    category: str = "general"


@dataclass
class ToolResult:
    """Consistent result format returned by every tool."""

    success: bool
    tool: str
    output: str
    error: Optional[str] = None
    truncated: bool = False
    exit_code: Optional[int] = None
    timed_out: bool = False


class ToolRegistry:
    """Registry that maps tool names to callables with metadata."""

    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}

    def register(
        self,
        name: str,
        func: Callable,
        description: str,
        parameters: Dict[str, Any],
        required: Optional[List[str]] = None,
        timeout_seconds: int = 30,
        category: str = "general",
    ) -> None:
        """Register a tool with the registry."""
        self._tools[name] = {
            "name": name,
            "func": func,
            "description": description,
            "parameters": parameters,
            "required": required or [],
            "timeout_seconds": timeout_seconds,
            "available": True,
            "category": category,
        }

    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve a tool's metadata by name."""
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return metadata for all registered tools."""
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
                "required": t["required"],
                "available": t["available"],
                "category": t["category"],
            }
            for t in self._tools.values()
        ]

    def get_definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions in OpenAI-compatible function-calling format."""
        definitions = []
        for tool in self._tools.values():
            if not tool["available"]:
                continue
            definitions.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool["description"],
                        "parameters": tool["parameters"],
                    },
                }
            )
        return definitions

    def execute(
        self,
        name: str,
        arguments: Dict[str, Any],
        workspace_root: Any = None,
    ) -> ToolResult:
        """Execute a tool by name with validated arguments.

        Parameters
        ----------
        name:
            The registered tool name.
        arguments:
            Keyword arguments to pass to the tool function.
        workspace_root:
            Optional workspace root passed to tools that need it.

        Returns
        -------
        ToolResult
            Structured result with success flag, output, and error details.
        """
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(
                success=False,
                tool=name,
                output="",
                error=f"Unknown tool: '{name}'. Use /tools to list available tools.",
            )

        # Validate required arguments
        for req in tool["required"]:
            if req not in arguments or arguments[req] is None:
                return ToolResult(
                    success=False,
                    tool=name,
                    output="",
                    error=f"Missing required argument: '{req}' for tool '{name}'.",
                )

        # Execute with timeout
        timeout = tool.get("timeout_seconds", 30)
        func = tool["func"]

        try:
            # Pass workspace_root if the function accepts it
            sig = inspect.signature(func)
            if "workspace_root" in sig.parameters:
                result = func(**arguments, workspace_root=workspace_root)
            else:
                result = func(**arguments)

            # Format result
            if isinstance(result, ToolResult):
                return result
            if isinstance(result, str):
                return ToolResult(
                    success=True,
                    tool=name,
                    output=result,
                )
            # Fallback: convert to string
            return ToolResult(
                success=True,
                tool=name,
                output=str(result),
            )

        except WorkspaceError as e:
            return ToolResult(
                success=False,
                tool=name,
                output="",
                error=f"Workspace security error: {e}",
            )
        except TimeoutError:
            return ToolResult(
                success=False,
                tool=name,
                output="",
                error=f"Tool '{name}' timed out after {timeout}s.",
                timed_out=True,
            )
        except TypeError as e:
            # Catch missing/wrong positional arguments from the tool function
            msg = str(e)
            if "missing" in msg or "required positional argument" in msg:
                return ToolResult(
                    success=False,
                    tool=name,
                    output="",
                    error=(
                        f"Missing required argument for tool '{name}'. "
                        f"Required: {', '.join(tool['required']) or '(none declared)'}."
                    ),
                )
            return ToolResult(
                success=False,
                tool=name,
                output="",
                error=f"Tool '{name}' execution error: {e}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool=name,
                output="",
                error=f"Tool '{name}' execution error: {e}",
            )
