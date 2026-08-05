"""Tests for the tool registry."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.registry import ToolRegistry, ToolResult


class TestToolRegistry(unittest.TestCase):
    """Test the tool registry."""

    def setUp(self):
        self.registry = ToolRegistry()

    def test_register_tool(self):
        """Tools can be registered."""
        self.registry.register(
            name="test_tool",
            func=lambda: "ok",
            description="A test tool",
            parameters={},
        )
        self.assertIsNotNone(self.registry.get_tool("test_tool"))

    def test_get_unknown_tool(self):
        """Unknown tool returns None."""
        self.assertIsNone(self.registry.get_tool("nonexistent"))

    def test_list_tools(self):
        """list_tools returns all registered tools."""
        self.registry.register("tool_a", lambda: "a", "Desc A", {})
        self.registry.register("tool_b", lambda: "b", "Desc B", {})
        tools = self.registry.list_tools()
        names = [t["name"] for t in tools]
        self.assertIn("tool_a", names)
        self.assertIn("tool_b", names)

    def test_get_definitions(self):
        """get_definitions returns OpenAI-compatible format."""
        self.registry.register(
            "my_tool",
            lambda: "ok",
            "A test tool",
            {"type": "object", "properties": {}},
        )
        defs = self.registry.get_definitions()
        self.assertEqual(len(defs), 1)
        self.assertEqual(defs[0]["type"], "function")
        self.assertEqual(defs[0]["function"]["name"], "my_tool")

    def test_execute_unknown_tool(self):
        """Executing an unknown tool returns an error result."""
        result = self.registry.execute("nonexistent", {})
        self.assertFalse(result.success)
        self.assertIn("unknown tool", result.error.lower())

    def test_execute_tool_success(self):
        """Executing a valid tool returns success."""
        self.registry.register(
            "greet",
            lambda name="world": f"Hello, {name}!",
            "Greet someone",
            {},
        )
        result = self.registry.execute("greet", {"name": "Alice"})
        self.assertTrue(result.success)
        self.assertIn("Alice", result.output)

    def test_execute_tool_with_error(self):
        """Executing a tool that raises returns an error result."""
        def failing_func():
            raise ValueError("Something went wrong")

        self.registry.register(
            "fail",
            failing_func,
            "A tool that fails",
            {},
        )
        result = self.registry.execute("fail", {})
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_execute_missing_required_arg(self):
        """Missing required argument returns an error."""
        self.registry.register(
            "needs_arg",
            lambda value="": f"Value: {value}",
            "Needs an arg",
            {},
            required=["value"],
        )
        result = self.registry.execute("needs_arg", {})
        self.assertFalse(result.success)
        self.assertIn("missing required", result.error.lower())

    def test_tool_availability(self):
        """Tools can be marked unavailable."""
        self.registry.register(
            "unavail",
            lambda: "ok",
            "Unavailable tool",
            {},
        )
        # Mark as unavailable
        tool = self.registry.get_tool("unavail")
        tool["available"] = False

        defs = self.registry.get_definitions()
        names = [d["function"]["name"] for d in defs]
        self.assertNotIn("unavail", names)


class TestToolResult(unittest.TestCase):
    """Test ToolResult dataclass."""

    def test_success_result(self):
        result = ToolResult(success=True, tool="test", output="ok")
        self.assertTrue(result.success)
        self.assertEqual(result.output, "ok")

    def test_error_result(self):
        result = ToolResult(
            success=False, tool="test", output="", error="something failed"
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error, "something failed")

    def test_truncated_result(self):
        result = ToolResult(
            success=True,
            tool="test",
            output="x" * 5000,
            truncated=True,
        )
        self.assertTrue(result.truncated)
