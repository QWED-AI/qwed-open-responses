"""
Tool Guard - Validates tool calls for safety and correctness.

Blocks dangerous tools and validates tool arguments.
"""

from typing import Any, Dict, Optional, List, Set, Callable
from .base import BaseGuard, GuardResult
import re


class ToolGuard(BaseGuard):
    """
    Validates tool calls before execution.

    Features:
    - Block dangerous tools
    - Validate tool arguments
    - Rate limit tool calls
    - Custom validation functions

    Usage:
        guard = ToolGuard(
            blocked_tools=["execute_shell", "delete_file"],
            allowed_tools=["search", "calculator"],  # If set, only these allowed
            dangerous_patterns=[r"DROP TABLE", r"rm -rf"],
        )

        result = guard.check({
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"query": "weather"}
        })
    """

    name = "ToolGuard"
    description = "Validates tool calls for safety"

    # Default dangerous tools
    DEFAULT_BLOCKED_TOOLS = {
        "execute_shell",
        "shell",
        "bash",
        "cmd",
        "exec",
        "eval",
        "delete_file",
        "remove_file",
        "write_file",
        "modify_file",
        "send_email",
        "transfer_money",
        "make_payment",
    }

    # Default dangerous patterns in arguments
    DEFAULT_DANGEROUS_PATTERNS = [
        r"(?i)DROP\s+TABLE",
        r"(?i)DELETE\s+FROM",
        r"(?i)TRUNCATE\s+TABLE",
        r"rm\s+-rf",
        r"rmdir\s+/s",
        r"del\s+/f",
        r"format\s+c:",
        r"sudo\s+",
        r"chmod\s+777",
        r"eval\s*\(",
        r"exec\s*\(",
        r"__import__",
        r"subprocess",
        r"os\.system",
    ]

    def __init__(
        self,
        blocked_tools: Optional[List[str]] = None,
        allowed_tools: Optional[List[str]] = None,
        use_default_blocklist: bool = True,
        dangerous_patterns: Optional[List[str]] = None,
        use_default_patterns: bool = True,
        custom_validators: Optional[Dict[str, Callable]] = None,
        max_calls_per_response: int = 10,
    ):
        """
        Initialize ToolGuard.

        Args:
            blocked_tools: Tools to always block
            allowed_tools: If set, only these tools allowed (whitelist mode)
            use_default_blocklist: Include default dangerous tools
            dangerous_patterns: Regex patterns to block in arguments
            use_default_patterns: Include default dangerous patterns
            custom_validators: Dict of tool_name -> validator function
            max_calls_per_response: Max tool calls in single response
        """
        self.blocked_tools: Set[str] = set(blocked_tools or [])
        if use_default_blocklist:
            self.blocked_tools.update(self.DEFAULT_BLOCKED_TOOLS)

        self.allowed_tools: Optional[Set[str]] = (
            set(allowed_tools) if allowed_tools else None
        )

        self.dangerous_patterns: List[re.Pattern] = []
        if use_default_patterns:
            self.dangerous_patterns.extend(
                re.compile(p) for p in self.DEFAULT_DANGEROUS_PATTERNS
            )
        if dangerous_patterns:
            self.dangerous_patterns.extend(re.compile(p) for p in dangerous_patterns)

        self.custom_validators = custom_validators or {}
        self.max_calls = max_calls_per_response

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Validate tool call(s) in response."""

        # Extract tool calls
        tool_calls = self._extract_tool_calls(response)

        if not tool_calls:
            return self.pass_result(message="No tool calls to verify")

        # Check call limit
        if len(tool_calls) > self.max_calls:
            return self.fail_result(
                f"Too many tool calls: {len(tool_calls)} (max: {self.max_calls})"
            )

        # Check each tool call
        for call in tool_calls:
            tool_name = call.get("tool_name") or call.get("name")

            # Unrecognized envelope (#28): fail closed, never pass silently.
            if tool_name is None and call.get("type") == "__unrecognized__":
                return self.fail_result(
                    "BLOCKED: Response contains tool-like content in an unrecognized format. "
                    f"Supported shapes: type=tool_call, tool_calls[], choices[].message.tool_calls[], "
                    f"content[].type=tool_use.",
                    details={"response_keys": list(response.keys())},
                )

            arguments = call.get("arguments", {})

            # Check blocked list
            if tool_name in self.blocked_tools:
                return self.fail_result(
                    f"BLOCKED: Tool '{tool_name}' is not allowed",
                    details={"blocked_tool": tool_name},
                )

            # Check allowed list (whitelist mode)
            if self.allowed_tools and tool_name not in self.allowed_tools:
                return self.fail_result(
                    f"BLOCKED: Tool '{tool_name}' is not in allowed list",
                    details={
                        "tool": tool_name,
                        "allowed": list(self.allowed_tools),
                    },
                )

            # Check for dangerous patterns in arguments
            args_str = str(arguments)
            for pattern in self.dangerous_patterns:
                if pattern.search(args_str):
                    return self.fail_result(
                        f"BLOCKED: Dangerous pattern detected in tool arguments",
                        details={
                            "tool": tool_name,
                            "pattern": pattern.pattern,
                        },
                    )

            # Run custom validator if exists
            if tool_name in self.custom_validators:
                try:
                    validator = self.custom_validators[tool_name]
                    is_valid, error_msg = validator(arguments)
                    if not is_valid:
                        return self.fail_result(
                            f"Tool '{tool_name}' validation failed: {error_msg}",
                            details={"tool": tool_name},
                        )
                except Exception as e:
                    return self.fail_result(
                        f"Tool validator error: {str(e)}",
                        details={"tool": tool_name},
                    )

        return self.pass_result(
            message=f"All {len(tool_calls)} tool call(s) verified",
            details={"tools_checked": [c.get("tool_name") for c in tool_calls]},
        )

    def _extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict]:
        """Extract tool calls from various response formats.

        Also detects tool-ish content in unrecognized envelope shapes (#28):
        if the response contains keys that suggest a tool call but none of the
        known extraction patterns matched, a sentinel entry is returned so
        the guard fails closed instead of passing with "No tool calls".
        """
        calls = []

        # Direct tool call (case-insensitive type match)
        resp_type = str(response.get("type", "")).lower()
        if resp_type == "tool_call":
            calls.append(response)

        # List of tool calls
        if "tool_calls" in response:
            calls.extend(response["tool_calls"])

        # OpenAI format
        if "choices" in response:
            for choice in response.get("choices", []):
                msg = choice.get("message", {})
                if msg.get("tool_calls"):
                    calls.extend(msg["tool_calls"])

        # Anthropic format: content blocks with type == "tool_use"
        for block in (response.get("content") or []):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append({
                    "type": "tool_call",
                    "tool_name": block.get("name", ""),
                    "arguments": block.get("input", {}),
                })

        # Shape-blindness sentinel (#28): if no known pattern matched but the
        # response carries tool-suggesting keys, return an unrecognized marker
        # so check() fails closed rather than reporting "No tool calls to verify".
        if not calls:
            _TOOL_HINT_KEYS = {"tool_use", "function_call", "tool_name", "function"}
            top_level = set(response.keys())
            nested_types = {
                str(b.get("type", "")).lower()
                for b in (response.get("content") or [])
                if isinstance(b, dict)
            }
            if (
                top_level & _TOOL_HINT_KEYS
                or nested_types & {"tool_use", "function_call"}
                or (resp_type not in ("text", "", "message", "structured_output")
                    and "tool" in resp_type)
            ):
                calls.append({"type": "__unrecognized__", "tool_name": None, "arguments": {}})

        return calls
