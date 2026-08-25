"""
Tool Guard - Validates tool calls for safety and correctness.

Blocks dangerous tools and validates tool arguments.
"""

from typing import Any, Dict, Optional, List, Set, Callable, Tuple
from .base import BaseGuard, GuardResult
import json
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
                    "Supported shapes: type=tool_call, tool_calls[], choices[].message.tool_calls[], "
                    "content[].type=tool_use.",
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

        Every extracted call is normalized (#33 review): OpenAI function-call
        wrappers are flattened and JSON-encoded argument strings are parsed,
        so blocklist and dangerous-argument checks always operate on
        ``tool_name``/``arguments`` regardless of envelope. Unparseable calls
        become fail-closed sentinels.
        """
        resp_type = str(response.get("type", "")).lower()

        calls: List[Dict] = []
        calls.extend(self._extract_known_shapes(response))

        # Responses API direct function_call items (#33 review)
        if resp_type == "function_call":
            calls.append(response)

        calls = self._normalize_calls(calls)

        if not calls:
            if self._looks_like_unrecognized_tool_content(response, resp_type):
                calls.append(
                    {"type": "__unrecognized__", "tool_name": None, "arguments": {}}
                )
        return calls

    @staticmethod
    def _parse_tool_arguments(raw: Any) -> Tuple[bool, Any]:
        """Parse tool-call arguments. Returns (ok, value)."""
        if isinstance(raw, dict):
            return True, raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                return False, None
            if isinstance(parsed, dict):
                return True, parsed
        return False, None

    @classmethod
    def _normalize_calls(cls, calls: List[Dict]) -> List[Dict]:
        """Flatten function-wrapped calls and decode string arguments.

        - choices[].message.tool_calls[] items carry a nested ``function``
          object ({name, arguments-as-JSON-string}) — flattened so the
          blocked-tool and dangerous-argument policies can see them.
        - Responses API items carry top-level name + JSON-string arguments.
        - Anything unparseable becomes a fail-closed sentinel.
        """
        normalized: List[Dict] = []
        for call in calls:
            if call.get("type") == "__unrecognized__":
                normalized.append(call)
                continue

            fn = call.get("function")
            if isinstance(fn, dict) and fn.get("name") is not None:
                ok, args = cls._parse_tool_arguments(fn.get("arguments", {}))
                if not ok:
                    normalized.append(
                        {
                            "type": "__unrecognized__",
                            "tool_name": None,
                            "arguments": {},
                            "reason": "unparseable_arguments",
                            "attempted_name": fn["name"],
                        }
                    )
                    continue
                normalized.append(
                    {
                        "type": "tool_call",
                        "tool_name": fn["name"],
                        "arguments": args,
                    }
                )
                continue

            if str(call.get("type", "")).lower() == "function_call" and call.get(
                "name"
            ):
                ok, args = cls._parse_tool_arguments(call.get("arguments", {}))
                if not ok:
                    normalized.append(
                        {
                            "type": "__unrecognized__",
                            "tool_name": None,
                            "arguments": {},
                            "reason": "unparseable_arguments",
                            "attempted_name": call["name"],
                        }
                    )
                    continue
                normalized.append(
                    {
                        "type": "tool_call",
                        "tool_name": call["name"],
                        "arguments": args,
                    }
                )
                continue

            args = call.get("arguments", {})
            if isinstance(args, str):
                ok, parsed_args = cls._parse_tool_arguments(args)
                if not ok:
                    normalized.append(
                        {
                            "type": "__unrecognized__",
                            "tool_name": None,
                            "arguments": {},
                            "reason": "unparseable_arguments",
                            "attempted_name": call.get("tool_name") or call.get("name"),
                        }
                    )
                    continue
                normalized.append({**call, "arguments": parsed_args})
                continue

            normalized.append(call)
        return normalized

    @staticmethod
    def _extract_known_shapes(response: Dict[str, Any]) -> List[Dict]:
        """Extract from the supported envelope shapes."""
        calls: List[Dict] = []

        # Direct tool call (case-insensitive type match)
        if str(response.get("type", "")).lower() == "tool_call":
            calls.append(response)

        # List of tool calls
        if "tool_calls" in response:
            calls.extend(response["tool_calls"])

        # OpenAI format
        for choice in response.get("choices", []):
            msg = choice.get("message", {})
            if msg.get("tool_calls"):
                calls.extend(msg["tool_calls"])

        # Anthropic format: content blocks with type == "tool_use"
        for block in response.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append(
                    {
                        "type": "tool_call",
                        "tool_name": block.get("name", ""),
                        "arguments": block.get("input", {}),
                    }
                )

        return calls

    @staticmethod
    def _looks_like_unrecognized_tool_content(
        response: Dict[str, Any], resp_type: str
    ) -> bool:
        """Detect tool-ish content that matched no known envelope shape (#28).

        Shape-based, not name-based: a hint key only counts when its VALUE is
        tool-shaped (an object carrying name/arguments), so ordinary fields
        like ``function: "parse_csv"`` on a structured response still pass.
        """
        # Tool-shaped objects under recognizable hint keys.
        for key in ("tool_use", "function_call", "function"):
            value = response.get(key)
            if isinstance(value, dict) and ("name" in value or "arguments" in value):
                return True

        # tool_name + arguments together is a tool call in all but name.
        if response.get("tool_name") is not None and "arguments" in response:
            return True

        nested_types = {
            str(block.get("type", "")).lower()
            for block in (response.get("content") or [])
            if isinstance(block, dict)
        }
        if nested_types & {"tool_use", "function_call"}:
            return True

        benign_types = {"text", "", "message", "structured_output"}
        return resp_type not in benign_types and "tool" in resp_type
