"""
Argument Guard - Validates tool/function call arguments.

Ensures arguments are within expected ranges and formats.
"""

from typing import Any, Dict, Optional, List, Callable
from .base import BaseGuard, GuardResult
from .tool_guard import ToolGuard
import re


class ArgumentGuard(BaseGuard):
    """
    Validates tool call arguments.

    Usage:
        guard = ArgumentGuard(
            rules={
                "amount": {"type": "number", "min": 0, "max": 10000},
                "email": {"type": "email"},
                "date": {"type": "date", "format": "%Y-%m-%d"},
            }
        )

        result = guard.check({
            "tool_name": "transfer",
            "arguments": {"amount": 500, "email": "user@example.com"}
        })
    """

    name = "ArgumentGuard"
    description = "Validates tool call arguments"

    # Common patterns
    EMAIL_PATTERN = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    URL_PATTERN = r'^https?://[^\s<>"{}|\\^`\[\]]+$'
    UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

    def __init__(
        self,
        rules: Optional[Dict[str, Dict]] = None,
        strict: bool = True,
        allow_extra_args: bool = True,
    ):
        """
        Initialize ArgumentGuard.

        Args:
            rules: Dict of argument_name -> validation rules
            strict: If True, fail on any validation error
            allow_extra_args: If True, allow arguments not in rules
        """
        self.rules = rules or {}
        self.strict = strict
        self.allow_extra_args = allow_extra_args

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Validate arguments."""

        # Extract arguments
        response_type = response.get("type", "")
        normalized_type = (
            response_type.strip().casefold() if isinstance(response_type, str) else ""
        )
        function = response.get("function")
        has_nested_call = any(
            isinstance(response.get(key), dict)
            for key in ("tool_call", "function_call")
        ) or (
            isinstance(function, dict)
            and any(key in function for key in ("name", "arguments"))
        )
        calls = (
            ToolGuard.normalize_tool_calls(response)
            if normalized_type in {"tool_call", "function_call"} or has_nested_call
            else []
        )
        if normalized_type in {"tool_call", "function_call"} or calls:
            if not calls or any(
                call.get("type") in {"__malformed__", "__unrecognized__"}
                for call in calls
            ):
                return self.fail_result("Invalid or ambiguous tool-call arguments")
            argument_sets = [call.get("arguments", {}) for call in calls]
        else:
            arguments = response.get("arguments", {})
            if not arguments and "output" in response:
                arguments = response["output"]
            argument_sets = [arguments]

        errors: List[str] = []

        for arguments in argument_sets:
            if not isinstance(arguments, dict):
                continue

            # Check each rule against every call in a collection.
            for arg_name, rule in self.rules.items():
                if arg_name in arguments:
                    value = arguments[arg_name]
                    arg_errors = self._validate_value(arg_name, value, rule)
                    errors.extend(arg_errors)
                elif rule.get("required", False):
                    errors.append(f"Missing required argument: {arg_name}")

            # Check for extra arguments
            if not self.allow_extra_args:
                extra = set(arguments.keys()) - set(self.rules.keys())
                if extra:
                    errors.append(f"Unexpected arguments: {', '.join(extra)}")

        if errors:
            return self.fail_result(
                message=f"Argument validation failed: {len(errors)} error(s)",
                details={"errors": errors},
            )

        return self.pass_result(message="All arguments valid")

    def _validate_value(
        self,
        name: str,
        value: Any,
        rule: Dict,
    ) -> List[str]:
        """Validate a single value against a rule."""
        errors = []
        rule_type = rule.get("type", "any")

        # Type check
        if rule_type == "string":
            if not isinstance(value, str):
                errors.append(f"{name}: expected string, got {type(value).__name__}")

        elif rule_type == "number":
            if not isinstance(value, (int, float)):
                errors.append(f"{name}: expected number, got {type(value).__name__}")
            else:
                if "min" in rule and value < rule["min"]:
                    errors.append(f"{name}: {value} < min ({rule['min']})")
                if "max" in rule and value > rule["max"]:
                    errors.append(f"{name}: {value} > max ({rule['max']})")

        elif rule_type == "integer":
            if not isinstance(value, int):
                errors.append(f"{name}: expected integer, got {type(value).__name__}")

        elif rule_type == "boolean":
            if not isinstance(value, bool):
                errors.append(f"{name}: expected boolean, got {type(value).__name__}")

        elif rule_type == "email":
            if not isinstance(value, str) or not re.match(self.EMAIL_PATTERN, value):
                errors.append(f"{name}: invalid email format")

        elif rule_type == "url":
            if not isinstance(value, str) or not re.match(self.URL_PATTERN, value):
                errors.append(f"{name}: invalid URL format")

        elif rule_type == "uuid":
            if not isinstance(value, str) or not re.match(
                self.UUID_PATTERN, value, re.I
            ):
                errors.append(f"{name}: invalid UUID format")

        elif rule_type == "enum":
            allowed = rule.get("values", [])
            if value not in allowed:
                errors.append(f"{name}: '{value}' not in {allowed}")

        elif rule_type == "pattern":
            pattern = rule.get("pattern", ".*")
            if not isinstance(value, str) or not re.match(pattern, value):
                errors.append(f"{name}: does not match pattern")

        # Length check (for strings and lists)
        if isinstance(value, (str, list)):
            if "min_length" in rule and len(value) < rule["min_length"]:
                errors.append(
                    f"{name}: length {len(value)} < min ({rule['min_length']})"
                )
            if "max_length" in rule and len(value) > rule["max_length"]:
                errors.append(
                    f"{name}: length {len(value)} > max ({rule['max_length']})"
                )

        return errors
