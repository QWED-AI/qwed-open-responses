"""
QWED Open Responses - Core Verifier.

The ResponseVerifier is the main entry point for verifying AI responses.
It orchestrates multiple guards to ensure responses are safe and correct.
"""

from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
import json


@dataclass
class GuardResult:
    """Result from a single guard check."""

    guard_name: str
    passed: bool
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    severity: str = "error"  # "error", "warning", "info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guard": self.guard_name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
            "severity": self.severity,
        }


@dataclass
class VerificationResult:
    """
    Result of verifying an AI response.

    Attributes:
        verified: True if all guards passed
        response: The original response (potentially modified)
        guards_passed: Number of guards that passed
        guards_failed: Number of guards that failed
        guard_results: Individual results from each guard
        blocked: True if response was blocked (critical failure)
        timestamp: When verification occurred
    """

    verified: bool
    response: Any
    guards_passed: int = 0
    guards_failed: int = 0
    guard_results: List[GuardResult] = field(default_factory=list)
    blocked: bool = False
    block_reason: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "guards_passed": self.guards_passed,
            "guards_failed": self.guards_failed,
            "guard_results": [g.to_dict() for g in self.guard_results],
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        if self.verified:
            return f"[OK] Verified ({self.guards_passed} guards passed)"
        else:
            return f"[FAIL] Not verified ({self.guards_failed} guards failed)"


class ResponseVerifier:
    """
    Main verifier for AI responses.

    Usage:
        verifier = ResponseVerifier()

        # Verify with default guards
        result = verifier.verify(response)

        # Verify with custom guards
        result = verifier.verify(response, guards=[
            SchemaGuard(schema=my_schema),
            ToolGuard(blocked_tools=["execute_sql"]),
            MathGuard(),
        ])

        if result.verified:
            # Safe to use response
            process(result.response)
        else:
            # Handle failure
            for guard_result in result.guard_results:
                if not guard_result.passed:
                    log_error(guard_result.message)
    """

    def __init__(
        self,
        default_guards: Optional[List["BaseGuard"]] = None,
        strict_mode: bool = True,
        allow_warnings: bool = True,
    ):
        """
        Initialize the verifier.

        Args:
            default_guards: Guards to use when none specified
            strict_mode: If True, any guard failure blocks response
            allow_warnings: If True, warnings don't block (only errors)
        """
        self.default_guards = default_guards or []
        self.strict_mode = strict_mode
        self.allow_warnings = allow_warnings

    def verify(
        self,
        response: Any,
        guards: Optional[List["BaseGuard"]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """
        Verify an AI response against a set of guards.

        Args:
            response: The AI response to verify (dict, str, or Response object)
            guards: Guards to apply (uses default_guards if None)
            context: Additional context for guards (e.g., conversation history)

        Returns:
            VerificationResult with verification status and details
        """
        guards_to_use = guards if guards is not None else self.default_guards
        context = context or {}

        # Parse response if needed
        parsed_response = self._parse_response(response)

        # Run all guards
        guard_results: List[GuardResult] = []
        guards_passed = 0
        guards_failed = 0
        blocked = False
        block_reason = None

        for guard in guards_to_use:
            try:
                result = guard.check(parsed_response, context)
                guard_results.append(result)

                if result.passed:
                    guards_passed += 1
                else:
                    guards_failed += 1

                    # Check if this blocks
                    if result.severity == "error" or (
                        result.severity == "warning" and not self.allow_warnings
                    ):
                        if self.strict_mode:
                            blocked = True
                            block_reason = result.message

            except Exception as e:
                # Guard threw exception - treat as failure
                guard_results.append(
                    GuardResult(
                        guard_name=guard.name,
                        passed=False,
                        message=f"Guard error: {str(e)}",
                        severity="error",
                    )
                )
                guards_failed += 1

        # Determine overall verification status
        verified = guards_failed == 0

        return VerificationResult(
            verified=verified,
            response=parsed_response,
            guards_passed=guards_passed,
            guards_failed=guards_failed,
            guard_results=guard_results,
            blocked=blocked,
            block_reason=block_reason,
        )

    def verify_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        guards: Optional[List["BaseGuard"]] = None,
    ) -> VerificationResult:
        """
        Convenience method to verify a tool call.

        Args:
            tool_name: Name of the tool being called
            arguments: Arguments to the tool
            guards: Guards to apply

        Returns:
            VerificationResult with verification status
        """
        tool_call = {
            "type": "tool_call",
            "tool_name": tool_name,
            "arguments": arguments,
        }
        return self.verify(tool_call, guards)

    def verify_structured_output(
        self,
        output: Dict[str, Any],
        schema: Optional[Dict[str, Any]] = None,
        guards: Optional[List["BaseGuard"]] = None,
    ) -> VerificationResult:
        """
        Convenience method to verify a structured output.

        Args:
            output: The structured output from the AI
            schema: JSON Schema to validate against
            guards: Additional guards to apply

        Returns:
            VerificationResult with verification status
        """
        from .guards import SchemaGuard

        guards_list = list(guards) if guards else []

        if schema:
            guards_list.insert(0, SchemaGuard(schema=schema))

        structured = {
            "type": "structured_output",
            "output": output,
        }
        return self.verify(structured, guards_list)

    def _parse_response(self, response: Any) -> Dict[str, Any]:
        """Parse response into a standard format."""
        if isinstance(response, dict):
            return response
        elif isinstance(response, str):
            # Try to parse as JSON
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                return {"type": "text", "content": response}
        elif hasattr(response, "model_dump"):
            # Pydantic model
            return response.model_dump()
        elif hasattr(response, "dict"):
            # Older pydantic
            return response.dict()
        elif hasattr(response, "__dict__"):
            return response.__dict__
        else:
            return {"type": "unknown", "raw": str(response)}


# Import guards for type hints
from .guards.base import BaseGuard
