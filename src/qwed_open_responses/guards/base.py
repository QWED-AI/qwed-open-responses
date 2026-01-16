"""
Base Guard - Abstract base class for all guards.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from dataclasses import dataclass


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


class BaseGuard(ABC):
    """
    Abstract base class for all verification guards.

    To create a custom guard, subclass this and implement the check() method.

    Example:
        class MyCustomGuard(BaseGuard):
            name = "MyCustomGuard"

            def check(self, response, context):
                if some_condition(response):
                    return self.pass_result()
                else:
                    return self.fail_result("Condition not met")
    """

    name: str = "BaseGuard"
    description: str = "Base guard class"

    @abstractmethod
    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """
        Check the response against this guard's rules.

        Args:
            response: The parsed AI response
            context: Additional context (conversation history, etc.)

        Returns:
            GuardResult indicating if check passed or failed
        """
        pass

    def pass_result(
        self,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Create a passing result."""
        return GuardResult(
            guard_name=self.name,
            passed=True,
            message=message or f"{self.name} passed",
            details=details,
            severity="info",
        )

    def fail_result(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "error",
    ) -> GuardResult:
        """Create a failing result."""
        return GuardResult(
            guard_name=self.name,
            passed=False,
            message=message,
            details=details,
            severity=severity,
        )

    def warn_result(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Create a warning result (passes but with warning)."""
        return GuardResult(
            guard_name=self.name,
            passed=False,
            message=message,
            details=details,
            severity="warning",
        )
