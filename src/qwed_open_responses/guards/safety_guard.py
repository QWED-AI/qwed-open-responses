"""
Safety Guard - Comprehensive safety checks for AI responses.

Combines multiple safety checks into a single guard.
"""

from typing import Any, Dict, Optional, List, Set
from .base import BaseGuard, GuardResult
import re


class SafetyGuard(BaseGuard):
    """
    Comprehensive safety guard for AI responses.

    Features:
    - PII detection (emails, phones, SSN, credit cards)
    - Prompt injection detection
    - Harmful content patterns
    - Budget/limit enforcement

    Usage:
        guard = SafetyGuard(
            check_pii=True,
            check_injection=True,
            max_cost=100.0,
        )
    """

    name = "SafetyGuard"
    description = "Comprehensive safety checks"

    # PII patterns
    PII_PATTERNS = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    }

    # Prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+(instructions?|prompts?)",
        r"disregard\s+(previous|all|above)",
        r"forget\s+(everything|all|your\s+instructions)",
        r"you\s+are\s+now\s+",
        r"act\s+as\s+if\s+you\s+are",
        r"pretend\s+(you|to\s+be)",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*",
        r"<\|.*?\|>",  # Special tokens
        r"\[\[.*?\]\]",  # Bracket commands
    ]

    # Harmful content patterns
    HARMFUL_PATTERNS = [
        r"password\s*[=:]\s*\S+",
        r"api[_-]?key\s*[=:]\s*\S+",
        r"secret\s*[=:]\s*\S+",
        r"private[_-]?key",
        r"BEGIN\s+(RSA|DSA|EC)\s+PRIVATE\s+KEY",
    ]

    def __init__(
        self,
        check_pii: bool = True,
        check_injection: bool = True,
        check_harmful: bool = True,
        check_budget: bool = True,
        pii_allow_list: Optional[Set[str]] = None,
        max_cost: Optional[float] = None,
        max_tokens: Optional[int] = None,
        custom_patterns: Optional[List[str]] = None,
    ):
        """
        Initialize SafetyGuard.

        Args:
            check_pii: Check for personally identifiable information
            check_injection: Check for prompt injection attempts
            check_harmful: Check for harmful content patterns
            check_budget: Enforce cost/token limits
            pii_allow_list: PII types to allow (e.g., {"email"})
            max_cost: Maximum cost in dollars
            max_tokens: Maximum token count
            custom_patterns: Additional patterns to check
        """
        self.check_pii = check_pii
        self.check_injection = check_injection
        self.check_harmful = check_harmful
        self.check_budget = check_budget
        self.pii_allow_list = pii_allow_list or set()
        self.max_cost = max_cost
        self.max_tokens = max_tokens
        self.custom_patterns = [re.compile(p, re.I) for p in (custom_patterns or [])]

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Run all safety checks."""

        content = self._extract_content(response)
        context = context or {}

        issues: List[Dict] = []

        # PII check
        if self.check_pii:
            pii_found = self._check_pii(content)
            if pii_found:
                issues.append(
                    {
                        "type": "pii",
                        "severity": "warning",
                        "details": pii_found,
                    }
                )

        # Injection check
        if self.check_injection:
            injections = self._check_injection(content)
            if injections:
                issues.append(
                    {
                        "type": "injection",
                        "severity": "error",
                        "details": injections,
                    }
                )

        # Harmful content check
        if self.check_harmful:
            harmful = self._check_harmful(content)
            if harmful:
                issues.append(
                    {
                        "type": "harmful",
                        "severity": "error",
                        "details": harmful,
                    }
                )

        # Budget check
        if self.check_budget:
            budget_issues = self._check_budget(response, context)
            if budget_issues:
                issues.append(
                    {
                        "type": "budget",
                        "severity": "error",
                        "details": budget_issues,
                    }
                )

        # Custom patterns
        for pattern in self.custom_patterns:
            if pattern.search(content):
                issues.append(
                    {
                        "type": "custom_pattern",
                        "severity": "error",
                        "pattern": pattern.pattern,
                    }
                )

        # Determine result
        errors = [i for i in issues if i.get("severity") == "error"]
        warnings = [i for i in issues if i.get("severity") == "warning"]

        if errors:
            return self.fail_result(
                message=f"Safety check failed: {len(errors)} critical issue(s)",
                details={"issues": issues},
            )
        elif warnings:
            return self.warn_result(
                message=f"Safety warnings: {len(warnings)} warning(s)",
                details={"issues": issues},
            )

        return self.pass_result(message="All safety checks passed")

    def _extract_content(self, response: Dict) -> str:
        """Extract text content from response."""
        parts = []

        if isinstance(response.get("content"), str):
            parts.append(response["content"])
        if isinstance(response.get("output"), str):
            parts.append(response["output"])
        if isinstance(response.get("text"), str):
            parts.append(response["text"])

        # Handle nested structures
        if isinstance(response.get("output"), dict):
            parts.append(str(response["output"]))
        if isinstance(response.get("arguments"), dict):
            parts.append(str(response["arguments"]))

        return " ".join(parts)

    def _check_pii(self, content: str) -> List[str]:
        """Check for PII in content."""
        found = []

        for pii_type, pattern in self.PII_PATTERNS.items():
            if pii_type in self.pii_allow_list:
                continue
            if re.search(pattern, content, re.I):
                found.append(pii_type)

        return found

    def _check_injection(self, content: str) -> List[str]:
        """Check for prompt injection patterns."""
        found = []

        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, content, re.I):
                found.append(pattern)

        return found

    def _check_harmful(self, content: str) -> List[str]:
        """Check for harmful content patterns."""
        found = []

        for pattern in self.HARMFUL_PATTERNS:
            if re.search(pattern, content, re.I):
                found.append(pattern)

        return found

    def _check_budget(
        self,
        response: Dict,
        context: Dict,
    ) -> List[str]:
        """Check budget/limit constraints."""
        issues = []

        # Check cost
        if self.max_cost:
            current_cost = context.get("total_cost", 0)
            response_cost = response.get("usage", {}).get("cost", 0)
            if current_cost + response_cost > self.max_cost:
                issues.append(
                    f"Cost exceeds limit: ${current_cost + response_cost} > ${self.max_cost}"
                )

        # Check tokens
        if self.max_tokens:
            current_tokens = context.get("total_tokens", 0)
            response_tokens = response.get("usage", {}).get("total_tokens", 0)
            if current_tokens + response_tokens > self.max_tokens:
                issues.append(
                    f"Tokens exceed limit: {current_tokens + response_tokens} > {self.max_tokens}"
                )

        return issues
