"""
Math Guard - Verifies mathematical calculations in AI responses.

Uses deterministic verification (when possible) to catch calculation errors.
"""

from typing import Any, Dict, Optional, List
from .base import BaseGuard, GuardResult
import re


class MathGuard(BaseGuard):
    """
    Verifies mathematical calculations in AI responses.

    Features:
    - Verify arithmetic expressions
    - Check percentage calculations
    - Validate financial calculations
    - Detect calculation inconsistencies

    Usage:
        guard = MathGuard(tolerance=0.01)

        result = guard.check({
            "output": {
                "subtotal": 100,
                "tax": 8,  # 8%
                "total": 108
            }
        })
    """

    name = "MathGuard"
    description = "Verifies mathematical calculations"

    def __init__(
        self,
        tolerance: float = 0.01,
        verify_totals: bool = True,
        verify_percentages: bool = True,
        custom_rules: Optional[List[Dict]] = None,
    ):
        """
        Initialize MathGuard.

        Args:
            tolerance: Allowed floating point difference
            verify_totals: Check that totals add up
            verify_percentages: Verify percentage calculations
            custom_rules: List of custom verification rules
        """
        self.tolerance = tolerance
        self.verify_totals = verify_totals
        self.verify_percentages = verify_percentages
        self.custom_rules = custom_rules or []

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Verify math in response."""

        data = response.get("output", response)
        errors: List[str] = []

        # Check for common math patterns
        if isinstance(data, dict):
            # Check totals
            if self.verify_totals:
                total_errors = self._verify_totals(data)
                errors.extend(total_errors)

            # Check percentages
            if self.verify_percentages:
                pct_errors = self._verify_percentages(data)
                errors.extend(pct_errors)

        # Check text content for inline calculations
        if isinstance(data, str):
            calc_errors = self._verify_inline_calculations(data)
            errors.extend(calc_errors)

        # Run custom rules
        for rule in self.custom_rules:
            rule_errors = self._run_custom_rule(rule, data)
            errors.extend(rule_errors)

        if errors:
            return self.fail_result(
                message=f"Math verification failed: {len(errors)} error(s)",
                details={"errors": errors},
            )

        return self.pass_result(message="Math verification passed")

    def _verify_totals(self, data: Dict) -> List[str]:
        """Verify that totals add up correctly."""
        errors = []

        # Common total patterns
        patterns = [
            # (total_field, component_fields, operation)
            ("total", ["subtotal", "tax", "shipping"], "add"),
            ("total", ["subtotal", "-discount", "tax"], "add"),
            ("net", ["gross", "-deductions"], "add"),
            ("balance", ["credits", "-debits"], "add"),
        ]

        for total_field, components, op in patterns:
            if total_field in data:
                expected_total = data[total_field]
                calculated = 0.0

                all_components_present = True
                for comp in components:
                    if comp.startswith("-"):
                        field = comp[1:]
                        if field in data:
                            calculated -= float(data[field])
                        else:
                            all_components_present = False
                    else:
                        if comp in data:
                            calculated += float(data[comp])
                        else:
                            all_components_present = False

                if all_components_present:
                    if abs(calculated - expected_total) > self.tolerance:
                        errors.append(
                            f"{total_field} mismatch: expected {expected_total}, "
                            f"calculated {calculated}"
                        )

        return errors

    def _verify_percentages(self, data: Dict) -> List[str]:
        """Verify percentage calculations."""
        errors = []

        # Look for percentage patterns
        for key, value in data.items():
            # Find fields that might be percentages
            if key.endswith("_percent") or key.endswith("_rate"):
                base_key = key.replace("_percent", "").replace("_rate", "")
                amount_key = base_key + "_amount"

                if base_key in data and amount_key in data:
                    base = float(data[base_key])
                    rate = float(value) / 100.0
                    expected_amount = base * rate
                    actual = float(data[amount_key])

                    if abs(expected_amount - actual) > self.tolerance:
                        errors.append(
                            f"Percentage calculation error: {rate*100}% of {base} "
                            f"should be {expected_amount}, got {actual}"
                        )

        return errors

    def _verify_inline_calculations(self, text: str) -> List[str]:
        """Verify calculations written in text."""
        errors = []

        # Pattern: "X + Y = Z" or "X * Y = Z"
        calc_pattern = (
            r"(\d+(?:\.\d+)?)\s*([\+\-\*\/])\s*(\d+(?:\.\d+)?)\s*=\s*(\d+(?:\.\d+)?)"
        )

        for match in re.finditer(calc_pattern, text):
            a, op, b, result = match.groups()
            a, b, result = float(a), float(b), float(result)

            if op == "+":
                expected = a + b
            elif op == "-":
                expected = a - b
            elif op == "*":
                expected = a * b
            elif op == "/":
                expected = a / b if b != 0 else float("inf")
            else:
                continue

            if abs(expected - result) > self.tolerance:
                errors.append(
                    f"Calculation error: {a} {op} {b} = {result} "
                    f"(should be {expected})"
                )

        return errors

    def _run_custom_rule(self, rule: Dict, data: Any) -> List[str]:
        """Run a custom verification rule."""
        errors = []

        rule_type = rule.get("type")

        if rule_type == "equals":
            field = rule.get("field")
            expected = rule.get("expected")
            if field in data and abs(float(data[field]) - expected) > self.tolerance:
                errors.append(f"{field} should equal {expected}")

        elif rule_type == "range":
            field = rule.get("field")
            min_val = rule.get("min", float("-inf"))
            max_val = rule.get("max", float("inf"))
            if field in data:
                val = float(data[field])
                if val < min_val or val > max_val:
                    errors.append(f"{field}={val} outside range [{min_val}, {max_val}]")

        return errors
