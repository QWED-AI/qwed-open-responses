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
        verifiable = False

        # Check for common math patterns — only shapes the guard can
        # actually verify count as verifiable math (issue #32: a vacuous
        # pass on arbitrary shapes hid unverifiable responses)
        if isinstance(data, dict):
            if self.verify_totals and self._totals_applicable(data):
                verifiable = True
                # the TOTAL_PATTERNS are alternative formulas: the response
                # verifies if ANY applicable pattern checks out (a receipt
                # with shipping legitimately mismatches the discount-less
                # formula)
                total_errors, totals_ok = self._verify_totals(data)
                if not totals_ok:
                    errors.extend(total_errors)

            if self.verify_percentages and self._percentages_applicable(data):
                verifiable = True
                pct_errors, pct_ok = self._verify_percentages(data)
                if not pct_ok:
                    errors.extend(pct_errors)

            if self.custom_rules:
                verifiable = True

        # Check text content for inline calculations
        elif isinstance(data, str):
            if self._CALC_PATTERN.search(data):
                verifiable = True
                errors.extend(self._verify_inline_calculations(data))

        # Run custom rules
        if self.custom_rules:
            for rule in self.custom_rules:
                rule_errors = self._run_custom_rule(rule, data)
                errors.extend(rule_errors)

        if errors:
            return self.fail_result(
                message=f"Math verification failed: {len(errors)} error(s)",
                details={"errors": errors},
            )

        if not verifiable:
            # issue #32: a response with no verifiable math shape must not
            # pass vacuously — visible warning-severity failure (blocking
            # in strict mode)
            return self.fail_result(
                message="No verifiable math found in response",
                severity="warning",
            )

        return self.pass_result(message="Math verification passed")

    # Common total patterns (issue #32: hoisted so applicability detection
    # and verification share one source of truth)
    TOTAL_PATTERNS = [
        # (total_field, component_fields, operation)
        ("total", ["subtotal", "tax", "shipping"], "add"),
        ("total", ["subtotal", "-discount", "tax"], "add"),
        ("net", ["gross", "-deductions"], "add"),
        ("balance", ["credits", "-debits"], "add"),
    ]

    _CALC_PATTERN = re.compile(
        r"(\d+(?:\.\d+)?)\s*([\+\-\*\/])\s*(\d+(?:\.\d+)?)\s*=\s*(\d+(?:\.\d+)?)"
    )

    def _totals_applicable(self, data: Dict) -> bool:
        """True when a totals pattern's total field is present — missing
        components are treated as zero, mirroring the npm guard."""
        return any(total_field in data for total_field, _c, _op in self.TOTAL_PATTERNS)

    def _percentages_applicable(self, data: Dict) -> bool:
        """True when a percentage shape is fully present (rate key + base +
        amount), mirroring what _verify_percentages can actually check."""
        for key in data:
            if key.endswith("_percent") or key.endswith("_rate"):
                base_key = key.replace("_percent", "").replace("_rate", "")
                if base_key in data and base_key + "_amount" in data:
                    return True
        return False

    def _verify_totals(self, data: Dict) -> tuple:
        """Verify totals against their components (missing components count
        as zero, mirroring the npm guard). Returns (errors, verified_any):
        verified_any is True when ANY applicable formula checks out — the
        patterns are alternative formulas, not conjunctive checks."""
        errors = []
        verified_any = False

        for total_field, components, op in self.TOTAL_PATTERNS:
            if total_field not in data:
                continue
            expected_total = float(data[total_field])
            calculated = 0.0
            for comp in components:
                field = comp[1:] if comp.startswith("-") else comp
                value = float(data[field]) if field in data else 0.0
                calculated += -value if comp.startswith("-") else value

            if abs(calculated - expected_total) <= self.tolerance:
                verified_any = True
            else:
                errors.append(
                    f"{total_field} mismatch: expected {expected_total}, "
                    f"calculated {calculated}"
                )

        return errors, verified_any

    def _verify_percentages(self, data: Dict) -> tuple:
        """Verify percentage calculations. Returns (errors, verified_any)."""
        errors = []
        found_any = False

        # Look for percentage patterns
        for key, value in data.items():
            # Find fields that might be percentages
            if key.endswith("_percent") or key.endswith("_rate"):
                base_key = key.replace("_percent", "").replace("_rate", "")
                amount_key = base_key + "_amount"

                if base_key in data and amount_key in data:
                    found_any = True
                    base = float(data[base_key])
                    rate = float(value) / 100.0
                    expected_amount = base * rate
                    actual = float(data[amount_key])

                    if abs(expected_amount - actual) > self.tolerance:
                        errors.append(
                            f"Percentage calculation error: {rate*100}% of {base} "
                            f"should be {expected_amount}, got {actual}"
                        )

        return errors, found_any

    def _verify_inline_calculations(self, text: str) -> List[str]:
        """Verify calculations written in text."""
        errors = []

        for match in re.finditer(self._CALC_PATTERN, text):
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
