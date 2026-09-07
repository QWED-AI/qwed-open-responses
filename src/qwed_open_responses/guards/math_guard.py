"""
Math Guard - Verifies mathematical calculations in AI responses.

Uses deterministic verification (when possible) to catch calculation errors.
"""

from typing import Any, Dict, Optional, List
from .base import BaseGuard, GuardResult
import math
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

        if isinstance(data, dict):
            try:
                verifiable = self._verify_dict_math(data, errors) or verifiable
            except (ValueError, TypeError):
                # float("invalid") on a supplied math field: fail the guard
                # with a GuardResult instead of escaping to the verifier's
                # generic exception handler (CodeRabbit on PR #36)
                return self.fail_result(
                    message="Math fields contain non-numeric values",
                    severity="error",
                )
        elif isinstance(data, str) and self._CALC_PATTERN.search(data):
            # merged condition (Sonar): the bounded-pattern search gates
            # the inline-calculation verifier
            verifiable = True
            errors.extend(self._verify_inline_calculations(data))

        # Custom rules execute when response data is an object (Greptile P1
        # on PR #36: scalar outputs like {"output": 42} must not crash
        # field-lookup with TypeError). A rule APPLIES when its field is
        # present in dict data — an applied rule marks the response verifiable.
        rule_applied = False
        if isinstance(data, dict):
            for rule in self.custom_rules:
                if rule.get("field") in data:
                    rule_applied = True
                    errors.extend(self._run_custom_rule(rule, data))
        verifiable = verifiable or rule_applied

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
        # ONE canonical total formula (Greptile P1 on PR #36: the two
        # overlapping "total" formulas let a receipt with supplied shipping
        # pass via the discount-less variant — total = 108 vs components
        # totaling 118). net/balance are distinct vocabularies, so
        # any-verifies remains sound across them.
        ("total", ["subtotal", "tax", "shipping", "-discount"], "add"),
        ("net", ["gross", "-deductions"], "add"),
        ("balance", ["credits", "-debits"], "add"),
    ]

    # Bounded quantifiers (Sonar on PR #36): the unbounded version had
    # super-linear search behavior on non-matching text. 30 digits and 10
    # whitespace characters cover every realistic input while capping the
    # backtracking work.
    _CALC_PATTERN = re.compile(
        r"(\d{1,30}(?:\.\d{1,30})?)\s{0,10}([\+\-\*\/])\s{0,10}"
        r"(\d{1,30}(?:\.\d{1,30})?)\s{0,10}=\s{0,10}(\d{1,30}(?:\.\d{1,30})?)"
    )
    _PERCENT_SUFFIXES = ("_percent", "_rate")

    def _verify_dict_math(self, data: Dict, errors: List[str]) -> bool:
        """Verify dict-shaped responses. Returns True when any check
        applied (verifiable math present)."""
        verifiable = False

        if self.verify_totals and self._totals_applicable(data):
            # Greptile P1 on PR #36: each distinct vocabulary (total, net, balance)
            # is an independent financial assertion. If a payload has both a valid
            # total and an invalid net, the net mismatch must NOT be suppressed.
            total_errors, totals_ok = self._verify_totals(data)
            errors.extend(total_errors)
            if totals_ok:
                verifiable = True

        if self.verify_percentages and self._percentages_applicable(data):
            verifiable = True
            pct_errors, pct_ok = self._verify_percentages(data)
            if not pct_ok:
                errors.extend(pct_errors)

        return verifiable

    def _totals_applicable(self, data: Dict) -> bool:
        """True when a totals pattern's total field AND at least one
        component are present — a lone total with no components verifies
        nothing (CodeAnt on PR #36: zero-defaulting made {"net": 0} pass
        vacuously)."""
        for total_field, components, _op in self.TOTAL_PATTERNS:
            if total_field not in data:
                continue
            if any(
                (comp[1:] if comp.startswith("-") else comp) in data
                for comp in components
            ):
                return True
        return False

    def _percentages_applicable(self, data: Dict) -> bool:
        """True when a percentage shape is fully present (rate key + base +
        amount), mirroring what _verify_percentages can actually check."""
        for key in data:
            if key.endswith(self._PERCENT_SUFFIXES):
                base_key = key.replace("_percent", "").replace("_rate", "")
                if base_key in data and base_key + "_amount" in data:
                    return True
        return False

    def _pattern_calculated(self, data: Dict, components: List[str]) -> float:
        """Sum a totals pattern's components — missing components count as
        zero, mirroring the npm guard."""
        calculated = 0.0
        for comp in components:
            field = comp[1:] if comp.startswith("-") else comp
            value = float(data[field]) if field in data else 0.0
            calculated += -value if comp.startswith("-") else value
        return calculated

    def _verify_totals(self, data: Dict) -> tuple:
        """Verify totals against their components (missing components count
        as zero, mirroring the npm guard). Returns (errors, verified_any):
        verified_any is True when ANY applicable formula checks out — the
        patterns are alternative formulas, not conjunctive checks."""
        errors = []
        verified_any = False

        for total_field, components, _op in self.TOTAL_PATTERNS:
            if total_field not in data:
                continue
            if not any(
                (comp[1:] if comp.startswith("-") else comp) in data
                for comp in components
            ):
                # a lone total with no components verifies nothing
                continue
            expected_total = float(data[total_field])
            calculated = self._pattern_calculated(data, components)

            if abs(calculated - expected_total) <= self.tolerance:
                verified_any = True
            else:
                errors.append(
                    f"{total_field} mismatch: expected {expected_total}, "
                    f"calculated {calculated}"
                )

        return errors, verified_any

    def _check_single_percentage(
        self, base_key: str, rate_val: Any, data: Dict
    ) -> Optional[str]:
        """Check one percentage calculation. Returns error message or None."""
        base = float(data[base_key])
        rate = float(rate_val) / 100.0
        expected_amount = base * rate
        actual = float(data[base_key + "_amount"])
        # Greptile P1 on PR #36: float("nan")/"inf" convert cleanly and NaN
        # tolerance comparisons are always false — non-finite inputs fail
        # closed as errors
        if not all(math.isfinite(v) for v in (base, rate, expected_amount, actual)):
            return f"Percentage fields for {base_key} contain non-finite values"

        if abs(expected_amount - actual) > self.tolerance:
            return (
                f"Percentage calculation error: {rate*100}% of {base} "
                f"should be {expected_amount}, got {actual}"
            )
        return None

    def _verify_percentages(self, data: Dict) -> tuple:
        """Verify percentage calculations. Returns (errors, verified_any)."""
        errors = []
        found_any = False

        for key, value in data.items():
            if not key.endswith(self._PERCENT_SUFFIXES):
                continue
            base_key = key.replace("_percent", "").replace("_rate", "")
            if base_key in data and (base_key + "_amount") in data:
                found_any = True
                err = self._check_single_percentage(base_key, value, data)
                if err:
                    errors.append(err)

        # found_any is APPLICABILITY, not success (Greptile P1 on PR #36:
        # treating it as ok silently ignored percentage mismatches —
        # {tax_percent: 10, tax: 100, tax_amount: 50} verified)
        return errors, found_any and not errors

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
        """Run a custom verification rule safely without uncaught exceptions."""
        if not isinstance(data, dict):
            return []

        errors = []
        field = rule.get("field")
        if not field or field not in data:
            return []

        try:
            val = float(data[field])
        except (ValueError, TypeError):
            return [f"{field} is not a valid number"]

        rule_type = rule.get("type")
        if rule_type == "equals":
            expected = rule.get("expected")
            if expected is not None:
                try:
                    exp_val = float(expected)
                    if abs(val - exp_val) > self.tolerance:
                        errors.append(f"{field} should equal {expected}")
                except (ValueError, TypeError):
                    errors.append(f"Invalid expected value for {field}: {expected}")

        elif rule_type == "range":
            min_val = rule.get("min", float("-inf"))
            max_val = rule.get("max", float("inf"))
            if val < min_val or val > max_val:
                errors.append(f"{field}={val} outside range [{min_val}, {max_val}]")

        return errors
