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

    def _check_content(self, data: Any, errors: List[str]) -> bool:
        """Verify built-in dict math or inline calculations."""
        if isinstance(data, dict):
            try:
                return self._verify_dict_math(data, errors)
            except (ValueError, TypeError) as exc:
                # Sentry on PR #36: append to errors so prior errors are not lost
                errors.append(f"Math fields contain non-numeric values: {exc}")
                return False
        if isinstance(data, str) and self._CALC_PATTERN.search(data):
            errors.extend(self._verify_inline_calculations(data))
            return True
        return False

    def _check_custom_rules(self, data: Any, errors: List[str]) -> bool:
        """Run configured custom verification rules on dict data."""
        if not isinstance(data, dict) or not self.custom_rules:
            return False
        rule_applied = False
        for rule in self.custom_rules:
            field = rule.get("field")
            if field and field in data:
                rule_errors = self._run_custom_rule(rule, data)
                errors.extend(rule_errors)
                if not rule_errors:
                    rule_applied = True
        return rule_applied

    def _build_error_result(self, errors: List[str]) -> GuardResult:
        """Format failing result preserving non-numeric context."""
        has_non_numeric = any(
            "non-numeric" in e or "not a finite number" in e for e in errors
        )
        msg = (
            f"Math fields contain non-numeric values: {len(errors)} error(s)"
            if has_non_numeric
            else f"Math verification failed: {len(errors)} error(s)"
        )
        return self.fail_result(
            message=msg,
            details={"errors": errors},
            severity="error",
        )

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Verify math in response."""
        data = response.get("output", response)
        errors: List[str] = []

        content_verifiable = self._check_content(data, errors)
        rules_applied = self._check_custom_rules(data, errors)
        verifiable = content_verifiable or rules_applied

        if errors:
            return self._build_error_result(errors)

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

    @staticmethod
    def _to_finite_float(val: Any) -> Optional[float]:
        """Convert val to finite float or return None if non-numeric/non-finite."""
        if val is None or isinstance(val, (dict, list)):
            return None
        try:
            num = float(val)
            return num if math.isfinite(num) else None
        except (ValueError, TypeError):
            return None

    def _pattern_calculated(self, data: Dict, components: List[str]) -> Optional[float]:
        """Sum a totals pattern's components — missing components count as
        zero; non-numeric or non-finite values return None."""
        calculated = 0.0
        for comp in components:
            field = comp[1:] if comp.startswith("-") else comp
            if field in data:
                val = self._to_finite_float(data[field])
                if val is None:
                    return None
                calculated += -val if comp.startswith("-") else val
        return calculated

    def _verify_totals(self, data: Dict) -> tuple:
        """Verify totals against their components (missing components count
        as zero, mirroring the npm guard). Returns (errors, verified_any)."""
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
            expected_total = self._to_finite_float(data[total_field])
            if expected_total is None:
                errors.append(f"{total_field} is not a finite number")
                continue

            calculated = self._pattern_calculated(data, components)
            if calculated is None:
                errors.append(f"{total_field} components contain non-numeric values")
                continue

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
        base = self._to_finite_float(data[base_key])
        rate_num = self._to_finite_float(rate_val)
        actual = self._to_finite_float(data[base_key + "_amount"])

        if base is None or rate_num is None or actual is None:
            return f"Percentage fields for {base_key} contain non-finite values"

        rate = rate_num / 100.0
        expected_amount = base * rate
        if not math.isfinite(expected_amount):
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

    def _run_custom_equals_rule(self, rule: Dict, val: float, field: str) -> List[str]:
        """Run equals custom rule validating finite expected value."""
        if "expected" not in rule or rule.get("expected") is None:
            return [f"Custom equals rule for '{field}' missing 'expected' value"]
        expected_raw = rule.get("expected")
        expected = self._to_finite_float(expected_raw)
        if expected is None:
            return [f"Invalid expected value for {field}: {expected_raw}"]
        if abs(val - expected) > self.tolerance:
            return [f"{field} should equal {expected_raw}"]
        return []

    def _run_custom_range_rule(self, rule: Dict, val: float, field: str) -> List[str]:
        """Run range custom rule validating finite min/max bounds."""
        min_raw = rule.get("min")
        max_raw = rule.get("max")
        if min_raw is None and max_raw is None:
            return [f"Custom range rule for '{field}' must specify 'min' or 'max'"]

        min_val = float("-inf") if min_raw is None else self._to_finite_float(min_raw)
        max_val = float("inf") if max_raw is None else self._to_finite_float(max_raw)

        if min_val is None:
            return [f"Invalid min bound for {field}: {min_raw}"]
        if max_val is None:
            return [f"Invalid max bound for {field}: {max_raw}"]

        if val < min_val or val > max_val:
            return [f"{field}={val} outside range [{min_raw}, {max_raw}]"]
        return []

    def _run_custom_rule(self, rule: Dict, data: Any) -> List[str]:
        """Run a custom verification rule safely without uncaught exceptions."""
        if not isinstance(data, dict):
            return []

        field = rule.get("field")
        if not field or field not in data:
            return []

        val = self._to_finite_float(data[field])
        if val is None:
            return [f"{field} is not a valid number"]

        rule_type = rule.get("type")
        if rule_type == "equals":
            return self._run_custom_equals_rule(rule, val, field)
        if rule_type == "range":
            return self._run_custom_range_rule(rule, val, field)

        return [f"Unsupported custom rule type: {rule_type}"]
