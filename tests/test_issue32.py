"""Issue #32 hygiene batch: MathGuard vacuous passes, request/trace IDs,
deprecated utcnow, parse strictness parity."""

import asyncio

import pytest

from qwed_open_responses import MathGuard, ResponseVerifier
from qwed_open_responses.core import GuardResult, VerificationResult, _canonical_json


class TestMathGuardNoVerifiableMath:
    """issue #32 item 1: string outputs and lone totals must not pass
    vacuously — the guard returns a distinct warning-severity failure."""

    def test_string_output_fails_not_passes(self):
        guard = MathGuard()
        result = guard.check({"output": "total should be 999"})
        assert result.passed is False
        assert result.severity == "warning"
        assert "No verifiable math" in result.message

    def test_lone_total_without_components_fails(self):
        # a lone total with NO components verifies nothing (CodeAnt on
        # PR #36: zero-defaulting made {"net": 0} pass vacuously)
        guard = MathGuard()
        result = guard.check({"output": {"total": 999}})
        assert result.passed is False
        assert result.severity == "warning"
        assert "No verifiable math" in result.message

    def test_lone_zero_net_fails(self):
        # the zero-default edge: {"net": 0} with no components must not
        # pass just because 0 == 0
        guard = MathGuard()
        result = guard.check({"output": {"net": 0}})
        assert result.passed is False
        assert "No verifiable math" in result.message

    def test_supplied_shipping_mismatch_fails(self):
        # Greptile P1 on PR #36: subtotal 100 + tax 8 + shipping 10 = 118,
        # but the receipt claims 108 — the discount-less formula must NOT
        # launder the mismatch by defaulting discount to 0
        guard = MathGuard()
        result = guard.check(
            {"output": {"subtotal": 100, "tax": 8, "shipping": 10, "total": 108}}
        )
        assert result.passed is False
        assert "total mismatch" in result.details["errors"][0]

    def test_full_formula_with_discount_passes(self):
        guard = MathGuard()
        result = guard.check(
            {
                "output": {
                    "subtotal": 100,
                    "tax": 8,
                    "shipping": 10,
                    "discount": 10,
                    "total": 108,
                }
            }
        )
        assert result.passed is True

    def test_percentage_mismatch_fails(self):
        # Greptile P1 on PR #36: found-any was conflated with ok —
        # {tax_percent: 10, tax: 100, tax_amount: 50} verified silently
        guard = MathGuard()
        result = guard.check(
            {"output": {"tax_percent": 10, "tax": 100, "tax_amount": 50}}
        )
        assert result.passed is False
        assert any("Percentage" in e for e in result.details["errors"])

    def test_non_numeric_math_field_fails_as_guard_result(self):
        # CodeRabbit on PR #36: float('invalid') escaped check() as an
        # exception; direct callers must receive a failing GuardResult
        guard = MathGuard()
        result = guard.check(
            {"output": {"subtotal": "invalid", "tax": 8, "total": 108}}
        )
        assert result.passed is False
        assert result.severity == "error"
        assert "non-numeric" in result.message

    def test_prose_without_math_fails(self):
        guard = MathGuard()
        result = guard.check({"output": "Thank you for your order!"})
        assert result.passed is False

    def test_complete_totals_still_pass(self):
        guard = MathGuard()
        result = guard.check(
            {"output": {"subtotal": 100, "tax": 8, "shipping": 0, "total": 108}}
        )
        assert result.passed is True

    def test_valid_total_without_shipping_passes(self):
        # missing components count as zero — subtotal + tax + total is
        # verifiable without shipping (mirrors the npm guard)
        guard = MathGuard()
        result = guard.check({"output": {"subtotal": 100, "tax": 8, "total": 108}})
        assert result.passed is True


class TestParseStrictnessParity:
    """issue #32 item 2: TS parseResponse was already aligned to Python's
    _parse_response (raises for non-object payloads) in the #30 parity
    work — pin the Python side's contract."""

    def test_python_rejects_non_object_payloads(self):
        verifier = ResponseVerifier(default_guards=[MathGuard()])
        # arrays, scalars, and None raise — mirroring npm parseResponse
        for payload in ([1, 2, 3], 42, None):
            with pytest.raises(ValueError):
                verifier.verify(payload)

    def test_plain_string_wraps_as_text_on_both_sides(self):
        # a non-JSON string is not rejected: both runtimes wrap it as
        # {type: "text", content: ...} — that IS the aligned behavior
        verifier = ResponseVerifier(default_guards=[MathGuard()])
        result = verifier.verify("just a string")
        assert result.response.get("type") == "text"


class TestRequestIdCorrelation:
    """issue #32 item 3: verdicts carry an operator correlation ID."""

    def test_request_id_populated_from_context(self):
        verifier = ResponseVerifier(default_guards=[MathGuard()])
        result = verifier.verify(
            {"output": {"subtotal": 100, "tax": 8, "shipping": 0, "total": 108}},
            context={"request_id": "req-123"},
        )
        assert result.request_id == "req-123"

    def test_request_id_none_without_context(self):
        verifier = ResponseVerifier(default_guards=[MathGuard()])
        result = verifier.verify(
            {"output": {"subtotal": 100, "tax": 8, "shipping": 0, "total": 108}}
        )
        assert result.request_id is None

    def test_request_id_preserved_on_binding_failure(self):
        # Sentry: cyclic/un-bindable response preserves request_id from context
        verifier = ResponseVerifier(default_guards=[MathGuard()])
        cyclic_payload: dict = {"output": {"subtotal": 100, "tax": 8, "total": 108}}
        cyclic_payload["self"] = cyclic_payload
        result = verifier.verify(cyclic_payload, context={"request_id": "req-cyclic"})
        assert result.verified is False
        assert result.request_id == "req-cyclic"


class TestAwareUtcTimestamp:
    """issue #32 item 4: datetime.utcnow() is deprecated — the timestamp is
    timezone-aware UTC."""

    def test_timestamp_carries_utc_offset(self):
        verifier = ResponseVerifier(default_guards=[MathGuard()])
        result = verifier.verify(
            {"output": {"subtotal": 100, "tax": 8, "shipping": 0, "total": 108}}
        )
        assert result.timestamp.endswith("+00:00")


class TestCustomRulesExecute:
    """PR #36 review (Sentry LOW + Greptile P1 + CodeRabbit, all
    T-Rex/agent-verified): the refactor dropped the custom-rule execution
    loop — configured equals/range rules were silently skipped."""

    def test_equals_rule_violation_fails(self):
        guard = MathGuard(
            custom_rules=[{"type": "equals", "field": "score", "expected": 10}]
        )
        result = guard.check({"output": {"score": 0}})
        assert result.passed is False
        assert any("should equal 10" in e for e in result.details["errors"])

    def test_equals_rule_satisfaction_passes(self):
        guard = MathGuard(
            custom_rules=[{"type": "equals", "field": "score", "expected": 10}]
        )
        result = guard.check({"output": {"score": 10}})
        assert result.passed is True

    def test_range_rule_violation_fails(self):
        guard = MathGuard(
            custom_rules=[{"type": "range", "field": "score", "min": 1, "max": 5}]
        )
        result = guard.check({"output": {"score": 0}})
        assert result.passed is False

    def test_rule_field_absent_is_not_verifiable(self):
        # a configured rule whose field is absent applies to nothing —
        # the response is not verifiable via that rule
        guard = MathGuard(
            custom_rules=[{"type": "equals", "field": "score", "expected": 10}]
        )
        result = guard.check({"output": {"other": 1}})
        assert result.passed is False
        assert "No verifiable math" in result.message


class TestNonFinitePercentageFailClosed:
    """Greptile P1: float('nan') converts cleanly and NaN tolerance
    comparisons are always false — a NaN rate/base/amount passed."""

    @pytest.mark.parametrize(
        "payload",
        [
            {"tax_percent": "nan", "tax": 100, "tax_amount": 0},
            {"tax_percent": 10, "tax": "nan", "tax_amount": 0},
            {"tax_percent": 10, "tax": 100, "tax_amount": "nan"},
            {"tax_percent": "inf", "tax": 100, "tax_amount": 10},
        ],
    )
    def test_nan_percentage_fields_fail(self, payload):
        guard = MathGuard()
        result = guard.check({"output": payload})
        assert result.passed is False
        assert any("non-finite" in e for e in result.details["errors"])


class TestReviewWaveFixes:
    """Tests for SonarQube, Sentry, and Greptile review findings on PR #36."""

    def test_invalid_net_not_suppressed_by_valid_total(self):
        # Greptile P1: valid total must not hide invalid net mismatch
        guard = MathGuard()
        payload = {
            "subtotal": 100,
            "tax": 8,
            "total": 108,
            "gross": 100,
            "deductions": 10,
            "net": 95,  # expected 90
        }
        result = guard.check({"output": payload})
        assert result.passed is False
        assert any("net mismatch" in e for e in result.details["errors"])

    def test_boolean_math_coercion(self):
        # Greptile / Sentry: True coerced to 1.0, False to 0.0
        guard = MathGuard()
        res_pass = guard.check({"output": {"subtotal": 100, "tax": True, "total": 101}})
        assert res_pass.passed is True

        res_fail = guard.check({"output": {"subtotal": 100, "tax": True, "total": 105}})
        assert res_fail.passed is False

    def test_custom_rules_safe_on_scalar_output(self):
        # Greptile P1: scalar outputs must not raise TypeError
        guard = MathGuard(
            custom_rules=[{"type": "equals", "field": "output", "expected": 42}]
        )
        result = guard.check({"output": 42})
        assert result.passed is False
        assert "No verifiable math" in result.message

    def test_custom_rules_safe_on_non_numeric_field(self):
        # Greptile P1: non-numeric rule fields fail gracefully instead of ValueError
        guard = MathGuard(
            custom_rules=[{"type": "equals", "field": "val", "expected": 10}]
        )
        result = guard.check({"output": {"val": "invalid_num"}})
        assert result.passed is False
        assert any("not a valid number" in e for e in result.details["errors"])

    def test_custom_rule_finite_operands(self):
        # Greptile / CodeRabbit: NaN / inf operands in equals / range rules fail closed
        guard_nan_val = MathGuard(
            custom_rules=[{"type": "equals", "field": "val", "expected": 10}]
        )
        res1 = guard_nan_val.check({"output": {"val": float("nan")}})
        assert res1.passed is False
        assert any("not a valid number" in e for e in res1.details["errors"])

        guard_nan_exp = MathGuard(
            custom_rules=[{"type": "equals", "field": "val", "expected": float("nan")}]
        )
        res2 = guard_nan_exp.check({"output": {"val": 10}})
        assert res2.passed is False
        assert any("Invalid expected value" in e for e in res2.details["errors"])

        guard_nan_min = MathGuard(
            custom_rules=[
                {"type": "range", "field": "val", "min": float("nan"), "max": 10}
            ]
        )
        res3 = guard_nan_min.check({"output": {"val": 5}})
        assert res3.passed is False
        assert any("Invalid min bound" in e for e in res3.details["errors"])

    def test_custom_rule_string_range_bounds(self):
        # Greptile / CodeRabbit: string range bounds like "1" and "5" are parsed without TypeError
        guard = MathGuard(
            custom_rules=[{"type": "range", "field": "score", "min": "1", "max": "5"}]
        )
        assert guard.check({"output": {"score": 3}}).passed is True
        assert guard.check({"output": {"score": 0}}).passed is False
        assert guard.check({"output": {"score": 6}}).passed is False

    def test_all_errors_preserved_with_non_numeric_fields(self):
        # Sentry: non-numeric field does not discard preceding mismatch errors
        guard = MathGuard()
        # net has a mismatch (100 - 10 = 90 != 95), and total has a non-numeric subtotal
        payload = {
            "gross": 100,
            "deductions": 10,
            "net": 95,
            "subtotal": "invalid",
            "tax": 8,
            "total": 108,
        }
        res = guard.check({"output": payload})
        assert res.passed is False
        errors = res.details["errors"]
        assert any("net mismatch" in e for e in errors)
        assert any("non-numeric" in e for e in errors)

    def test_falsy_output_presence_does_not_fall_back_to_response(self):
        # CodeRabbit: {"output": "", "subtotal": 100, "total": 100} validates output ("")
        guard = MathGuard()
        res = guard.check({"output": "", "subtotal": 100, "total": 100})
        assert res.passed is False
        assert "No verifiable math" in res.message

    def test_non_numeric_total_reports_total_not_components(self):
        # Sentry: non-numeric total blames the total field, not components
        guard = MathGuard()
        res = guard.check({"output": {"subtotal": 100, "tax": 8, "total": "invalid"}})
        assert res.passed is False
        assert any("total is not a finite number" in e for e in res.details["errors"])

    def test_incomplete_custom_rules_fail(self):
        # Incomplete or invalid custom rules must return errors and fail
        guard_no_exp = MathGuard(custom_rules=[{"type": "equals", "field": "total"}])
        res1 = guard_no_exp.check({"output": {"total": 0}})
        assert res1.passed is False
        assert any("missing 'expected' value" in e for e in res1.details["errors"])

        guard_no_bounds = MathGuard(custom_rules=[{"type": "range", "field": "total"}])
        res2 = guard_no_bounds.check({"output": {"total": 0}})
        assert res2.passed is False
        assert any("must specify 'min' or 'max'" in e for e in res2.details["errors"])

        guard_bad_type = MathGuard(custom_rules=[{"type": "unknown", "field": "total"}])
        res3 = guard_bad_type.check({"output": {"total": 0}})
        assert res3.passed is False
        assert any("Unsupported custom rule type" in e for e in res3.details["errors"])

    def test_verification_result_positional_args_backward_compatibility(self):
        # VerificationResult positional constructor must preserve binding at index 9
        res = VerificationResult(
            True,
            {"val": 1},
            ["g1"],
            [],
            [],
            0.05,
            True,
            "2026-09-07T00:00:00Z",
            {"signature": "sig123"},
            "req-456",
        )
        assert res.binding == {"signature": "sig123"}
        assert res.request_id == "req-456"
