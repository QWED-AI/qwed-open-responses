"""Issue #32 hygiene batch: MathGuard vacuous passes, request/trace IDs,
deprecated utcnow, parse strictness parity."""

import asyncio

import pytest

from qwed_open_responses import MathGuard, ResponseVerifier
from qwed_open_responses.core import GuardResult, _canonical_json


class TestMathGuardNoVerifiableMath:
    """issue #32 item 1: string outputs and lone totals must not pass
    vacuously — the guard returns a distinct warning-severity failure."""

    def test_string_output_fails_not_passes(self):
        guard = MathGuard()
        result = guard.check({"output": "total should be 999"})
        assert result.passed is False
        assert result.severity == "warning"
        assert "No verifiable math" in result.message

    def test_lone_total_without_components_fails_as_mismatch(self):
        # a lone total verifies against zero-defaulted components (mirrors
        # the npm guard) — 999 vs 0 is a mismatch, not a vacuous pass
        guard = MathGuard()
        result = guard.check({"output": {"total": 999}})
        assert result.passed is False
        assert result.details["errors"][0].startswith("total mismatch")

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


class TestAwareUtcTimestamp:
    """issue #32 item 4: datetime.utcnow() is deprecated — the timestamp is
    timezone-aware UTC."""

    def test_timestamp_carries_utc_offset(self):
        verifier = ResponseVerifier(default_guards=[MathGuard()])
        result = verifier.verify(
            {"output": {"subtotal": 100, "tax": 8, "shipping": 0, "total": 108}}
        )
        assert result.timestamp.endswith("+00:00")
