"""Regression coverage for bounded verification resources in issue #45."""

import pytest

from qwed_open_responses import ResponseVerifier, SafetyGuard, SchemaGuard


def _assert_parse_limit_failure(payload):
    result = ResponseVerifier(default_guards=[SafetyGuard()]).verify(payload)

    assert result.verified is False
    assert result.guards_failed == 1
    assert result.guard_results[0].guard_name == "ResponseVerifier"
    assert "limit" in result.guard_results[0].message.lower()


def test_safety_guard_fails_closed_on_oversized_content():
    result = SafetyGuard().check({"content": "x" * 100_001})

    assert result.passed is False
    assert "character limit" in result.details["resource_limit"]


def test_safety_guard_counts_unicode_code_points_consistently():
    result = SafetyGuard().check({"content": "😀" * 50_001})

    assert result.passed is True


def test_safety_guard_accepts_content_at_character_limit():
    result = SafetyGuard().check({"content": "x" * 100_000})

    assert result.passed is True


def test_safety_guard_fails_closed_on_wide_content_graph():
    result = SafetyGuard().check({"content": [""] * 10_001})

    assert result.passed is False
    assert "node count" in result.details["resource_limit"]


def test_safety_guard_fails_closed_on_deep_content_graph():
    response = {"content": "safe"}
    for _ in range(13):
        response = {"nested": response}

    result = SafetyGuard().check(response)

    assert result.passed is False
    assert "nesting" in result.details["resource_limit"]


def test_safety_guard_fails_closed_on_cyclic_content_graph():
    response = {"content": "safe"}
    response["nested"] = response

    result = SafetyGuard().check(response)

    assert result.passed is False
    assert "cycle" in result.details["resource_limit"]


def test_safety_guard_fails_closed_on_non_string_output_keys():
    result = SafetyGuard().check({"output": {1: "safe"}})

    assert result.passed is False
    assert "non-string object key" in result.details["resource_limit"]


def test_safety_guard_fails_closed_on_unstringifiable_large_integer():
    result = SafetyGuard().check({"output": {"value": 10**5_000}})

    assert result.passed is False
    assert "character limit" in result.details["resource_limit"]


def test_safety_guard_rechecks_shared_objects_in_each_context():
    shared = {"phone": 1234567890}

    result = SafetyGuard().check({"ordinary": shared, "arguments": shared})

    assert result.passed is True
    assert result.severity == "warning"
    assert result.details["issues"][0]["details"] == ["phone"]


def test_safety_guard_charges_field_names_and_join_separators():
    wide_key = SafetyGuard().check({"x" * 20_000: 0})
    assert wide_key.passed is False
    assert "field labels" in wide_key.details["resource_limit"]

    fields = SafetyGuard().check({"items": ["x" * 10] * 9_997})
    assert fields.passed is False
    assert "character limit" in fields.details["resource_limit"]


def test_safety_guard_email_detection_handles_valid_and_adversarial_text():
    valid = SafetyGuard().check({"content": "Contact user.name+tag@example.com"})
    trailing_domain_char = SafetyGuard().check(
        {"content": "Contact a@b.com1, user@example.com-, or user@example.com."}
    )
    adversarial = SafetyGuard().check(
        {"content": ("a." * 1_000) + "@" + ("b." * 1_000) + "!"}
    )
    malformed = SafetyGuard().check({"content": "user@foo..com"})

    assert valid.passed is True
    assert valid.severity == "warning"
    assert valid.details["issues"][0]["details"] == ["email"]
    assert trailing_domain_char.passed is True
    assert trailing_domain_char.severity == "warning"
    assert trailing_domain_char.details["issues"][0]["details"] == ["email"]
    assert adversarial.passed is True
    assert malformed.passed is True


def test_schema_guard_stops_after_first_validation_error():
    schema = {
        "type": "object",
        "properties": {f"field_{index}": {"type": "string"} for index in range(50)},
    }
    data = {f"field_{index}": index for index in range(50)}

    result = SchemaGuard(schema).check({"output": data})

    assert result.passed is False
    assert len(result.details["errors"]) == 1
    assert result.details["total_errors"] is None
    assert result.details["errors_truncated"] is True


def test_verifier_returns_failed_verdict_for_oversized_json():
    payload = '{"content":"' + ("x" * 100_000) + '"}'

    _assert_parse_limit_failure(payload)


def test_verifier_accepts_json_at_character_limit():
    payload = '{"content":"' + ("x" * 99_986) + '"}'

    assert len(payload) == 100_000
    assert len(ResponseVerifier()._parse_response(payload)["content"]) == 99_986


def test_verifier_returns_failed_verdict_for_deep_json():
    depth = 101
    payload = '{"nested":' * depth + "null" + "}" * depth

    _assert_parse_limit_failure(payload)


def test_verifier_accepts_json_at_nesting_limit():
    depth = 100
    payload = '{"nested":' * depth + "null" + "}" * depth

    parsed = ResponseVerifier()._parse_response(payload)
    for _ in range(depth):
        parsed = parsed["nested"]
    assert parsed is None


def test_verifier_returns_failed_verdict_for_integer_conversion_limit():
    payload = '{"value":' + ("9" * 4_301) + "}"

    _assert_parse_limit_failure(payload)


def test_verifier_keeps_plain_text_and_non_object_json_contracts():
    result = ResponseVerifier(default_guards=[SafetyGuard()]).verify("not JSON")

    assert result.verified is True
    assert result.response == {"type": "text", "content": "not JSON"}
    with pytest.raises(ValueError, match="Cannot parse JSON response"):
        ResponseVerifier(default_guards=[SafetyGuard()]).verify("[]")


def test_verifier_keeps_plain_text_with_many_brackets():
    text = "[" * 101 + " code sample"

    result = ResponseVerifier(default_guards=[SafetyGuard()]).verify(text)

    assert result.verified is True
    assert result.response == {"type": "text", "content": text}
