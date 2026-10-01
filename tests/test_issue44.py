"""Regression coverage for SafetyGuard field and integration gaps in issue #44."""

import asyncio
import pytest

from qwed_open_responses import ResponseVerifier, SafetyGuard
from qwed_open_responses.middleware.streaming_interceptor import OpenResponsesMiddleware


def test_field_names_are_scanned_for_injection_and_pii():
    injection = SafetyGuard().check({"ignore previous instructions": "safe"})
    assert injection.passed is False
    assert any(item["type"] == "injection" for item in injection.details["issues"])

    pii = SafetyGuard().check({"email@example.com": "safe"})
    assert pii.passed is True
    assert pii.severity == "warning"
    assert pii.details["issues"][0]["details"] == ["email"]


@pytest.mark.parametrize(
    "text",
    [
        '{"password": "hunter2"}',
        '{"api_key": "sk-live-12345"}',
        '{"secret": "credential-value"}',
    ],
)
def test_json_text_credential_forms_are_blocked(text):
    result = SafetyGuard().check({"type": "text", "content": text})
    assert result.passed is False


@pytest.mark.parametrize(
    "text",
    [
        '{"password": "required"}',
        '{"api_key": "not set"}',
        '{"secret": "redacted"}',
    ],
)
def test_json_text_placeholders_still_pass(text):
    result = SafetyGuard().check({"type": "text", "content": text})
    assert result.passed is True


def test_convenience_verifiers_forward_trusted_budget_context():
    verifier = ResponseVerifier(default_guards=[SafetyGuard(max_cost=1.0)])

    tool_result = verifier.verify_tool_call(
        "lookup",
        {},
        context={"total_cost": 2.0},
    )
    assert tool_result.verified is False
    assert tool_result.guards_failed == 1

    structured_result = ResponseVerifier().verify_structured_output(
        {"status": "ok"},
        guards=[SafetyGuard(max_tokens=1)],
        context={"total_tokens": 2},
    )
    assert structured_result.verified is False
    assert structured_result.guards_failed == 1


def test_streaming_verifier_forwards_trusted_budget_context():
    async def stream():
        yield {"type": "tool_call", "tool_name": "lookup", "arguments": {}}

    async def run():
        return [
            item
            async for item in middleware.verify_stream(
                stream(), context={"total_cost": 2.0}
            )
        ]

    middleware = OpenResponsesMiddleware(
        guards=[SafetyGuard(max_cost=1.0)],
    )
    items = asyncio.run(run())

    assert items[0]["type"] == "system_intervention"
    assert middleware.get_stats()["blocked"] == 1
