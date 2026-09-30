"""Regression tests for ToolGuard vocabulary and separator normalization."""

import base64
import json

import pytest

from qwed_open_responses import ToolGuard


@pytest.mark.parametrize(
    "payload",
    [
        "rm -fr /",
        "DROP/*x*/TABLE users",
        "os . system(1)",
    ],
)
@pytest.mark.parametrize("json_encoded", [False, True], ids=["parsed", "json"])
def test_equivalent_dangerous_command_spellings_are_blocked(payload, json_encoded):
    arguments = {"command": payload}
    response = {
        "type": "function_call" if json_encoded else "tool_call",
        "name" if json_encoded else "tool_name": "search",
        "arguments": json.dumps(arguments) if json_encoded else arguments,
    }

    result = ToolGuard().check(response)

    assert result.passed is False
    assert "dangerous pattern" in result.message.lower()


@pytest.mark.parametrize(
    "tool_name",
    ["executeShell", "transferMoney", "runCommand", "terminal", " execute-shell "],
)
def test_common_tool_name_aliases_are_blocked(tool_name):
    result = ToolGuard().check(
        {"type": "tool_call", "tool_name": tool_name, "arguments": {}}
    )

    assert result.passed is False
    assert "not allowed" in result.message


def test_custom_validator_uses_padded_normalized_name():
    calls = []

    def validator(arguments):
        calls.append(arguments)
        return True, ""

    guard = ToolGuard(
        use_default_blocklist=False,
        custom_validators={" bash ": validator},
    )

    result = guard.check(
        {"type": "tool_call", "tool_name": "BASH", "arguments": {"ok": True}}
    )

    assert result.passed is True
    assert calls == [{"ok": True}]


def test_allowed_tools_preserve_name_separators():
    guard = ToolGuard(
        use_default_blocklist=False,
        allowed_tools=["safe-tool"],
    )

    exact_name = guard.check(
        {"type": "tool_call", "tool_name": "safe-tool", "arguments": {}}
    )
    alias_name = guard.check(
        {"type": "tool_call", "tool_name": "safeTool", "arguments": {}}
    )

    assert exact_name.passed is True
    assert alias_name.passed is False


@pytest.mark.parametrize(
    "payload", ["rm -r -f /", "rm -f -r /", "rm --force --recursive /"]
)
def test_separate_rm_flags_are_blocked(payload):
    result = ToolGuard().check(
        {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"command": payload},
        }
    )

    assert result.passed is False
    assert "dangerous pattern" in result.message.lower()


def test_rm_flag_normalization_does_not_rewrite_unrecognized_words():
    result = ToolGuard().check(
        {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"query": "rm -refactor documentation"},
        }
    )

    assert result.passed is True


@pytest.mark.parametrize("payload", ["rm -fr /", "DROP/*comment*/TABLE users"])
def test_base64_decoded_arguments_receive_pattern_normalization(payload):
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    result = ToolGuard().check(
        {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"query": encoded},
        }
    )

    assert result.passed is False
    assert result.details.get("encoding") == "base64"


@pytest.mark.parametrize(
    "blocked_tool,incoming_tool,blocked",
    [
        ("bash", "ba\u017fh", True),
        ("\u13a0", "\uab70", True),
        ("ss", "\u1e9e", True),
        ("i", "\u0131", False),
    ],
)
def test_blocked_tool_names_follow_python_casefold(blocked_tool, incoming_tool, blocked):
    guard = ToolGuard(blocked_tools=[blocked_tool], use_default_blocklist=False)

    result = guard.check(
        {"type": "tool_call", "tool_name": incoming_tool, "arguments": {}}
    )

    assert result.passed is not blocked


@pytest.mark.parametrize(
    "allowed_tool,incoming_tool,passed",
    [
        ("bash", "ba\u017fh", True),
        ("i", "\u0131", False),
    ],
)
def test_allowed_tool_names_follow_python_casefold(allowed_tool, incoming_tool, passed):
    guard = ToolGuard(allowed_tools=[allowed_tool], use_default_blocklist=False)

    result = guard.check(
        {"type": "tool_call", "tool_name": incoming_tool, "arguments": {}}
    )

    assert result.passed is passed


def test_custom_validators_keep_separator_distinct_names():
    seen = []

    def validator(label):
        def check(_arguments):
            seen.append(label)
            return True, ""

        return check

    guard = ToolGuard(
        use_default_blocklist=False,
        custom_validators={
            "pay-out": validator("hyphen"),
            "pay_out": validator("underscore"),
        },
    )
    for name in ("pay-out", "pay_out"):
        assert (
            guard.check(
                {"type": "tool_call", "tool_name": name, "arguments": {}}
            ).passed
            is True
        )

    assert seen == ["hyphen", "underscore"]


def test_custom_validators_reject_casefold_collisions():
    with pytest.raises(ValueError, match="Conflicting custom validators"):
        ToolGuard(
            custom_validators={
                "pay-out": lambda _args: (True, ""),
                "PAY-OUT": lambda _args: (False, "different policy"),
            }
        )
