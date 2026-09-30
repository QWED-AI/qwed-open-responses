"""Regression tests for ToolGuard vocabulary and separator normalization."""

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


def test_allowed_tools_use_the_same_separator_normalization():
    guard = ToolGuard(
        use_default_blocklist=False,
        allowed_tools=["safe-tool"],
    )

    result = guard.check(
        {"type": "tool_call", "tool_name": "safeTool", "arguments": {}}
    )

    assert result.passed is True
