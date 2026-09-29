"""Regression tests for raw tool-argument scanning in issue #39."""

import base64
import json

import pytest

from qwed_open_responses import ToolGuard


@pytest.mark.parametrize(
    "payload",
    [
        "DROP\tTABLE users;",
        "DROP\nTABLE users;",
        "DROP TABLE users;",
        "rm\t-rf /",
        "rm -rf /",
        "eval\n(1 + 1)",
    ],
)
@pytest.mark.parametrize("json_encoded", [False, True], ids=["parsed", "json"])
def test_default_patterns_scan_raw_values(payload, json_encoded):
    arguments = {"command": payload}
    if json_encoded:
        response = {
            "type": "function_call",
            "name": "search",
            "arguments": json.dumps(arguments),
        }
    else:
        response = {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": arguments,
        }

    result = ToolGuard().check(response)

    assert result.passed is False
    assert "dangerous pattern" in result.message.lower()


def test_nested_json_values_are_scanned_after_parsing():
    response = {
        "type": "function_call",
        "name": "search",
        "arguments": json.dumps({"filters": [{"query": "DROP\tTABLE users;"}]}),
    }

    assert ToolGuard().check(response).passed is False


def test_custom_patterns_scan_raw_string_leaves():
    guard = ToolGuard(
        use_default_patterns=False,
        dangerous_patterns=[r"BLOCK\s+ME"],
    )

    result = guard.check(
        {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"nested": ["block\nme"]},
        }
    )

    assert result.passed is False


def test_benign_string_values_pass():
    result = ToolGuard().check(
        {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"query": "weather\tforecast\nfor tomorrow"},
        }
    )

    assert result.passed is True


def test_base64_detection_scans_nested_raw_string_values():
    payload = base64.b64encode(b"rm -rf /").decode("ascii")
    result = ToolGuard().check(
        {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"nested": [{"payload": payload}]},
        }
    )

    assert result.passed is False
    assert result.details["encoding"] == "base64"
