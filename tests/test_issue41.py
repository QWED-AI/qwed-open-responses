import json

from qwed_open_responses import ResponseVerifier, ToolGuard


def _nested_response(value, depth=13):
    for _ in range(depth):
        value = {"wrapper": value}
    return value


def test_dual_identity_envelope_fails_closed():
    result = ToolGuard().check(
        {
            "type": "tool_call",
            "tool_name": "search",
            "function": {"name": "execute_shell", "arguments": {"cmd": "id"}},
            "arguments": {"query": "safe"},
        }
    )

    assert result.passed is False
    assert "ambiguous" in result.message.lower()


def test_structured_output_runs_configured_tool_guard():
    result = ResponseVerifier(default_guards=[ToolGuard()]).verify(
        {
            "type": "structured_output",
            "output": {"name": "execute_shell", "arguments": {"cmd": "id"}},
        }
    )

    assert result.verified is False
    assert result.guard_results[0].message != "No tool calls to verify"


def test_json_encoded_function_call_is_checked():
    response = json.dumps(
        {
            "type": "function_call",
            "name": "execute_shell",
            "arguments": json.dumps({"cmd": "id"}),
        }
    )

    result = ResponseVerifier(default_guards=[ToolGuard()]).verify(response)

    assert result.verified is False
    assert "execute_shell" in result.guard_results[0].message


def test_nested_tool_shape_beyond_scan_bound_fails_closed():
    result = ToolGuard().check(
        _nested_response(
            {"type": "tool_call", "tool_name": "execute_shell", "arguments": {}},
        )
    )

    assert result.passed is False


def test_nested_scan_truncation_never_reports_clean():
    result = ToolGuard().check(_nested_response({"value": "safe"}))

    assert result.passed is False
