"""Tool calls in the output[] of a Responses API object.

ToolGuard used to fail closed on every response object whose output[] held a
function_call, even a harmless one, because the unknown-item rule from
GHSA-xhq6-w3f2-m5w6 had no matching extraction. Each known call item is now
verified like a standalone item. Unknown executable items, ambiguous hybrid
envelopes and max_calls_per_response must keep failing closed.
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from qwed_open_responses import ArgumentGuard, ResponseVerifier, ToolGuard


def _function_call(name, arguments=None, call_id="call_1"):
    return {
        "type": "function_call",
        "id": f"fc_{call_id}",
        "call_id": call_id,
        "name": name,
        "arguments": json.dumps(arguments or {}),
        "status": "completed",
    }


MESSAGE_ITEM = {
    "type": "message",
    "id": "msg_1",
    "role": "assistant",
    "status": "completed",
    "content": [{"type": "output_text", "text": "Looking that up.", "annotations": []}],
}


def _response(*items, **extra):
    return {
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "model": "gpt-test",
        "output": list(items),
        "tools": [
            {
                "type": "function",
                "name": "search",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                "strict": True,
            }
        ],
        **extra,
    }


def _verify(response, guards=None):
    return ResponseVerifier().verify(response, guards=guards or [ToolGuard()])


# ---------------------------------------------------------------- allowed


def test_harmless_function_call_in_output_verifies():
    response = _response(_function_call("search", {"query": "weather"}))

    result = _verify(response)

    assert result.verified is True
    assert result.guard_results[0].details["tools_checked"] == ["search"]


def test_message_and_function_call_together_verify():
    response = _response(MESSAGE_ITEM, _function_call("search", {"query": "x"}))

    assert _verify(response).verified is True


def test_every_call_in_output_is_checked():
    response = _response(
        _function_call("search", {"query": "a"}, "c1"),
        _function_call("lookup", {"id": 7}, "c2"),
    )

    result = _verify(response)

    assert result.verified is True
    assert result.guard_results[0].details["tools_checked"] == ["search", "lookup"]


def test_allowlisted_call_in_output_verifies():
    guard = ToolGuard(allowed_tools=["search"])

    assert _verify(_response(_function_call("search")), [guard]).verified is True


def test_hosted_tool_item_beside_a_call_still_passes():
    hosted = {
        "type": "web_search_call",
        "id": "ws_1",
        "status": "completed",
        "action": {"type": "search", "query": "weather"},
    }

    assert _verify(_response(hosted, _function_call("search"))).verified is True


def test_allowlisted_action_item_in_output_scans_its_command():
    guard = ToolGuard(use_default_blocklist=False, allowed_tools=["local_shell"])
    benign = {
        "type": "local_shell_call",
        "call_id": "c1",
        "action": {"type": "exec", "command": ["ls", "-la"], "env": {}},
    }
    dangerous = dict(benign, action={"type": "exec", "command": ["rm", "-rf", "/"]})

    assert _verify(_response(benign), [guard]).verified is True
    assert _verify(_response(dangerous), [guard]).verified is False


# ---------------------------------------------------------------- blocked


def test_blocklisted_function_call_in_output_is_blocked():
    result = _verify(_response(MESSAGE_ITEM, _function_call("bash", {"cmd": "ls"})))

    assert result.verified is False
    assert "Tool 'bash' is not allowed" in result.block_reason


def test_call_outside_allowlist_is_blocked():
    guard = ToolGuard(allowed_tools=["search"])

    result = _verify(_response(_function_call("send_report")), [guard])

    assert result.verified is False
    assert "not in allowed list" in result.block_reason


def test_one_bad_call_blocks_the_whole_response():
    response = _response(
        _function_call("search", {"query": "a"}, "c1"),
        _function_call("execute_shell", {"cmd": "ls"}, "c2"),
    )

    assert _verify(response).verified is False


@pytest.mark.parametrize(
    "arguments",
    [
        {"query": "DROP TABLE users"},
        {"query": "x; rm -rf /"},
        {"note": base64.b64encode(b"rm -rf /").decode()},
    ],
    ids=["sql", "shell", "base64"],
)
def test_dangerous_arguments_in_output_call_are_blocked(arguments):
    response = _response(MESSAGE_ITEM, _function_call("search", arguments))

    result = _verify(response)

    assert result.verified is False
    assert "Dangerous pattern" in result.block_reason


def test_custom_validator_runs_on_output_call():
    guard = ToolGuard(
        custom_validators={
            "search": lambda args: (len(args.get("query", "")) < 5, "too long")
        }
    )

    assert _verify(
        _response(_function_call("search", {"query": "ok"})), [guard]
    ).verified
    long_query = _response(_function_call("search", {"query": "far too long"}))
    assert _verify(long_query, [guard]).verified is False


@pytest.mark.parametrize("item_type", ["local_shell_call", "apply_patch_call"])
def test_default_blocklist_still_covers_action_items_beside_a_call(item_type):
    action = {
        "local_shell_call": {
            "type": "local_shell_call",
            "call_id": "c2",
            "action": {"type": "exec", "command": ["ls"], "env": {}},
        },
        "apply_patch_call": {
            "type": "apply_patch_call",
            "call_id": "c2",
            "operation": {"type": "update_file", "path": "a.py", "diff": ""},
        },
    }[item_type]

    response = _response(_function_call("search", call_id="c1"), action)

    assert _verify(response).verified is False


# ---------------------------------------------------------------- malformed


@pytest.mark.parametrize(
    "item",
    [
        {"type": "function_call", "call_id": "c1", "arguments": "{}"},
        {"type": "function_call", "call_id": "c1", "name": " ", "arguments": "{}"},
        {
            "type": "function_call",
            "call_id": "c1",
            "name": "search",
            "arguments": "[1]",
        },
        {"type": "function_call", "call_id": "c1", "name": "search", "arguments": "{"},
    ],
    ids=["no_name", "blank_name", "array_args", "bad_json"],
)
def test_malformed_function_call_in_output_fails_closed(item):
    guard = ToolGuard(use_default_blocklist=False)

    assert _verify(_response(item), [guard]).verified is False


# ---------------------------------------------------------------- unknown items

UNKNOWN_ITEMS = [
    {"type": "future_device_call", "call_id": "c9", "action": {"op": "wipe"}},
    {"type": "future_payment_request", "id": "p1", "payload": {"amount": 5}},
    {"type": "tool_call", "tool_name": "search", "arguments": {}},
]


@pytest.mark.parametrize("unknown", UNKNOWN_ITEMS)
def test_unknown_item_alone_fails_closed(unknown):
    result = _verify(_response(unknown), [ToolGuard(use_default_blocklist=False)])

    assert result.verified is False
    assert "unrecognized format" in result.block_reason


@pytest.mark.parametrize("position", ["before", "after"])
@pytest.mark.parametrize("unknown", UNKNOWN_ITEMS)
def test_unknown_item_beside_a_known_call_fails_closed(unknown, position):
    known = _function_call("search", {"query": "weather"})
    items = [unknown, known] if position == "before" else [known, unknown]

    result = _verify(
        _response(MESSAGE_ITEM, *items), [ToolGuard(use_default_blocklist=False)]
    )

    assert result.verified is False
    assert "unrecognized format" in result.block_reason


def test_named_unknown_item_does_not_borrow_an_allowed_name():
    unknown = {"type": "future_device_call", "name": "search", "arguments": "{}"}
    guard = ToolGuard(allowed_tools=["search"])

    assert _verify(_response(unknown), [guard]).verified is False


# ---------------------------------------------------------------- mixed content


@pytest.mark.parametrize(
    "hidden",
    [
        {"type": "tool_use", "name": "bash", "input": {"cmd": "ls"}},
        {"name": "bash", "arguments": {"cmd": "ls"}},
        {"tool_name": "bash", "arguments": {}},
    ],
    ids=["tool_use_block", "name_and_arguments", "tool_name"],
)
def test_tool_shape_hidden_in_message_beside_a_call_fails_closed(hidden):
    message = {**MESSAGE_ITEM, "content": [*MESSAGE_ITEM["content"], hidden]}

    result = _verify(_response(message, _function_call("search")))

    assert result.verified is False


def test_hosted_mcp_call_with_name_and_arguments_still_fails_closed():
    mcp_call = {
        "type": "mcp_call",
        "id": "mcp_1",
        "server_label": "ops",
        "name": "run",
        "arguments": "{}",
        "output": "done",
    }

    assert _verify(_response(mcp_call, _function_call("search"))).verified is False


def test_message_only_response_is_unchanged():
    assert _verify(_response(MESSAGE_ITEM)).verified is True


def test_function_call_outside_a_response_object_still_fails_closed():
    envelope = {"object": "list", "output": [_function_call("search")]}

    result = _verify(envelope)

    assert result.verified is False
    assert "unrecognized format" in result.block_reason


# ---------------------------------------------------------------- hybrids


@pytest.mark.parametrize(
    "extra",
    [
        {"tool_calls": [{"name": "search", "arguments": {}}]},
        {"choices": [{"message": {"tool_calls": []}}]},
        {"content": [{"type": "text", "text": "hi"}]},
        {"type": "function_call", "name": "search", "arguments": "{}"},
    ],
    ids=["tool_calls", "choices", "content", "direct_type"],
)
def test_response_object_with_a_sibling_call_collection_is_ambiguous(extra):
    response = _response(_function_call("search"), **extra)

    result = _verify(response, [ToolGuard(use_default_blocklist=False)])

    assert result.verified is False
    assert "Ambiguous hybrid" in result.block_reason


def test_output_action_item_cannot_hide_behind_a_sibling_tool_calls_array():
    # Before this change only the sibling tool_calls entry was checked, so
    # the local_shell_call in output[] verified clean.
    shell = {
        "type": "local_shell_call",
        "call_id": "c1",
        "action": {"type": "exec", "command": ["rm", "-rf", "/"], "env": {}},
    }
    response = _response(shell, tool_calls=[{"name": "search", "arguments": {}}])

    assert _verify(response).verified is False


@pytest.mark.parametrize(
    "extra",
    [
        {"tool_calls": [{"name": "search", "arguments": {}}]},
        {"content": [{"type": "tool_use", "name": "bash", "input": {}}]},
        {"function": {"name": "bash", "arguments": "{}"}},
        {"tool_call": {"name": "bash", "arguments": {}}},
    ],
    ids=["tool_calls", "content", "function_wrapper", "nested_tool_call"],
)
def test_output_call_item_carrying_another_envelope_is_ambiguous(extra):
    item = {**_function_call("search"), **extra}

    result = _verify(_response(item), [ToolGuard(use_default_blocklist=False)])

    assert result.verified is False


# ---------------------------------------------------------------- max calls


def test_max_calls_per_response_counts_output_calls():
    calls = [_function_call("search", call_id=f"c{i}") for i in range(11)]

    result = _verify(_response(MESSAGE_ITEM, *calls))

    assert result.verified is False
    assert "Too many tool calls: 11 (max: 10)" in result.block_reason


def test_max_calls_per_response_allows_the_limit():
    calls = [_function_call("search", call_id=f"c{i}") for i in range(10)]

    assert _verify(_response(*calls)).verified is True


def test_custom_max_calls_per_response_applies_to_output():
    guard = ToolGuard(max_calls_per_response=1)
    response = _response(
        _function_call("search", call_id="c1"), _function_call("search", call_id="c2")
    )

    assert _verify(response, [guard]).verified is False


# ---------------------------------------------------------------- ArgumentGuard


def test_argument_guard_applies_tool_rules_to_output_calls():
    guard = ArgumentGuard(
        tool_rules={"transfer": {"amount": {"type": "number", "max": 100}}}
    )
    small = _response(MESSAGE_ITEM, _function_call("transfer", {"amount": 50}))
    large = _response(MESSAGE_ITEM, _function_call("transfer", {"amount": 500}))

    assert _verify(small, [guard]).verified is True
    assert _verify(large, [guard]).verified is False


def test_argument_guard_reports_missing_required_argument_in_output_call():
    guard = ArgumentGuard(rules={"query": {"type": "string", "required": True}})

    assert _verify(_response(_function_call("search", {})), [guard]).verified is False


def test_argument_guard_fails_closed_on_unknown_output_item():
    guard = ArgumentGuard(rules={})
    unknown = {"type": "future_device_call", "action": {"op": "wipe"}}

    assert (
        _verify(_response(_function_call("search"), unknown), [guard]).verified is False
    )


# ---------------------------------------------------------------- OpenAI wrapper


def _openai_response(output):
    responses = pytest.importorskip("openai.types.responses")
    payload = _response(*output)
    payload.pop("status")
    return responses.Response.model_validate(
        {
            **payload,
            "created_at": 1,
            "parallel_tool_calls": True,
            "tool_choice": "auto",
        }
    )


def _verified_client(sdk_response, guards):
    pytest.importorskip("openai")
    from qwed_open_responses.middleware.openai_sdk import VerifiedOpenAI

    client = MagicMock(spec=["chat", "responses"])
    client.responses.create.return_value = sdk_response
    with patch(
        "qwed_open_responses.middleware.openai_sdk.openai.OpenAI",
        return_value=client,
    ):
        return VerifiedOpenAI(guards=guards)


def test_verified_openai_responses_create_passes_a_harmless_tool_call():
    sdk_response = _openai_response(
        [MESSAGE_ITEM, _function_call("search", {"query": "weather"})]
    )
    verified = _verified_client(sdk_response, [ToolGuard()])

    response = verified.responses.create(model="gpt-test", input="weather?")

    assert response is sdk_response
    assert response._qwed_verification.verified is True


def test_verified_openai_responses_create_blocks_a_dangerous_tool_call():
    from qwed_open_responses.middleware.openai_sdk import ResponseBlocked

    sdk_response = _openai_response([_function_call("bash", {"cmd": "rm -rf /"})])
    verified = _verified_client(sdk_response, [ToolGuard()])

    with pytest.raises(ResponseBlocked, match="Tool 'bash' is not allowed"):
        verified.responses.create(model="gpt-test", input="clean up")
