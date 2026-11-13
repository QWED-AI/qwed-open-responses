"""ArgumentGuard on tool calls in the output[] of a Responses API object.

Each call item's arguments are checked against ``rules`` / ``tool_rules``,
as they are for a standalone call. Previously the ``output`` list itself was
read as one argument set, so no rule was ever applied.
"""

import json

import pytest

from qwed_open_responses import ArgumentGuard, ResponseVerifier


def _function_call(name, arguments, call_id="call_1"):
    return {
        "type": "function_call",
        "id": f"fc_{call_id}",
        "call_id": call_id,
        "name": name,
        "arguments": json.dumps(arguments),
        "status": "completed",
    }


MESSAGE_ITEM = {
    "type": "message",
    "id": "msg_1",
    "role": "assistant",
    "status": "completed",
    "content": [{"type": "output_text", "text": "On it.", "annotations": []}],
}


def _response(*items):
    return {"id": "resp_1", "object": "response", "output": list(items)}


def _verify(response, guard):
    return ResponseVerifier().verify(response, guards=[guard])


def test_tool_rules_apply_to_each_output_call():
    guard = ArgumentGuard(
        tool_rules={"transfer": {"amount": {"type": "number", "max": 100}}}
    )
    small = _response(MESSAGE_ITEM, _function_call("transfer", {"amount": 50}))
    large = _response(MESSAGE_ITEM, _function_call("transfer", {"amount": 500}))

    assert _verify(small, guard).verified is True
    assert _verify(large, guard).verified is False


def test_tool_rules_pick_the_schema_per_call():
    guard = ArgumentGuard(
        rules={"query": {"type": "string"}},
        tool_rules={"transfer": {"amount": {"type": "number", "max": 100}}},
    )
    response = _response(
        _function_call("search", {"query": "fees"}, "c1"),
        _function_call("transfer", {"amount": 500}, "c2"),
    )

    assert _verify(response, guard).verified is False


def test_missing_required_argument_in_output_call_fails():
    guard = ArgumentGuard(rules={"query": {"type": "string", "required": True}})

    assert _verify(_response(_function_call("search", {})), guard).verified is False


def test_unexpected_argument_in_output_call_fails_when_extras_are_off():
    guard = ArgumentGuard(rules={"query": {"type": "string"}}, allow_extra_args=False)
    call = _function_call("search", {"query": "fees", "debug": True})

    assert _verify(_response(call), guard).verified is False


def test_unknown_output_item_fails_closed():
    guard = ArgumentGuard(rules={})
    unknown = {"type": "future_device_call", "action": {"op": "wipe"}}

    response = _response(_function_call("search", {"query": "x"}), unknown)

    assert _verify(response, guard).verified is False


@pytest.mark.parametrize("key", ["tool_name", "toolName"])
def test_tool_rules_match_a_call_named_by_another_name_field(key):
    guard = ArgumentGuard(
        tool_rules={"transfer": {"amount": {"type": "number", "max": 100}}}
    )

    def call(amount):
        return {
            "type": "function_call",
            "call_id": "c1",
            key: "transfer",
            "arguments": json.dumps({"amount": amount}),
        }

    assert _verify(_response(call(50)), guard).verified is True
    assert _verify(_response(call(500)), guard).verified is False


def test_conflicting_name_fields_fail_closed():
    # #64: rules for "search" must not be applied to a call that a consumer
    # could dispatch as "transfer".
    guard = ArgumentGuard(rules={}, tool_rules={"transfer": {"amount": {"max": 1}}})
    call = {
        "type": "function_call",
        "call_id": "c1",
        "name": "search",
        "tool_name": "transfer",
        "arguments": json.dumps({"amount": 500}),
    }

    assert _verify(_response(call), guard).verified is False


def test_message_only_response_is_unchanged():
    guard = ArgumentGuard(rules={"query": {"type": "string", "required": True}})

    assert _verify(_response(MESSAGE_ITEM), guard).verified is True
