"""Client-executed Responses API action items (GHSA-xhq6-w3f2-m5w6).

Items such as ``local_shell_call`` ask the client to run a shell command,
apply a patch or drive a computer without a function name/arguments
envelope. They must be policy-checked like function calls — never read as
tool-free content — on the direct, nested and streaming paths.
"""

import asyncio

import pytest

from qwed_open_responses import ArgumentGuard, ResponseVerifier, ToolGuard
from qwed_open_responses.middleware.streaming_interceptor import (
    OpenResponsesMiddleware,
)

ACTION_ITEMS = {
    "local_shell_call": {
        "type": "local_shell_call",
        "call_id": "c1",
        "status": "completed",
        "action": {"type": "exec", "command": ["rm", "-rf", "/"], "env": {}},
    },
    "shell_call": {
        "type": "shell_call",
        "call_id": "c2",
        "action": {"commands": ["rm -rf /"]},
    },
    "apply_patch_call": {
        "type": "apply_patch_call",
        "call_id": "c3",
        "operation": {"type": "delete_file", "path": "/etc/passwd"},
    },
    "computer_call": {
        "type": "computer_call",
        "call_id": "c4",
        "action": {"type": "type", "text": "rm -rf /"},
    },
    "custom_tool_call": {
        "type": "custom_tool_call",
        "call_id": "c5",
        "name": "bash",
        "input": "rm -rf /",
    },
    "mcp_approval_request": {
        "type": "mcp_approval_request",
        "id": "a1",
        "server_label": "ops",
        "name": "execute_shell",
        "arguments": "{}",
    },
}


def _verify(response, guards=None):
    return ResponseVerifier().verify(response, guards=guards or [ToolGuard()])


def _stream(items, guards=None):
    middleware = OpenResponsesMiddleware(guards=guards or [ToolGuard()])

    async def source():
        for item in items:
            yield item

    async def collect():
        return [out async for out in middleware.verify_stream(source())]

    return asyncio.run(collect()), middleware.get_stats()


@pytest.mark.parametrize("item_type", sorted(ACTION_ITEMS))
def test_action_item_is_blocked_standalone(item_type):
    result = _verify(ACTION_ITEMS[item_type])

    assert result.verified is False
    assert result.blocked is True


@pytest.mark.parametrize("item_type", sorted(ACTION_ITEMS))
def test_action_item_is_blocked_inside_response_output(item_type):
    response = {
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "output": [ACTION_ITEMS[item_type]],
    }

    result = _verify(response)

    assert result.verified is False
    assert result.blocked is True


@pytest.mark.parametrize("item_type", sorted(ACTION_ITEMS))
def test_action_item_is_blocked_in_stream(item_type):
    out, stats = _stream([ACTION_ITEMS[item_type]])

    assert out[0]["type"] == "system_intervention"
    assert stats == {"total": 1, "verified": 0, "blocked": 1}


@pytest.mark.parametrize("item_type", sorted(ACTION_ITEMS))
def test_action_item_is_blocked_inside_stream_event(item_type):
    event = {"type": "response.output_item.done", "item": ACTION_ITEMS[item_type]}

    out, stats = _stream([event])

    assert out[0]["type"] == "system_intervention"
    assert stats["blocked"] == 1


@pytest.mark.parametrize(
    "item_type, canonical_name",
    [
        ("local_shell_call", "local_shell"),
        ("shell_call", "shell"),
        ("apply_patch_call", "apply_patch"),
        ("computer_call", "computer_use"),
    ],
)
def test_action_items_normalize_to_canonical_tool_names(item_type, canonical_name):
    calls = ToolGuard.normalize_tool_calls(ACTION_ITEMS[item_type])

    assert len(calls) == 1
    assert calls[0]["type"] == "tool_call"
    assert calls[0]["tool_name"] == canonical_name


def test_stream_intervention_names_the_canonical_tool():
    out, _ = _stream([ACTION_ITEMS["local_shell_call"]])

    assert out[0]["tool_name"] == "local_shell"


def _allow_only(*names):
    return ToolGuard(use_default_blocklist=False, allowed_tools=list(names))


def test_allowlisted_local_shell_still_scans_the_joined_argv():
    dangerous = ACTION_ITEMS["local_shell_call"]
    benign = {
        "type": "local_shell_call",
        "call_id": "c6",
        "action": {"type": "exec", "command": ["ls", "-la"], "env": {}},
    }

    assert _verify(dangerous, [_allow_only("local_shell")]).verified is False
    assert _verify(benign, [_allow_only("local_shell")]).verified is True


def test_allowlisted_shell_call_scans_each_command():
    benign = {"type": "shell_call", "call_id": "c7", "action": {"commands": ["ls"]}}

    assert _verify(ACTION_ITEMS["shell_call"], [_allow_only("shell")]).verified is False
    assert _verify(benign, [_allow_only("shell")]).verified is True


def test_allowlist_without_action_tool_blocks_it():
    result = _verify(ACTION_ITEMS["apply_patch_call"], [_allow_only("search")])

    assert result.verified is False


def test_custom_tool_input_is_pattern_scanned():
    item = {
        "type": "custom_tool_call",
        "call_id": "c8",
        "name": "run_sql",
        "input": "DROP TABLE users",
    }
    benign = dict(item, input="select 1")

    assert _verify(item).verified is False
    assert _verify(benign).verified is True


@pytest.mark.parametrize("key", ["tool_name", "toolName"])
def test_custom_tool_conflicting_declared_name_fails_closed(key):
    item = {
        "type": "custom_tool_call",
        "call_id": "c9",
        "name": "bash",
        key: "search",
        "input": "ls",
    }

    result = _verify(item, [ToolGuard(use_default_blocklist=False)])

    assert result.verified is False


@pytest.mark.parametrize(
    "item",
    [
        {"type": "custom_tool_call", "call_id": "c10", "input": "ls"},
        {"type": "custom_tool_call", "call_id": "c11", "name": "x", "input": {"a": 1}},
        {"type": "local_shell_call", "call_id": "c12", "action": "rm -rf /"},
        {"type": "apply_patch_call", "call_id": "c13"},
        {"type": "mcp_approval_request", "id": "a2", "name": "x", "arguments": "[1]"},
    ],
)
def test_malformed_action_items_fail_closed(item):
    result = _verify(item, [ToolGuard(use_default_blocklist=False)])

    assert result.verified is False


@pytest.mark.parametrize(
    "extra",
    [
        {"tool_call": {"name": "search", "arguments": {}}},
        {"function_call": {"name": "search", "arguments": "{}"}},
        {"function": {"name": "search", "arguments": "{}"}},
        {"tool_calls": [{"name": "search", "arguments": {}}]},
    ],
)
def test_action_item_carrying_another_call_envelope_is_ambiguous(extra):
    item = {**ACTION_ITEMS["local_shell_call"], **extra}

    result = _verify(item, [ToolGuard(use_default_blocklist=False)])

    assert result.verified is False


UNKNOWN_ACTION_ITEMS = [
    {"type": "future_device_call", "call_id": "c14", "action": {"op": "wipe"}},
    {"type": "future_payment_request", "id": "p1", "payload": {"amount": 5}},
]


@pytest.mark.parametrize("unknown", UNKNOWN_ACTION_ITEMS)
def test_unknown_executable_item_fails_closed_in_response_output(unknown):
    guards = [ToolGuard(use_default_blocklist=False)]

    result = _verify({"object": "response", "output": [unknown]}, guards)

    assert result.verified is False


@pytest.mark.parametrize("unknown", UNKNOWN_ACTION_ITEMS)
@pytest.mark.parametrize(
    "wrap",
    [
        lambda item: item,
        lambda item: {"type": "response.output_item.done", "item": item},
        lambda item: {
            "type": "response.completed",
            "response": {"object": "response", "output": [item]},
        },
    ],
    ids=["stream_item", "output_item_event", "completed_event"],
)
def test_unknown_executable_item_fails_closed_in_stream(unknown, wrap):
    out, stats = _stream([wrap(unknown)], [ToolGuard(use_default_blocklist=False)])

    assert out[0]["type"] == "system_intervention"
    assert stats["blocked"] == 1


@pytest.mark.parametrize(
    "response",
    [
        {"type": "refund_request", "amount": 5},
        {"type": "structured_output", "output": {"pr": {"type": "pull_request"}}},
        {"type": "message", "content": [{"type": "phone_call", "minutes": 3}]},
        {"object": "list", "output": [{"type": "merge_request", "iid": 1}]},
    ],
)
def test_ordinary_data_type_labels_are_not_action_items(response):
    assert _verify(response).verified is True


def test_unknown_executable_item_blocked_even_without_tool_guard():
    from qwed_open_responses import SafetyGuard

    item = {"type": "future_device_call", "call_id": "c15", "action": {"op": "wipe"}}

    out, _ = _stream([item], [SafetyGuard()])

    assert out[0]["type"] == "system_intervention"


@pytest.mark.parametrize(
    "item",
    [
        {
            "type": "web_search_call",
            "id": "ws1",
            "status": "completed",
            "action": {"type": "search", "query": "weather"},
        },
        {
            "type": "file_search_call",
            "id": "fs1",
            "status": "completed",
            "queries": ["q"],
        },
    ],
)
def test_hosted_tool_items_keep_passing(item):
    assert _verify(item).verified is True
    out, stats = _stream([item])
    assert out == [item]
    assert stats["blocked"] == 0


def test_tool_outputs_are_not_treated_as_action_requests():
    item = {"type": "function_call_output", "call_id": "c1", "output": "done"}

    assert _verify(item).verified is True


def test_argument_guard_applies_rules_to_custom_tool_input():
    guard = ArgumentGuard(rules={"input": {"type": "string", "max_length": 5}})
    item = {
        "type": "custom_tool_call",
        "call_id": "c16",
        "name": "echo",
        "input": "far too long",
    }

    assert ResponseVerifier().verify(item, guards=[guard]).verified is False
    short = dict(item, input="ok")
    assert ResponseVerifier().verify(short, guards=[guard]).verified is True


def test_argument_guard_keeps_root_arguments_for_data_type_labels():
    guard = ArgumentGuard(rules={"amount": {"type": "number", "max": 10}})
    item = {"type": "refund_request", "arguments": {"amount": 50}}

    assert ResponseVerifier().verify(item, guards=[guard]).verified is False
    small = {"type": "refund_request", "arguments": {"amount": 5}}
    assert ResponseVerifier().verify(small, guards=[guard]).verified is True
