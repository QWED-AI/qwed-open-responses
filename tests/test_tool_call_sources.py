"""One call source per response, and nothing hidden beside it.

A harmless call in one envelope must not let a call in another go
unchecked, whatever ``object`` says (an ``output[]`` list, a stream
``item``, a ``response`` wrapper, another block). A response object's
``output`` must be a list of objects. Argument normalisation stays linear
on long inputs. The npm twin is npm/test/tool-call-sources.test.js; the
shared envelope cases are in fixtures/tool_guard_envelope_parity.json.
"""

import random
import re
import time

import pytest

from qwed_open_responses import ArgumentGuard, ResponseVerifier, ToolGuard

RM_RF = {
    "type": "local_shell_call",
    "call_id": "call_9",
    "action": {"type": "exec", "command": ["rm", "-rf", "/"], "env": {}},
}
BASH_CALL = {
    "type": "function_call",
    "call_id": "call_1",
    "name": "bash",
    "arguments": '{"cmd": "ls"}',
}
SEARCH_CALL = {
    "type": "function_call",
    "call_id": "call_2",
    "name": "search",
    "arguments": "{}",
}
SEARCH_TOOL_CALLS = [
    {"type": "function", "function": {"name": "search", "arguments": "{}"}}
]
SEARCH_TOOL_USE = {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {}}


def _check(response, **options):
    return ToolGuard(allowed_tools=["search"], **options).check(response)


HIDDEN_BESIDE_A_SAFE_CALL = {
    "output list with no object": {"output": [RM_RF], "tool_calls": SEARCH_TOOL_CALLS},
    "realtime.response object": {
        "object": "realtime.response",
        "output": [BASH_CALL],
        "tool_calls": SEARCH_TOOL_CALLS,
    },
    "stream item": {
        "type": "response.output_item.done",
        "item": RM_RF,
        "tool_calls": SEARCH_TOOL_CALLS,
    },
    "response wrapper": {
        "type": "response.completed",
        "response": {"object": "response", "output": [RM_RF]},
        "tool_calls": SEARCH_TOOL_CALLS,
    },
    "output list beside a tool_use block": {
        "output": [RM_RF],
        "content": [SEARCH_TOOL_USE],
    },
    "unknown item in an output list": {
        "output": [{"type": "exec_call", "command": "rm -rf /"}],
        "tool_calls": SEARCH_TOOL_CALLS,
    },
    "unknown stream item beside a response object call": {
        "object": "response",
        "output": [SEARCH_CALL],
        "item": {"type": "exec_call"},
    },
    "legacy function_call beside message tool_calls": {
        "choices": [
            {
                "message": {
                    "tool_calls": SEARCH_TOOL_CALLS,
                    "function_call": {"name": "bash", "arguments": "{}"},
                }
            }
        ]
    },
    "function_call block beside a tool_use block": {
        "content": [SEARCH_TOOL_USE, BASH_CALL],
    },
    "root tool_name and arguments beside tool_calls": {
        "tool_name": "bash",
        "arguments": {"cmd": "ls"},
        "tool_calls": SEARCH_TOOL_CALLS,
    },
    "output list on a direct tool_call": {
        "type": "tool_call",
        "tool_name": "search",
        "arguments": {},
        "output": [RM_RF],
    },
    "stream item on a direct function_call": {
        **SEARCH_CALL,
        "item": RM_RF,
    },
}


@pytest.mark.parametrize(
    "response", HIDDEN_BESIDE_A_SAFE_CALL.values(), ids=HIDDEN_BESIDE_A_SAFE_CALL
)
def test_call_hidden_beside_a_safe_call_fails_closed(response):
    result = _check(response)

    assert result.passed is False
    assert "unrecognized format" in result.message


def _wrapped(depth, inner):
    for _ in range(depth):
        inner = {"type": "response.completed", "response": inner}
    return inner


def test_response_wrapper_chain_is_followed_to_the_scan_bound():
    hidden = {"object": "response", "output": [{"type": "exec_call"}]}

    for depth in (1, 11):
        response = {**_wrapped(depth, hidden), "tool_calls": SEARCH_TOOL_CALLS}
        assert _check(response).passed is False
    # Past the bound the chain cannot be read to the end, so it fails closed
    # even with nothing executable inside.
    benign = {**_wrapped(13, {"output": []}), "tool_calls": SEARCH_TOOL_CALLS}
    assert _check(benign).passed is False
    shallow = {**_wrapped(2, {"output": []}), "tool_calls": SEARCH_TOOL_CALLS}
    assert _check(shallow).passed is True


@pytest.mark.parametrize(
    "response",
    [
        {
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "refusal": None,
                        "annotations": [],
                        "function_call": None,
                        "tool_calls": SEARCH_TOOL_CALLS,
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 9, "completion_tokens": 3},
        },
        {
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Searching."},
                {
                    "type": "server_tool_use",
                    "id": "srvtoolu_1",
                    "name": "web_search",
                    "input": {"query": "q"},
                },
                SEARCH_TOOL_USE,
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 9, "output_tokens": 3},
        },
        {"type": "tool_call", "tool_name": "search", "arguments": {"q": "x"}},
        {**SEARCH_CALL, "status": "completed", "id": "fc_1"},
        {"object": "response", "output": [SEARCH_CALL]},
    ],
    ids=[
        "chat completion",
        "anthropic message",
        "tool_call",
        "function_call",
        "response",
    ],
)
def test_one_call_source_with_ordinary_fields_still_verifies(response):
    assert _check(response).passed is True


def test_response_object_root_type_exempts_nothing_without_a_call():
    response = {
        "object": "response",
        "type": "message",
        "output": [
            {
                "type": "message",
                "content": [{"type": "tool_use", "name": "bash", "input": {}}],
            }
        ],
    }

    assert _check(response).passed is False


@pytest.mark.parametrize("key", ["functionCall", "tool_use", "toolCalls"])
def test_root_action_item_carrying_another_call_is_ambiguous(key):
    response = {
        "type": "custom_tool_call",
        "name": "search",
        "input": "x",
        key: {"name": "bash", "arguments": "{}"},
    }

    result = _check(response)

    assert result.passed is False
    assert "Ambiguous hybrid" in result.message


# A response object's output must be a list of objects.


@pytest.mark.parametrize(
    "output",
    [
        (BASH_CALL,),
        ["text"],
        [None, SEARCH_CALL],
        [[BASH_CALL]],
        "hello",
        {"type": "message"},
    ],
    ids=["tuple", "string member", "null member", "list member", "string", "object"],
)
def test_malformed_response_output_fails_closed(output):
    result = _check({"object": "response", "output": output})

    assert result.passed is False
    assert "output must be a list of objects" in result.message


def test_response_object_without_output_has_no_calls():
    assert _check({"object": "response", "output": None}).passed is True


def _sdk_response(call):
    responses = pytest.importorskip("openai.types.responses")
    return responses.Response.model_validate(
        {
            "id": "resp_1",
            "object": "response",
            "created_at": 1,
            "status": "completed",
            "model": "gpt-test",
            "tools": [],
            "tool_choice": "auto",
            "parallel_tool_calls": True,
            "output": [call],
        }
    )


def test_sdk_objects_left_in_output_fail_closed():
    sdk_response = _sdk_response(BASH_CALL)

    for response in (
        dict(sdk_response),
        {"object": "response", "output": sdk_response.output},
    ):
        result = _check(response)
        assert result.passed is False
        assert "model_dump()" in result.message
    # The SDK object itself is converted by ResponseVerifier, and the bash
    # call inside is then screened like any other.
    verified = ResponseVerifier().verify(
        sdk_response, guards=[ToolGuard(allowed_tools=["search"])]
    )
    assert verified.verified is False
    assert "Tool 'bash'" in verified.guard_results[0].message


# Conflicting name fields get their own message (#64).


@pytest.mark.parametrize(
    "response",
    [
        {"type": "tool_call", "name": "search", "tool_name": "bash"},
        {"tool_calls": [{"tool_call": {"name": "search", "tool_name": "bash"}}]},
        {
            "object": "response",
            "output": [
                {
                    "type": "custom_tool_call",
                    "call_id": "call_1",
                    "name": "search",
                    "tool_name": "  ",
                    "input": "x",
                }
            ],
        },
    ],
    ids=["direct call", "nested call", "custom_tool_call with a blank tool_name"],
)
def test_conflicting_name_fields_say_so(response):
    result = _check(response)

    assert result.passed is False
    assert "name fields disagree" in result.message


# NaN and Infinity are not JSON (matches the npm package).


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_json_number_literals_fail_closed(literal):
    response = {
        "type": "tool_call",
        "tool_name": "search",
        "arguments": '{"amount": %s}' % literal,
    }

    assert _check(response).passed is False


# ArgumentGuard follows the same call sources.


def test_argument_guard_checks_output_calls_without_a_response_object():
    guard = ArgumentGuard(rules={"amount": {"type": "number", "max": 100}})
    call = {
        "type": "function_call",
        "call_id": "call_1",
        "name": "transfer",
        "arguments": '{"amount": 999}',
    }

    assert guard.check({"output": [call]}).passed is False
    assert guard.check({"item": call}).passed is False
    assert guard.check({"object": "response", "output": [call]}).passed is False


def test_argument_guard_rejects_non_finite_numbers():
    guard = ArgumentGuard(rules={"amount": {"type": "number", "min": 0, "max": 100}})

    for value in (float("nan"), float("inf")):
        result = guard.check(
            {
                "type": "tool_call",
                "tool_name": "transfer",
                "arguments": {"amount": value},
            }
        )
        assert result.passed is False
    nan_text = {
        "type": "tool_call",
        "tool_name": "transfer",
        "arguments": '{"amount": NaN}',
    }
    assert guard.check(nan_text).passed is False


def test_argument_guard_tool_rules_match_padded_names():
    guard = ArgumentGuard(
        tool_rules={" Transfer ": {"amount": {"type": "number", "max": 100}}}
    )

    result = guard.check(
        {"type": "tool_call", "tool_name": "transfer ", "arguments": {"amount": 999}}
    )

    assert result.passed is False


# Argument normalisation is linear: "\s*\.\s*" backtracked quadratically.


def test_dot_spacing_matches_the_regex_it_replaces():
    old = re.compile(r"\s*\.\s*")
    rng = random.Random(64)
    alphabet = [" ", "\t", "\n", "　", "\x85", ".", "a", "b"]
    for _ in range(3000):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        assert ToolGuard._collapse_dot_spacing(value) == old.sub(".", value), value


@pytest.mark.parametrize(
    "text",
    [" " * 99_000, " " * 99_000 + "x", "a" + " \t" * 49_000 + "b", ". " * 49_000],
    ids=["spaces", "spaces then text", "mixed whitespace", "dots and spaces"],
)
def test_long_whitespace_in_output_call_is_checked_quickly(text):
    response = {
        "object": "response",
        "output": [
            {
                "type": "custom_tool_call",
                "call_id": f"call_{index}",
                "name": "search",
                "input": text,
            }
            for index in range(10)
        ],
    }

    started = time.perf_counter()
    result = _check(response)
    elapsed = time.perf_counter() - started

    assert result.passed is True
    # The regex took about 18 seconds per 99,000-space item; this takes
    # milliseconds. The bound leaves room for slow CI runners.
    assert elapsed < 5


def test_dot_spacing_still_folds_spaced_dangerous_calls():
    response = {
        "type": "tool_call",
        "tool_name": "search",
        "arguments": {"q": "os 　.\n system('id')"},
    }

    assert _check(response).passed is False
