"""ToolGuard envelope rules shared with the npm package.

Both packages run every case in fixtures/tool_guard_envelope_parity.json
with ``allowed_tools=["search"]``, so a passing case means the only call
screened was ``search``. The npm twin is
npm/test/tool-guard-envelope-parity.test.js.
"""

import asyncio
import json
from pathlib import Path

import pytest

from qwed_open_responses import ResponseVerifier, ToolGuard
from qwed_open_responses.middleware.streaming_interceptor import (
    OpenResponsesMiddleware,
)

PARITY_CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "tool_guard_envelope_parity.json").read_text(
        encoding="utf-8"
    )
)["cases"]


@pytest.mark.parametrize("case", PARITY_CASES, ids=lambda case: case["name"])
def test_tool_guard_matches_shared_envelope_cases(case):
    result = ResponseVerifier().verify(
        case["response"], guards=[ToolGuard(allowed_tools=["search"])]
    )

    assert result.verified is (case["expect"] == "pass"), case["rule"]


@pytest.mark.parametrize(
    "item",
    [
        {"type": "tool_call", "tool_name": "search", "name": "execute_shell"},
        {"type": "function_call", "name": "search", "toolName": "execute_shell"},
    ],
)
def test_conflicting_names_are_blocked_in_the_stream(item):
    # #64: the middleware forwards the original item, so a consumer could
    # dispatch on the field the guard did not screen.
    middleware = OpenResponsesMiddleware(guards=[ToolGuard()])

    async def source():
        yield {**item, "arguments": "{}"}

    async def collect():
        return [out async for out in middleware.verify_stream(source())]

    out = asyncio.run(collect())

    assert out[0]["type"] == "system_intervention"
