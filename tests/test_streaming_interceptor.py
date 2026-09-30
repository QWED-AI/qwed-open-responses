"""Tests for OpenResponsesMiddleware — Streaming Interceptor."""

import asyncio

from qwed_open_responses.core import GuardResult, VerificationResult
from qwed_open_responses.guards.argument_guard import ArgumentGuard
from qwed_open_responses.guards.base import BaseGuard
from qwed_open_responses.guards.tax_guard import TaxGuard
from qwed_open_responses.guards.tool_guard import ToolGuard
from qwed_open_responses.middleware.streaming_interceptor import (
    OpenResponsesMiddleware,
)


# ------------------------------------------------------------------ #
#  Test helpers
# ------------------------------------------------------------------ #


class PassGuard(BaseGuard):
    """Guard that always passes."""

    name = "pass_guard"
    description = "Always passes"

    def check(self, _response, _context=None):
        return GuardResult(guard_name=self.name, passed=True, message="OK")


class FailGuard(BaseGuard):
    """Guard that always fails."""

    name = "fail_guard"
    description = "Always fails"

    def check(self, _response, _context=None):
        return GuardResult(
            guard_name=self.name,
            passed=False,
            message="Blocked: dangerous tool call",
            severity="error",
        )


class ExplodingGuard(BaseGuard):
    """Guard that throws an exception."""

    name = "exploding_guard"
    description = "Raises an error"

    def check(self, _response, _context=None):
        raise RuntimeError("kaboom")


class CaptureGuard(PassGuard):
    """Pass while retaining the exact response object presented to guards."""

    def __init__(self):
        self.responses = []

    def check(self, response, context=None):
        self.responses.append(response)
        return super().check(response, context)


async def _collect(stream):
    """Collect all items from an async generator."""
    items = []
    async for item in stream:
        items.append(item)
    return items


async def _make_stream(items):
    """Create an async generator from a list."""
    for item in items:
        yield item


# ------------------------------------------------------------------ #
#  Tests: class attributes
# ------------------------------------------------------------------ #


class TestOpenResponsesMiddlewareAttributes:
    def test_verifiable_types_is_frozenset(self):
        assert isinstance(OpenResponsesMiddleware.VERIFIABLE_ITEM_TYPES, frozenset)

    def test_verifiable_types_contents(self):
        assert "tool_call" in OpenResponsesMiddleware.VERIFIABLE_ITEM_TYPES
        assert "function_call" in OpenResponsesMiddleware.VERIFIABLE_ITEM_TYPES


# ------------------------------------------------------------------ #
#  Tests: passthrough (non-tool items)
# ------------------------------------------------------------------ #


class TestPassthrough:
    def test_text_items_pass_through(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {"type": "text", "content": "Hello"},
            {"type": "metadata", "model": "gpt-4"},
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert result == items

    def test_empty_stream(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        result = asyncio.run(_collect(mw.verify_stream(_make_stream([]))))
        assert result == []


# ------------------------------------------------------------------ #
#  Tests: verified tool calls
# ------------------------------------------------------------------ #


class TestVerifiedToolCalls:
    def test_guard_and_consumer_receive_the_original_item(self):
        guard = CaptureGuard()
        mw = OpenResponsesMiddleware(guards=[guard])
        item = {
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"query": "weather"},
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert guard.responses == [item]
        assert guard.responses[0] is item
        assert result == [item]
        assert result[0] is item

    def test_real_tool_guard_blocks_unwrapped_dangerous_fields(self):
        mw = OpenResponsesMiddleware(guards=[ToolGuard()])
        item = {
            "type": "tool_call",
            "tool_name": "execute_shell",
            "arguments": {"cmd": "rm -rf /"},
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result[0]["type"] == "system_intervention"
        assert result[0]["tool_name"] == "execute_shell"
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 1}

    def test_nested_safe_call_cannot_mask_conflicting_root_call(self):
        mw = OpenResponsesMiddleware(guards=[ToolGuard()])
        item = {
            "type": "tool_call",
            "tool_name": "execute_shell",
            "arguments": {"cmd": "rm -rf /"},
            "tool_call": {"name": "search", "arguments": {}},
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result[0]["type"] == "system_intervention"
        assert result[0]["tool_name"] == "execute_shell"
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 1}

    def test_nested_safe_call_cannot_mask_sibling_function_call(self):
        mw = OpenResponsesMiddleware(guards=[ToolGuard()])
        item = {
            "type": "tool_call",
            "tool_call": {"name": "search", "arguments": {}},
            "function": {
                "name": "execute_shell",
                "arguments": {"cmd": "rm -rf /"},
            },
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result[0]["type"] == "system_intervention"
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 1}

    def test_nested_stream_call_shapes_remain_supported_by_tool_guard(self):
        guard = ToolGuard(
            allowed_tools=["search", "calculate"], use_default_blocklist=False
        )
        mw = OpenResponsesMiddleware(guards=[guard])
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "search", "arguments": {"query": "x"}},
            },
            {
                "type": "function_call",
                "function_call": {"name": "calculate", "arguments": {"x": 1}},
            },
        ]

        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))

        assert result[0] is items[0]
        assert result[1] is items[1]
        assert mw.get_stats() == {"total": 2, "verified": 2, "blocked": 0}

    def test_tool_type_case_and_whitespace_variants_are_verified(self):
        guard = ToolGuard(allowed_tools=["search"], use_default_blocklist=False)
        mw = OpenResponsesMiddleware(guards=[guard])
        items = [
            {"type": "Tool_Call", "tool_name": "search", "arguments": {}},
            {"type": "tool_call ", "tool_name": "search", "arguments": {}},
            {"type": "Function_Call", "name": "search", "arguments": {}},
            {"type": "function_call ", "name": "search", "arguments": {}},
        ]

        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))

        assert all(actual is expected for actual, expected in zip(result, items))
        assert mw.get_stats() == {"total": 4, "verified": 4, "blocked": 0}

    def test_unknown_tool_shaped_type_fails_closed(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        item = {
            "type": "tool_call_v2",
            "tool_name": "search",
            "arguments": {"query": "x"},
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result[0]["type"] == "system_intervention"
        assert "Unrecognized tool-call item type" in result[0]["reason"]
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 1}

    def test_unknown_nested_tool_envelopes_fail_closed(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {
                "type": "tool_call_v2",
                "tool_use": {
                    "name": "execute_shell",
                    "input": {"cmd": "rm -rf /"},
                },
            },
            {
                "type": "tool_call_v2",
                "tool_calls": [
                    {
                        "function": {
                            "name": "execute_shell",
                            "arguments": {"cmd": "rm -rf /"},
                        }
                    }
                ],
            },
        ]

        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))

        assert [item["type"] for item in result] == [
            "system_intervention",
            "system_intervention",
        ]
        assert mw.get_stats() == {"total": 2, "verified": 0, "blocked": 2}

    def test_benign_structured_output_and_metadata_pass_through(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {
                "type": "structured_output",
                "name": "person",
                "arguments": {"name": "Ada"},
            },
            {"type": "metadata", "tool_call": {"source": "sdk"}},
            {"type": "metadata", "function_call": {"status": "complete"}},
        ]

        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))

        assert all(actual is expected for actual, expected in zip(result, items))
        assert mw.get_stats() == {"total": 3, "verified": 0, "blocked": 0}

    def test_unknown_tool_block_result_is_bound_to_original_item(self):
        results = []
        item = {
            "type": "tool_call_v2",
            "tool_name": "execute_shell",
            "arguments": {"cmd": "rm -rf /"},
        }
        mw = OpenResponsesMiddleware(
            guards=[PassGuard()],
            on_blocked=lambda _item, result: results.append(result),
        )

        asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert len(results) == 1
        assert results[0].verify_binding(item)
        assert results[0].binding["guards"] == [
            "pass_guard",
            "OpenResponsesMiddleware",
        ]

    def test_nested_arguments_are_checked_by_argument_guard(self):
        mw = OpenResponsesMiddleware(
            guards=[ArgumentGuard(rules={"amount": {"type": "number", "max": 100}})]
        )
        item = {
            "type": "tool_call",
            "tool_call": {
                "name": "transfer_money",
                "arguments": {"amount": 101},
            },
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result[0]["type"] == "system_intervention"
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 1}

    def test_nested_arguments_are_passed_to_tax_guard(self):
        class CapturingTaxGuard(TaxGuard):
            def __init__(self):
                self.calls = []

            def verify_tool_call(self, tool_name, arguments):
                self.calls.append((tool_name, arguments))
                return self.pass_result()

        guard = CapturingTaxGuard()
        mw = OpenResponsesMiddleware(guards=[guard])
        item = {
            "type": "function_call",
            "function_call": {
                "name": "send_international_wire",
                "arguments": {"amount_usd": 50},
            },
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result == [item]
        assert guard.calls == [("send_international_wire", {"amount_usd": 50})]

    def test_direct_function_call_tool_name_is_passed_to_tax_guard(self):
        class CapturingTaxGuard(TaxGuard):
            def __init__(self):
                self.calls = []

            def verify_tool_call(self, tool_name, arguments):
                self.calls.append((tool_name, arguments))
                return self.pass_result()

        guard = CapturingTaxGuard()
        mw = OpenResponsesMiddleware(guards=[guard])
        item = {
            "type": "function_call",
            "tool_name": "process_payroll",
            "arguments": {"gross_ytd": 1000, "claimed_tax": 100},
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result == [item]
        assert guard.calls == [
            ("process_payroll", {"gross_ytd": 1000, "claimed_tax": 100})
        ]

    def test_invalid_function_call_name_does_not_fallback_to_tool_name(self):
        class CapturingTaxGuard(TaxGuard):
            def __init__(self):
                self.calls = []

            def verify_tool_call(self, tool_name, arguments):
                self.calls.append((tool_name, arguments))
                return self.pass_result()

        guard = CapturingTaxGuard()
        mw = OpenResponsesMiddleware(guards=[guard])
        item = {
            "type": "function_call",
            "name": " ",
            "tool_name": "process_payroll",
            "arguments": {"gross_ytd": 1000, "claimed_tax": 100},
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result[0]["type"] == "system_intervention"
        assert guard.calls == []
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 1}

    def test_tool_result_items_pass_through_without_verification(self):
        guard = CaptureGuard()
        mw = OpenResponsesMiddleware(guards=[guard])
        item = {
            "type": "tool_result",
            "id": "result_1",
            "tool_use_id": "process_payroll",
            "content": {"mime_type": "application/json", "text": "{}"},
            "is_error": False,
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result == [item]
        assert result[0] is item
        assert guard.responses == []
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 0}

    def test_tool_result_correlation_fields_pass_through_without_verification(self):
        guard = CaptureGuard()
        mw = OpenResponsesMiddleware(guards=[guard])
        item = {
            "type": "tool_result",
            "tool_name": "process_payroll",
            "arguments": {"gross_ytd": 1000, "claimed_tax": 100},
            "tool_use_id": "call_1",
            "content": {"status": "ok"},
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result == [item]
        assert result[0] is item
        assert guard.responses == []
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 0}

    def test_tool_result_nested_tool_use_is_blocked(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        item = {
            "type": "tool_result",
            "tool_use": {
                "name": "execute_shell",
                "input": {"cmd": "rm -rf /"},
            },
        }

        result = asyncio.run(_collect(mw.verify_stream(_make_stream([item]))))

        assert result[0]["type"] == "system_intervention"
        assert mw.get_stats() == {"total": 1, "verified": 0, "blocked": 1}

    def test_tool_call_passes_with_pass_guard(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "get_weather", "arguments": {"city": "NYC"}},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1
        assert result[0]["type"] == "tool_call"

    def test_function_call_passes(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {
                "type": "function_call",
                "function_call": {"name": "calc", "arguments": {"x": 1}},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1

    def test_stats_after_verified(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "safe_tool", "arguments": {}},
            }
        ]
        asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        stats = mw.get_stats()
        assert stats["total"] == 1
        assert stats["verified"] == 1
        assert stats["blocked"] == 0


# ------------------------------------------------------------------ #
#  Tests: blocked tool calls
# ------------------------------------------------------------------ #


class TestBlockedToolCalls:
    def test_blocked_returns_system_intervention(self):
        mw = OpenResponsesMiddleware(guards=[FailGuard()], block_on_failure=True)
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "rm_rf", "arguments": {}},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1
        assert result[0]["type"] == "system_intervention"
        assert result[0]["status"] == "blocked"
        assert result[0]["tool_name"] == "rm_rf"
        assert "QWED blocked" in result[0]["reason"]
        assert "guards_passed" in result[0]["verification"]
        assert "guards_failed" in result[0]["verification"]

    def test_non_blocking_passes_through(self):
        mw = OpenResponsesMiddleware(guards=[FailGuard()], block_on_failure=False)
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "dangerous", "arguments": {}},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        # Non-blocking mode passes item through
        assert len(result) == 1
        assert result[0]["type"] == "tool_call"

    def test_stats_after_blocked(self):
        mw = OpenResponsesMiddleware(guards=[FailGuard()])
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "bad", "arguments": {}},
            }
        ]
        asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        stats = mw.get_stats()
        assert stats["total"] == 1
        assert stats["verified"] == 0
        assert stats["blocked"] == 1


# ------------------------------------------------------------------ #
#  Tests: on_blocked callback
# ------------------------------------------------------------------ #


class TestOnBlockedCallback:
    def test_callback_invoked(self):
        blocked_items = []

        def on_blocked(item, _result):
            blocked_items.append(item)

        mw = OpenResponsesMiddleware(
            guards=[FailGuard()], block_on_failure=True, on_blocked=on_blocked
        )
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "evil", "arguments": {}},
            }
        ]
        asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(blocked_items) == 1

    def test_callback_exception_doesnt_crash(self):
        def bad_callback(_item, _result):
            raise ValueError()

        mw = OpenResponsesMiddleware(
            guards=[FailGuard()], block_on_failure=True, on_blocked=bad_callback
        )
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "test", "arguments": {}},
            }
        ]
        # Should not raise
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1
        assert result[0]["type"] == "system_intervention"


# ------------------------------------------------------------------ #
#  Tests: edge cases
# ------------------------------------------------------------------ #


class TestEdgeCases:
    def test_empty_tool_call_dict(self):
        """Empty dict is valid — should not fall through to function_call."""
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {
                "type": "tool_call",
                "tool_call": {},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1

    def test_missing_tool_call_key(self):
        """If tool_call is None, falls back to function_call."""
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [{"type": "tool_call"}]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1

    def test_none_block_reason_fallback(self):
        """When block_reason is None, should use fallback string."""
        mw = OpenResponsesMiddleware(guards=[ExplodingGuard()], block_on_failure=True)
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "test", "arguments": {}},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1
        assert "None" not in result[0]["reason"]

    def test_reset_stats(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "a", "arguments": {}},
            }
        ]
        asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert mw.get_stats()["total"] == 1
        mw.reset_stats()
        assert mw.get_stats()["total"] == 0

    def test_mixed_stream(self):
        mw = OpenResponsesMiddleware(guards=[PassGuard()])
        items = [
            {"type": "text", "content": "Hello"},
            {
                "type": "tool_call",
                "tool_call": {"name": "safe", "arguments": {}},
            },
            {"type": "text", "content": "Goodbye"},
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 3
        stats = mw.get_stats()
        assert stats["total"] == 3
        assert stats["verified"] == 1

    def test_no_guards_fails_closed(self):
        """(#27) Zero guards must block, not pass."""
        mw = OpenResponsesMiddleware(guards=[])
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "anything", "arguments": {}},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1
        assert result[0]["type"] == "system_intervention"


# ------------------------------------------------------------------ #
#  Tests: lazy import (__init__.py)
# ------------------------------------------------------------------ #


class TestLazyImport:
    def test_import_open_responses_middleware(self):
        from qwed_open_responses.middleware import OpenResponsesMiddleware as MW

        assert MW is OpenResponsesMiddleware

    def test_import_unknown_raises(self):
        import pytest
        import qwed_open_responses.middleware as middleware

        with pytest.raises(AttributeError):
            _ = middleware.DoesNotExist
