"""Tests for OpenResponsesMiddleware — Streaming Interceptor."""

import asyncio

from qwed_open_responses.core import GuardResult, VerificationResult
from qwed_open_responses.guards.base import BaseGuard
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

    def check(self, response, context=None):
        return GuardResult(guard_name=self.name, passed=True, message="OK")


class FailGuard(BaseGuard):
    """Guard that always fails."""

    name = "fail_guard"
    description = "Always fails"

    def check(self, response, context=None):
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

    def check(self, response, context=None):
        raise RuntimeError("kaboom")


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

        def on_blocked(item, result):
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
        def bad_callback(item, result):
            raise ValueError("callback error!")

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

    def test_no_guards_passes_all(self):
        mw = OpenResponsesMiddleware(guards=[])
        items = [
            {
                "type": "tool_call",
                "tool_call": {"name": "anything", "arguments": {}},
            }
        ]
        result = asyncio.run(_collect(mw.verify_stream(_make_stream(items))))
        assert len(result) == 1
        assert result[0]["type"] == "tool_call"


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
