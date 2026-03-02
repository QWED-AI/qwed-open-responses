"""
Open Responses Streaming Interceptor for QWED.

Intercepts and verifies streaming events defined by the Open Responses
specification, which uses "items" as the atomic unit of model output
and tool use.

Source: Open Responses interoperable LLM interface.
"""

import logging
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional

from ..core import ResponseVerifier, VerificationResult
from ..guards.base import BaseGuard

logger = logging.getLogger(__name__)


class OpenResponsesMiddleware:
    """
    Intercepts and verifies streaming events from the Open Responses protocol.

    The Open Responses spec defines a shared schema for agentic loops
    and tool invocations. This middleware monitors the stream for
    'tool_call' items and runs them through QWED guards before they
    are yielded to the consumer.

    Usage::

        from qwed_open_responses.middleware.streaming_interceptor import (
            OpenResponsesMiddleware,
        )
        from qwed_open_responses import ToolGuard

        mw = OpenResponsesMiddleware(guards=[ToolGuard()])

        async for item in mw.verify_stream(response_stream):
            process(item)
    """

    # Tool types that require verification before yielding
    VERIFIABLE_ITEM_TYPES: frozenset = frozenset({"tool_call", "function_call"})

    def __init__(
        self,
        guards: Optional[List[BaseGuard]] = None,
        block_on_failure: bool = True,
        on_blocked: Optional[
            Callable[[Dict[str, Any], VerificationResult], None]
        ] = None,
    ):
        """
        Initialise the streaming interceptor.

        Args:
            guards: Guards to apply when a tool-call item arrives.
            block_on_failure: If True, dangerous items are replaced with
                a ``system_intervention`` item instead of being yielded.
                If False, failed items pass through unmodified (warn-only).
            on_blocked: Optional callback invoked when an item is blocked.
        """
        self._verifier = ResponseVerifier(default_guards=guards or [])
        self._block_on_failure = block_on_failure
        self._on_blocked = on_blocked
        self._stats: Dict[str, int] = {"total": 0, "verified": 0, "blocked": 0}

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    async def verify_stream(
        self,
        response_stream: AsyncGenerator[Dict[str, Any], None],
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Monitor the stream for tool-call items, verifying each before yield.

        Items whose ``type`` is not in :pyattr:`VERIFIABLE_ITEM_TYPES` are
        passed through unchanged.

        Yields:
            Verified (or replaced) items from the stream.
        """
        async for item in response_stream:
            self._stats["total"] += 1

            if item.get("type") in self.VERIFIABLE_ITEM_TYPES:
                verified_item = self._verify_tool_call(item)
                if verified_item is not None:
                    yield verified_item
            else:
                # Non-tool items (text, metadata, etc.) pass through
                yield item

    def get_stats(self) -> Dict[str, int]:
        """Return running totals of items processed."""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset running totals."""
        self._stats = {"total": 0, "verified": 0, "blocked": 0}

    # ------------------------------------------------------------------ #
    #  Internals                                                           #
    # ------------------------------------------------------------------ #

    def _verify_tool_call(
        self,
        item: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Run a single tool-call item through the guard stack.

        Returns the original item if verified, a ``system_intervention``
        item if blocked (when ``block_on_failure`` is True), or the
        original item unmodified (when ``block_on_failure`` is False).
        """
        # Use explicit None check — empty dicts are valid tool calls
        tool_call = item.get("tool_call")
        if tool_call is None:
            tool_call = item.get("function_call", {})

        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("arguments", {})

        # Build a verification payload — use "arguments" key for guard compat
        payload: Dict[str, Any] = {
            "type": "tool_call",
            "tool_name": tool_name,
            "arguments": tool_args,
            "raw_item": item,
        }

        result: VerificationResult = self._verifier.verify(payload)

        if result.verified:
            self._stats["verified"] += 1
            logger.debug("✅ Verified tool call: %s", tool_name)
            return item

        # Blocked
        self._stats["blocked"] += 1
        block_reason = result.block_reason or "verification failed"
        logger.warning(
            "🛡️ Blocked tool call: %s — reason: %s",
            tool_name,
            block_reason,
        )

        if self._on_blocked:
            try:
                self._on_blocked(item, result)
            except Exception:
                logger.exception(
                    "on_blocked callback failed for tool call '%s'",
                    tool_name,
                )

        if self._block_on_failure:
            return {
                "type": "system_intervention",
                "status": "blocked",
                "tool_name": tool_name,
                "reason": f"QWED blocked {tool_name}: {block_reason}",
                "verification": {
                    "guards_passed": result.guards_passed,
                    "guards_failed": result.guards_failed,
                    "mechanism": "QWED Open Responses Streaming Interceptor",
                },
            }

        # Non-blocking mode: pass through unmodified (warn-only)
        return item
