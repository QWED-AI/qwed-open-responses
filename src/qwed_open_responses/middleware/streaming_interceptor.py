"""
Open Responses Streaming Interceptor for QWED.

Intercepts and verifies streaming events defined by the Open Responses
specification, which uses "items" as the atomic unit of model output
and tool use.

Source: Open Responses interoperable LLM interface.
"""

import logging
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Tuple

from ..core import ResponseVerifier, VerificationResult
from ..guards.base import BaseGuard, GuardResult
from ..guards.tool_guard import ToolGuard

logger = logging.getLogger(__name__)


class _UnrecognizedToolItemGuard(BaseGuard):
    name = "OpenResponsesMiddleware"
    description = "Rejects tool calls with unsupported item types"

    def __init__(self, reason: str):
        self._reason = reason

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        return self.fail_result(self._reason)


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
    VERIFIABLE_ITEM_TYPES: frozenset[str] = frozenset({"tool_call", "function_call"})

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
                **This disables the trust boundary** (issue #31): nothing
                is actually stopped — use only for monitoring/observation,
                never in paths that depend on verification.
            on_blocked: Optional callback invoked when an item is blocked.
        """
        self._verifier = ResponseVerifier(default_guards=guards or [])
        self._block_on_failure = block_on_failure
        if not block_on_failure:
            # #31: warn-only mode is an explicit opt-out of interception —
            # surface it loudly so it cannot be enabled by accident.
            logger.warning(
                "OpenResponsesMiddleware: block_on_failure=False disables "
                "the trust boundary — failed tool-call items will pass "
                "through unmodified. Use only for monitoring/observation."
            )
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

        Non-tool items are passed through unchanged. Tool-like items with an
        unsupported type are blocked rather than treated as verified output.

        Yields:
            Verified (or replaced) items from the stream.
        """
        async for item in response_stream:
            self._stats["total"] += 1

            item_type = item.get("type")
            normalized_type = (
                item_type.strip().casefold() if isinstance(item_type, str) else ""
            )

            if normalized_type in self.VERIFIABLE_ITEM_TYPES:
                verified_item = self._verify_tool_call(item)
                if verified_item is not None:
                    yield verified_item
            elif self._is_tool_shaped_item(item):
                blocked_item = self._block_unrecognized_tool_item(item)
                if blocked_item is not None:
                    yield blocked_item
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

    @staticmethod
    def _is_tool_shaped_item(item: Dict[str, Any]) -> bool:
        """Identify tool calls using an explicit type or envelope marker."""
        root_type = ToolGuard._normalized_type(item.get("type", ""))
        passthrough_on_scan_limit = {
            "text",
            "message",
            "structured_output",
            "tool_result",
            "function_call_output",
        }
        # Keep tool-bearing branches ahead of ordinary payload branches. This
        # lets a bounded scan inspect a declared ``content`` envelope before a
        # large benign payload sibling consumes the budget.
        stack = [(item, False)]
        seen: set[int] = set()
        scanned_nodes = 0
        envelope_keys = {
            "tool_name",
            "tool_call",
            "function_call",
            "function",
            "tool_use",
            "tool_calls",
        }
        priority_keys = envelope_keys | {"content", "choices"}
        sensitive_keys = envelope_keys | {"content"}
        tool_type_prefixes = ("tool_call", "function_call", "tool_use")

        while stack:
            node, sensitive_path = stack.pop()
            scanned_nodes += 1
            if scanned_nodes > ToolGuard._MAX_ARGS_SCAN_NODES:
                # An oversized ordinary payload is still valid declared
                # output, but an oversized executable branch cannot be
                # inspected safely. Unknown item types remain fail-closed.
                return sensitive_path or root_type not in passthrough_on_scan_limit

            if isinstance(node, (dict, list)):
                node_id = id(node)
                if node_id in seen:
                    continue
                seen.add(node_id)

            if isinstance(node, dict):
                normalized_type = ToolGuard._normalized_type(node.get("type", ""))
                is_tool_type = normalized_type.startswith(tool_type_prefixes) or (
                    "tool" in normalized_type
                    and normalized_type not in passthrough_on_scan_limit
                )
                if is_tool_type:
                    return bool(ToolGuard.normalize_tool_calls(item)) or bool(
                        OpenResponsesMiddleware._has_tool_hint(node)
                    )
                if envelope_keys.intersection(node):
                    return bool(ToolGuard.normalize_tool_calls(node)) or bool(
                        OpenResponsesMiddleware._has_tool_hint(node)
                    )
                choices_hint = OpenResponsesMiddleware._has_choices_tool_calls(
                    node.get("choices")
                )
                if choices_hint is None:
                    return True
                if choices_hint:
                    return bool(ToolGuard.normalize_tool_calls(node)) or bool(
                        OpenResponsesMiddleware._has_tool_hint(node)
                    )

                ordinary_children: List[Tuple[Any, bool]] = []
                priority_children: List[Tuple[Any, bool]] = []
                for key, child in node.items():
                    if key == "choices" and choices_hint is False:
                        continue
                    target = (
                        priority_children if key in priority_keys else ordinary_children
                    )
                    target.append(
                        (
                            child,
                            sensitive_path or key in sensitive_keys,
                        )
                    )
                children = ordinary_children + priority_children
                child_count = len(children)
            elif isinstance(node, list):
                if sensitive_path and (
                    scanned_nodes + len(stack) + len(node)
                    > ToolGuard._MAX_ARGS_SCAN_NODES
                ):
                    # Content/tool collections can be large. Inspect direct
                    # entries for executable markers with a separate finite
                    # budget so a tool block at the end is not hidden by the
                    # ordinary node budget, while an unbounded collection
                    # still fails closed when it cannot be inspected.
                    priority_scan_limit = ToolGuard._MAX_ARGS_SCAN_NODES * 2
                    for index, child in enumerate(node):
                        if OpenResponsesMiddleware._has_tool_hint(child):
                            return True
                        if index + 1 >= priority_scan_limit:
                            return True
                    return False
                ordinary_list_children: List[Tuple[Any, bool]] = []
                priority_list_children: List[Tuple[Any, bool]] = []
                for child in node:
                    target = (
                        priority_list_children
                        if OpenResponsesMiddleware._has_tool_hint(child)
                        else ordinary_list_children
                    )
                    target.append((child, sensitive_path))
                children = ordinary_list_children + priority_list_children
                child_count = len(node)
            else:
                continue

            if (
                scanned_nodes + len(stack) + child_count
                > ToolGuard._MAX_ARGS_SCAN_NODES
            ):
                return sensitive_path or root_type not in passthrough_on_scan_limit
            stack.extend(children)

        return False

    @staticmethod
    def _has_choices_tool_calls(choices: Any) -> Optional[bool]:
        """Return whether ``choices`` contains an executable tool envelope."""
        if not isinstance(choices, list):
            return False
        scan_limit = ToolGuard._MAX_ARGS_SCAN_NODES * 2
        for index, choice in enumerate(choices):
            if (
                isinstance(choice, dict)
                and isinstance(choice.get("message"), dict)
                and "tool_calls" in choice["message"]
            ):
                return True
            if index + 1 >= scan_limit:
                return None
        return False

    @staticmethod
    def _has_tool_hint(value: Any) -> bool:
        """Prioritize bounded nested containers that can describe a call."""
        stack = [(value, 0)]
        seen: set[int] = set()
        scanned_nodes = 0
        while stack:
            node, depth = stack.pop()
            scanned_nodes += 1
            if scanned_nodes > 128:
                return True
            if isinstance(node, (dict, list)):
                node_id = id(node)
                if node_id in seen:
                    continue
                seen.add(node_id)

            if isinstance(node, dict):
                node_type = ToolGuard._normalized_type(node.get("type", ""))
                is_result = node_type in {"tool_result", "function_call_output"}
                if not is_result and ToolGuard._is_tool_shaped_dict(node):
                    return True
                if depth < ToolGuard._MAX_NESTED_SCAN_DEPTH:
                    stack.extend((child, depth + 1) for child in node.values())
            elif isinstance(node, list) and depth < ToolGuard._MAX_NESTED_SCAN_DEPTH:
                stack.extend((child, depth + 1) for child in node)
        return False

    @staticmethod
    def _tool_name(item: Dict[str, Any]) -> str:
        name = item.get("tool_name") or item.get("name")
        tool_call = item.get("tool_call")
        if tool_call is None:
            tool_call = item.get("function_call")
        if not isinstance(name, str) or not name.strip():
            name = tool_call.get("name") if isinstance(tool_call, dict) else None
        return name if isinstance(name, str) and name.strip() else "unknown"

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
        tool_name = self._tool_name(item)
        result: VerificationResult = self._verifier.verify(item)
        return self._handle_tool_call_result(item, tool_name, result)

    def _block_unrecognized_tool_item(
        self,
        item: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Fail closed when a tool-shaped item declares an unknown type."""
        reason = f"Unrecognized tool-call item type: {item.get('type')!r}"
        result = self._verifier.verify(
            item,
            guards=[
                *self._verifier.default_guards,
                _UnrecognizedToolItemGuard(reason),
            ],
        )
        return self._handle_tool_call_result(item, self._tool_name(item), result)

    def _handle_tool_call_result(
        self,
        item: Dict[str, Any],
        tool_name: str,
        result: VerificationResult,
    ) -> Optional[Dict[str, Any]]:
        """Update middleware state and apply its configured block behavior."""

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

        # Non-blocking mode: pass through unmodified (warn-only).
        # #31: this deliberately disables the trust boundary — the failed
        # item reaches the consumer exactly as the model produced it. The
        # blocked-mode system_intervention replacement only protects a
        # consumer that honors it; document both sides of that contract.
        return item
