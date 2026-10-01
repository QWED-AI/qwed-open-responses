"""
Open Responses Streaming Interceptor for QWED.

Intercepts and verifies streaming events defined by the Open Responses
specification, which uses "items" as the atomic unit of model output
and tool use.

Source: Open Responses interoperable LLM interface.
"""

import logging
from typing import Any, AsyncGenerator, Callable, Dict, Iterable, List, Optional, Tuple

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
        context: Optional[Dict[str, Any]] = None,
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
                verified_item = self._verify_tool_call(item, context=context)
                if verified_item is not None:
                    yield verified_item
            elif self._is_tool_shaped_item(item):
                blocked_item = self._block_unrecognized_tool_item(item, context=context)
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
        """Identify tool calls with a bounded main and overflow scan."""
        root_type = ToolGuard._normalized_type(item.get("type", ""))
        passthrough_on_scan_limit = {
            "text",
            "message",
            "structured_output",
            "tool_result",
            "function_call_output",
        }
        result_item_types = {"tool_result", "function_call_output"}
        stack = [item]
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
        priority_key_order = (
            "tool_name",
            "tool_call",
            "function_call",
            "function",
            "tool_use",
            "tool_calls",
            "content",
            "choices",
        )
        tool_type_prefixes = ("tool_call", "function_call", "tool_use")
        # Keep one explicit, shared overflow budget instead of multiplying a
        # per-entry recursive hint scan across large collections.
        overflow_scan_limit = ToolGuard._MAX_ARGS_SCAN_NODES * 4

        while stack:
            if scanned_nodes >= ToolGuard._MAX_ARGS_SCAN_NODES:
                return (
                    OpenResponsesMiddleware._scan_tool_hint_values(
                        reversed(stack), overflow_scan_limit
                    )
                    is not False
                    or root_type not in passthrough_on_scan_limit
                )
            node = stack.pop()
            scanned_nodes += 1

            if isinstance(node, (dict, list)):
                node_id = id(node)
                if node_id in seen:
                    continue
                seen.add(node_id)

            if isinstance(node, dict):
                normalized_type = ToolGuard._normalized_type(node.get("type", ""))
                is_tool_type = normalized_type not in passthrough_on_scan_limit and (
                    normalized_type.startswith(tool_type_prefixes)
                    or (
                        "tool" in normalized_type
                        and ToolGuard._is_tool_shaped_dict(node)
                    )
                )
                if is_tool_type:
                    return bool(ToolGuard.normalize_tool_calls(node)) or bool(
                        OpenResponsesMiddleware._has_tool_hint(node)
                    )
                node_envelope_keys = envelope_keys
                if node is item and root_type in result_item_types:
                    # Root correlation fields are not a new invocation, but a
                    # function wrapper is exempt only after its call is
                    # normalized and matched to the correlated root metadata.
                    node_envelope_keys = envelope_keys - {"tool_name"}
                    if OpenResponsesMiddleware._is_result_function_metadata(item):
                        node_envelope_keys = node_envelope_keys - {"function"}
                if node_envelope_keys.intersection(node):
                    return bool(ToolGuard.normalize_tool_calls(node)) or bool(
                        OpenResponsesMiddleware._has_tool_hint(node)
                    )
                if (
                    scanned_nodes + len(stack) + len(node)
                    > ToolGuard._MAX_ARGS_SCAN_NODES
                ):

                    def ordered_children() -> Iterable[Any]:
                        for key in priority_key_order:
                            if key in node:
                                yield node[key]
                        for key, child in node.items():
                            if key not in priority_keys:
                                yield child

                    return (
                        OpenResponsesMiddleware._scan_tool_hint_values(
                            ordered_children(), overflow_scan_limit
                        )
                        is not False
                        or root_type not in passthrough_on_scan_limit
                    )

                ordinary_children: List[Any] = []
                priority_children: List[Any] = []
                for key, child in node.items():
                    target = (
                        priority_children if key in priority_keys else ordinary_children
                    )
                    target.append(child)
                children = ordinary_children + priority_children
            elif isinstance(node, list):
                if (
                    scanned_nodes + len(stack) + len(node)
                    > ToolGuard._MAX_ARGS_SCAN_NODES
                ):
                    return (
                        OpenResponsesMiddleware._scan_tool_hint_values(
                            node, overflow_scan_limit
                        )
                        is not False
                        or root_type not in passthrough_on_scan_limit
                    )
                children = node
            else:
                continue

            stack.extend(children)

        return False

    @staticmethod
    def _has_tool_hint(value: Any) -> bool:
        """Detect a bounded nested marker that can describe a call."""
        hint, _ = OpenResponsesMiddleware._scan_tool_hint(value, 128)
        return hint is not False

    @staticmethod
    def _scan_tool_hint_values(values: Iterable[Any], max_nodes: int) -> Optional[bool]:
        """Scan values for explicit tool markers within one shared budget."""
        scanned_nodes = 0
        for value in values:
            remaining = max_nodes - scanned_nodes
            if remaining <= 0:
                return None
            hint, child_nodes = OpenResponsesMiddleware._scan_tool_hint(
                value, remaining, allow_bare_name_arguments=False
            )
            scanned_nodes += child_nodes
            if hint is not False:
                return True
        return False

    @staticmethod
    def _is_result_function_metadata(item: Dict[str, Any]) -> bool:
        """Recognize a normalized function echo tied to a completed result."""
        result_type = ToolGuard._normalized_type(item.get("type", ""))
        if result_type not in {"tool_result", "function_call_output"}:
            return False

        correlation_ids = (item.get("tool_use_id"), item.get("call_id"))
        if not any(
            isinstance(value, str) and value.strip() for value in correlation_ids
        ):
            return False

        function = item.get("function")
        tool_name = item.get("tool_name")
        if (
            not isinstance(function, dict)
            or not isinstance(tool_name, str)
            or not tool_name.strip()
            or "name" not in function
            or "arguments" not in function
        ):
            return False

        nested_call_keys = {
            "tool_name",
            "tool_call",
            "tool_calls",
            "function_call",
            "function",
            "tool_use",
        }
        if nested_call_keys.intersection(function):
            return False
        function_type = ToolGuard._normalized_type(function.get("type", ""))
        if function_type.startswith(("tool_call", "function_call", "tool_use")) or (
            "tool" in function_type
        ):
            return False

        root_arguments = item.get("arguments")
        function_name = function.get("name")
        function_arguments = function.get("arguments")
        if (
            not isinstance(root_arguments, dict)
            or not isinstance(function_name, str)
            or not function_name.strip()
            or not isinstance(function_arguments, dict)
        ):
            return False

        if any(
            depth < 0 or depth > ToolGuard._MAX_ARGS_JSON_DEPTH
            for depth in (
                ToolGuard._arguments_depth(root_arguments),
                ToolGuard._arguments_depth(function_arguments),
            )
        ):
            return False

        normalized_calls = ToolGuard.normalize_tool_calls(
            {"type": "function_call", "function": function}
        )
        if len(normalized_calls) != 1:
            return False
        normalized_call = normalized_calls[0]
        normalized_name = normalized_call.get("tool_name")
        return (
            normalized_call.get("type") == "tool_call"
            and isinstance(normalized_name, str)
            and normalized_name.casefold() == tool_name.casefold()
            and normalized_call.get("arguments") == root_arguments
            and function_arguments == root_arguments
        )

    @staticmethod
    def _scan_tool_hint(
        value: Any,
        max_nodes: int,
        allow_bare_name_arguments: bool = True,
    ) -> Tuple[Optional[bool], int]:
        """Scan a subtree within a caller-shared node budget."""
        stack = [(value, 0)]
        seen: set[int] = set()
        scanned_nodes = 0
        while stack:
            if scanned_nodes >= max_nodes:
                return None, scanned_nodes
            node, depth = stack.pop()
            scanned_nodes += 1
            if isinstance(node, (dict, list)):
                node_id = id(node)
                if node_id in seen:
                    continue
                seen.add(node_id)

            if isinstance(node, dict):
                node_type = ToolGuard._normalized_type(node.get("type", ""))
                is_result = node_type in {"tool_result", "function_call_output"}
                if allow_bare_name_arguments:
                    is_tool_shaped = ToolGuard._is_tool_shaped_dict(node)
                else:
                    is_tool_shaped = (
                        node_type.startswith(("tool_call", "function_call", "tool_use"))
                        or ("tool" in node_type and not is_result)
                        or any(
                            key in node
                            for key in (
                                "tool_name",
                                "tool_call",
                                "function_call",
                                "function",
                                "tool_use",
                                "tool_calls",
                            )
                        )
                    )
                if not is_result and is_tool_shaped:
                    return True, scanned_nodes
                if depth < ToolGuard._MAX_NESTED_SCAN_DEPTH:
                    if scanned_nodes + len(stack) + len(node) > max_nodes:
                        return None, scanned_nodes
                    stack.extend((child, depth + 1) for child in node.values())
                elif node:
                    return None, scanned_nodes
            elif isinstance(node, list) and depth < ToolGuard._MAX_NESTED_SCAN_DEPTH:
                if scanned_nodes + len(stack) + len(node) > max_nodes:
                    return None, scanned_nodes
                stack.extend((child, depth + 1) for child in node)
            elif isinstance(node, list) and node:
                return None, scanned_nodes
        return False, scanned_nodes

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
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Run a single tool-call item through the guard stack.

        Returns the original item if verified, a ``system_intervention``
        item if blocked (when ``block_on_failure`` is True), or the
        original item unmodified (when ``block_on_failure`` is False).
        """
        tool_name = self._tool_name(item)
        result: VerificationResult = self._verifier.verify(item, context=context)
        return self._handle_tool_call_result(item, tool_name, result)

    def _block_unrecognized_tool_item(
        self,
        item: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fail closed when a tool-shaped item declares an unknown type."""
        reason = f"Unrecognized tool-call item type: {item.get('type')!r}"
        result = self._verifier.verify(
            item,
            guards=[
                *self._verifier.default_guards,
                _UnrecognizedToolItemGuard(reason),
            ],
            context=context,
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
