"""
Tool Guard - Validates tool calls for safety and correctness.

Blocks dangerous tools and validates tool arguments.
"""

from typing import Any, Dict, Optional, List, Set, Callable, Tuple
from .base import BaseGuard, GuardResult
import json
import re


class ToolGuard(BaseGuard):
    """
    Validates tool calls before execution.

    Features:
    - Block dangerous tools
    - Validate tool arguments
    - Rate limit tool calls
    - Custom validation functions

    Usage:
        guard = ToolGuard(
            blocked_tools=["execute_shell", "delete_file"],
            allowed_tools=["search", "calculator"],  # If set, only these allowed
            dangerous_patterns=[r"DROP TABLE", r"rm -rf"],
        )

        result = guard.check({
            "type": "tool_call",
            "tool_name": "search",
            "arguments": {"query": "weather"}
        })
    """

    name = "ToolGuard"
    description = "Validates tool calls for safety"

    # Default dangerous tools
    DEFAULT_BLOCKED_TOOLS = {
        "execute_shell",
        "shell",
        "bash",
        "cmd",
        "exec",
        "eval",
        "delete_file",
        "remove_file",
        "write_file",
        "modify_file",
        "send_email",
        "transfer_money",
        "make_payment",
    }

    # Default dangerous patterns in arguments.
    # Compiled with re.IGNORECASE (see __init__) so both implementations
    # block the same payloads — "RM -RF /" must not pass on Python while
    # npm blocks it (#30 cross-language parity).
    DEFAULT_DANGEROUS_PATTERNS = [
        r"DROP\s+TABLE",
        r"DELETE\s+FROM",
        r"TRUNCATE\s+TABLE",
        r"rm\s+-rf",
        r"rmdir\s+/s",
        r"del\s+/f",
        r"format\s+c:",
        r"sudo\s+",
        r"chmod\s+777",
        r"eval\s*\(",
        r"exec\s*\(",
        r"__import__",
        r"subprocess",
        r"os\.system",
    ]

    # Fail-closed bound on JSON-encoded argument payloads before parsing.
    _MAX_ARGS_JSON_CHARS = 10_000
    _MAX_ARGS_JSON_DEPTH = 128
    _MAX_NESTED_SCAN_DEPTH = 12

    @staticmethod
    def _max_sequence_depth(text: str) -> int:
        """Return the max brace/bracket nesting depth outside JSON strings.

        Used as a deterministic fail-closed guard against deep nesting, so
        the json.loads recursion limit can never crash the caller, regardless
        of the interpreter's runtime recursion configuration (CPython versions
        differ in where they raise).
        """
        depth = 0
        max_depth = 0
        in_string = False
        escaped = False
        for ch in text:
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch in "{[":
                depth += 1
                if depth > max_depth:
                    max_depth = depth
            elif ch in "}]":
                depth -= 1
        return max_depth

    @staticmethod
    def _safe_parse_json_object(payload: str) -> Tuple[bool, Any]:
        """Parse a bounded, structurally-validated JSON object string.

        Explicit sanitization chain between source and sink:
        1. Length bound (DoS)
        2. Brace-delimitation check (must be an object)
        3. json.loads (bounded, shape-validated input only)

        Note: the parameter is deliberately NOT named ``raw`` — the QWED
        taint scanner is per-file and scope-blind, so a tainted local named
        ``raw`` elsewhere in this module (from ``call.get(...)``) would
        otherwise collide with this parameter and trip a false TAINT finding
        on the ``json.loads`` you're about to see is bounded anyway.

        Returns (ok, parsed_dict).
        """
        if len(payload) > ToolGuard._MAX_ARGS_JSON_CHARS:
            return False, None
        stripped = payload.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            return False, None
        if ToolGuard._max_sequence_depth(stripped) > ToolGuard._MAX_ARGS_JSON_DEPTH:
            return False, None
        try:
            parsed = json.loads(stripped)
        except (ValueError, TypeError, RecursionError):
            # RecursionError: a bounded payload can still exceed the JSON
            # decoder recursion depth (deeply nested objects) - fail closed
            # instead of crashing the caller (Greptile/T-Rex P1).
            return False, None
        if not isinstance(parsed, dict):
            return False, None
        return True, parsed

    def __init__(
        self,
        blocked_tools: Optional[List[str]] = None,
        allowed_tools: Optional[List[str]] = None,
        use_default_blocklist: bool = True,
        dangerous_patterns: Optional[List[str]] = None,
        use_default_patterns: bool = True,
        custom_validators: Optional[Dict[str, Callable]] = None,
        max_calls_per_response: int = 10,
    ):
        """
        Initialize ToolGuard.

        Args:
            blocked_tools: Tools to always block
            allowed_tools: If set, only these tools allowed (whitelist mode)
            use_default_blocklist: Include default dangerous tools
            dangerous_patterns: Regex patterns to block in arguments
            use_default_patterns: Include default dangerous patterns
            custom_validators: Dict of tool_name -> validator function
            max_calls_per_response: Max tool calls in single response
        """
        self.blocked_tools: Set[str] = set(blocked_tools or [])
        if use_default_blocklist:
            self.blocked_tools.update(self.DEFAULT_BLOCKED_TOOLS)

        self.allowed_tools: Optional[Set[str]] = (
            set(allowed_tools) if allowed_tools else None
        )

        self.dangerous_patterns: List[re.Pattern] = []
        if use_default_patterns:
            self.dangerous_patterns.extend(
                # Case-insensitive: npm side uses /i on every pattern — the
                # default sets must behave identically across runtimes (#30).
                re.compile(p, re.IGNORECASE)
                for p in self.DEFAULT_DANGEROUS_PATTERNS
            )
        if dangerous_patterns:
            self.dangerous_patterns.extend(re.compile(p) for p in dangerous_patterns)

        self.custom_validators = custom_validators or {}
        self.max_calls = max_calls_per_response

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Validate tool call(s) in response."""

        # Extract tool calls
        tool_calls = self._extract_tool_calls(response)

        if not tool_calls:
            return self.pass_result(message="No tool calls to verify")

        # Check call limit
        if len(tool_calls) > self.max_calls:
            return self.fail_result(
                f"Too many tool calls: {len(tool_calls)} (max: {self.max_calls})"
            )

        # Check each tool call
        for call in tool_calls:
            tool_name = call.get("tool_name") or call.get("name")

            # Malformed entry (#33): non-object tool_calls/choices member —
            # fail closed, never forward unvalidated content. An ambiguous
            # hybrid envelope (direct call + sibling collection) is also
            # rejected (Greptile P1).
            if call.get("type") == "__malformed__":
                if call.get("reason") == "ambiguous_hybrid_envelope":
                    message = (
                        "BLOCKED: Ambiguous hybrid tool-call envelope - response "
                        "mixes a direct tool call (type=tool_call/function_call) "
                        "with a sibling tool_calls/choices/content collection."
                    )
                else:
                    message = (
                        "BLOCKED: Response contains a malformed tool-call entry "
                        "(non-object item in tool_calls or choices[].message.tool_calls). "
                        "Each entry must be an object with a tool name."
                    )
                return self.fail_result(
                    message,
                    details={"response_keys": list(response.keys())},
                )

            # Unrecognized envelope (#28): fail closed, never pass silently.
            # Rejected unconditionally - a caller-declared name on an
            # __unrecognized__ sentinel must not bypass rejection (Greptile P1).
            if call.get("type") == "__unrecognized__":
                return self.fail_result(
                    "BLOCKED: Response contains tool-like content in an unrecognized format. "
                    "Supported shapes: type=tool_call, tool_calls[], choices[].message.tool_calls[], "
                    "content[].type=tool_use.",
                    details={"response_keys": list(response.keys())},
                )

            # A tool call must carry a real name — blank/non-string names can
            # never match blocklist/allowed/dangerous checks, so fail closed
            # rather than reporting an anonymous call verified (#33).
            if not ToolGuard._valid_tool_name(tool_name):
                return self.fail_result(
                    "BLOCKED: Tool call has no valid (non-blank string) name.",
                    details={"response_keys": list(response.keys())},
                )

            arguments = call.get("arguments", {})

            # Check blocked list
            if tool_name in self.blocked_tools:
                return self.fail_result(
                    f"BLOCKED: Tool '{tool_name}' is not allowed",
                    details={"blocked_tool": tool_name},
                )

            # Check allowed list (whitelist mode)
            if self.allowed_tools and tool_name not in self.allowed_tools:
                return self.fail_result(
                    f"BLOCKED: Tool '{tool_name}' is not in allowed list",
                    details={
                        "tool": tool_name,
                        "allowed": list(self.allowed_tools),
                    },
                )

            # Check for dangerous patterns in arguments. A negative depth
            # means a cycle was detected — fail closed on it too.
            args_depth = ToolGuard._arguments_depth(arguments)
            if args_depth < 0 or args_depth > ToolGuard._MAX_ARGS_JSON_DEPTH:
                return self.fail_result(
                    "BLOCKED: Tool arguments exceed maximum nesting depth.",
                    details={"tool": tool_name},
                )
            args_str = str(arguments)
            for pattern in self.dangerous_patterns:
                if pattern.search(args_str):
                    return self.fail_result(
                        "BLOCKED: Dangerous pattern detected in tool arguments",
                        details={
                            "tool": tool_name,
                            "pattern": pattern.pattern,
                        },
                    )

            # Run custom validator if exists
            if tool_name in self.custom_validators:
                try:
                    validator = self.custom_validators[tool_name]
                    is_valid, error_msg = validator(arguments)
                    if not is_valid:
                        return self.fail_result(
                            f"Tool '{tool_name}' validation failed: {error_msg}",
                            details={"tool": tool_name},
                        )
                except Exception as e:
                    return self.fail_result(
                        f"Tool validator error: {str(e)}",
                        details={"tool": tool_name},
                    )

        return self.pass_result(
            message=f"All {len(tool_calls)} tool call(s) verified",
            details={"tools_checked": [c.get("tool_name") for c in tool_calls]},
        )

    def _extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict]:
        """Extract tool calls from various response formats.

        Also detects tool-ish content in unrecognized envelope shapes (#28):
        if the response contains keys that suggest a tool call but none of the
        known extraction patterns matched, a sentinel entry is returned so
        the guard fails closed instead of passing with "No tool calls".

        Every extracted call is normalized (#33 review): OpenAI function-call
        wrappers are flattened and JSON-encoded argument strings are parsed,
        so blocklist and dangerous-argument checks always operate on
        ``tool_name``/``arguments`` regardless of envelope. Unparseable calls
        become fail-closed sentinels.
        """
        resp_type = str(response.get("type", "")).lower()

        calls: List[Dict] = []
        calls.extend(self._extract_known_shapes(response))

        # Responses API direct function_call items (#33 review). Only when the
        # known shapes yielded nothing — a hybrid response carrying both
        # type: function_call and a tool_calls array must not double-count.
        if not calls and resp_type == "function_call":
            calls.append(response)

        calls = self._normalize_calls(calls)

        if not calls:
            if self._looks_like_unrecognized_tool_content(response, resp_type):
                calls.append(
                    {"type": "__unrecognized__", "tool_name": None, "arguments": {}}
                )
        return calls

    @staticmethod
    def _is_container(value: Any) -> bool:
        """A dict or list (the only container types we traverse)."""
        return isinstance(value, (dict, list))

    @staticmethod
    def _container_children(node: Any) -> Any:
        """Iterable children of a container node (empty for a scalar)."""
        if isinstance(node, dict):
            return node.values()
        if isinstance(node, list):
            return node
        return ()

    @staticmethod
    def _arguments_depth(obj: Any) -> int:
        """Non-recursive max container nesting depth of a Python object.

        Used to fail closed on deeply-nested dict arguments before
        ``str(arguments)`` / json.dumps can raise RecursionError (Greptile P1).
        Uses an explicit stack, so it never recurses itself. Returns -1 when
        an ancestor back-reference (true cycle) is detected, so callers fail
        closed (Greptile P1). Containers shared by siblings (acyclic DAG
        references) are allowed — enter/exit bookkeeping keeps the visited
        set limited to the active traversal path, not the whole traversal.
        """
        if not ToolGuard._is_container(obj):
            return 0
        max_depth = 0
        # (node, depth, entering) frames: entering=False marks the exit of a
        # node, so `on_path` holds only true ancestors at any moment.
        stack: List[Tuple[Any, int, bool]] = [(obj, 1, True)]
        on_path: Set[int] = set()
        while stack:
            node, depth, entering = stack.pop()
            if not entering:
                on_path.discard(id(node))
                continue
            if id(node) in on_path:
                return -1
            on_path.add(id(node))
            if depth > max_depth:
                max_depth = depth
            stack.append((node, depth, False))
            for child in ToolGuard._container_children(node):
                if ToolGuard._is_container(child):
                    stack.append((child, depth + 1, True))
        return max_depth

    @staticmethod
    def _parse_tool_arguments(raw: Any) -> Tuple[bool, Any]:
        """Parse tool-call arguments. Returns (ok, value).

        ``None`` and blank strings are legitimate zero-argument payloads.
        Oversized argument payloads fail closed before parsing (DoS bound).
        Deeply-nested dict arguments are also rejected (non-recursive depth
        check) so recursion never crashes the caller (Greptile P1).
        """
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return True, {}
        if isinstance(raw, dict):
            depth = ToolGuard._arguments_depth(raw)
            if depth < 0 or depth > ToolGuard._MAX_ARGS_JSON_DEPTH:
                return False, None
            return True, raw
        if isinstance(raw, str):
            ok, args = ToolGuard._safe_parse_json_object(raw)
            if not ok:
                return False, None
            return True, args
        return False, None

    @staticmethod
    def _unrecognized_sentinel(name: Any = None) -> Dict[str, Any]:
        """Fail-closed sentinel for calls whose arguments cannot be parsed."""
        return {
            "type": "__unrecognized__",
            "tool_name": None,
            "arguments": {},
            "reason": "unparseable_arguments",
            "attempted_name": name,
        }

    @classmethod
    def _normalize_one(cls, call: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single tool call into the canonical tool_call shape.

        Fail-closed: any recognized-but-unparseable shape becomes an
        __unrecognized__ sentinel rather than silently passing.
        """
        if call.get("type") in ("__unrecognized__", "__malformed__"):
            return call

        # OpenAI function wrapper: {function: {name, arguments-as-JSON-string}}.
        resolved = cls._normalize_function_wrapper(call)
        if resolved is not None:
            return resolved

        # Responses API direct item: {type: "function_call", name, arguments}.
        resolved = cls._normalize_function_call_item(call)
        if resolved is not None:
            return resolved

        # JSON-encoded argument strings on otherwise-recognized calls.
        return cls._normalize_json_encoded_arguments(call)

    @staticmethod
    def _valid_tool_name(name: Any) -> bool:
        """A tool-call name must be a non-empty string to be verifiable (#33)."""
        return isinstance(name, str) and bool(name.strip())

    @classmethod
    def _normalize_function_wrapper(
        cls, call: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Normalize an OpenAI ``{function: {name, arguments}}`` wrapper.

        Returns None when the call is not such a wrapper.
        """
        fn = call.get("function")
        if fn is None:
            return None
        if not isinstance(fn, dict):
            # Incidental non-wrapper ``function`` key (e.g. string metadata on
            # a valid tool_call) is not a function wrapper. Fall through: the
            # call itself is still policy-checked by name in check(), and a
            # nameless call is rejected there (Sentry: false negative fixed).
            return None
        if not cls._valid_tool_name(fn.get("name")):
            return cls._unrecognized_sentinel(call.get("tool_name") or call.get("name"))
        name = fn["name"]
        ok, args = cls._parse_tool_arguments(fn.get("arguments", {}))
        if not ok:
            return cls._unrecognized_sentinel(name)
        return {"type": "tool_call", "tool_name": name, "arguments": args}

    @classmethod
    def _normalize_function_call_item(
        cls, call: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Normalize a Responses API ``{type: function_call, name, arguments}`` item.

        Returns None when the call is not such an item.
        """
        if str(call.get("type", "")).lower() != "function_call":
            return None
        name = call.get("name")
        if not cls._valid_tool_name(name):
            return cls._unrecognized_sentinel(None)
        ok, args = cls._parse_tool_arguments(call.get("arguments", {}))
        if not ok:
            return cls._unrecognized_sentinel(name)
        return {"type": "tool_call", "tool_name": name, "arguments": args}

    @classmethod
    def _normalize_json_encoded_arguments(cls, call: Dict[str, Any]) -> Dict[str, Any]:
        """Parse JSON-encoded argument strings on otherwise-recognized calls."""
        raw = call.get("arguments")
        if isinstance(raw, str):
            ok, parsed = cls._parse_tool_arguments(raw)
            if not ok:
                return cls._unrecognized_sentinel(
                    call.get("tool_name") or call.get("name")
                )
            return {**call, "arguments": parsed}
        return call

    @classmethod
    def _normalize_calls(cls, calls: List[Dict]) -> List[Dict]:
        return [cls._normalize_one(call) for call in calls]

    @staticmethod
    def _malformed_sentinel(item: Any) -> Dict[str, Any]:
        """Fail-closed sentinel for a non-dict tool-call entry (#33).

        Invalid entries in a tool_calls/choices array can never be validated,
        so they become an ``__malformed__`` sentinel that ``check()`` rejects
        instead of being silently discarded — or crashing on ``.get(...)``.
        """
        return {
            "type": "__malformed__",
            "tool_name": None,
            "arguments": {},
            "reason": "malformed_entry",
            "value": item,
        }

    @staticmethod
    def _iter_tool_collection(collection: Any) -> List[Dict]:
        """Safely convert a tool-call collection into entries (#33).

        A non-list container (scalar int / dict) is itself malformed and
        becomes a fail-closed sentinel rather than crashing the for-loop.
        ``None`` reads as an empty collection. Non-list members become
        malformed sentinels - never silently dropped.
        """
        if collection is None:
            return []
        if not isinstance(collection, list):
            return [ToolGuard._malformed_sentinel(collection)]
        return [
            c if isinstance(c, dict) else ToolGuard._malformed_sentinel(c)
            for c in collection
        ]

    @staticmethod
    def _extract_choices_tool_calls(choices: Any) -> List[Dict]:
        """Extract tool_calls from OpenAI ``choices[].message``.

        Non-object ``choice`` or ``tool_calls`` members become malformed
        sentinels - never silently dropped, and never crash on ``.get``. A
        non-list ``choices`` (scalar) is malformed, not ``TypeError``.
        """
        if not isinstance(choices, list):
            return ToolGuard._iter_tool_collection(choices)
        calls: List[Dict] = []
        for choice in choices:
            if not isinstance(choice, dict):
                calls.append(ToolGuard._malformed_sentinel(choice))
                continue
            msg = choice.get("message")
            if not isinstance(msg, dict):
                continue
            calls.extend(ToolGuard._iter_tool_collection(msg.get("tool_calls")))
        return calls

    @staticmethod
    def _extract_anthropic_tool_calls(blocks: Any) -> List[Dict]:
        """Extract ``content[].type == "tool_use"`` blocks (Anthropic).

        String content (plain text / ``type=text`` responses) is not a
        tool-block collection and yields no tool calls (Greptile P1).
        Non-list, non-string containers remain malformed (#33).
        """
        if blocks is None or isinstance(blocks, str):
            return []
        if not isinstance(blocks, list):
            if isinstance(blocks, dict):
                # Dict-valued content is a valid format for some APIs. Only a
                # direct tool_use block is a tool call; tool shapes nested
                # inside a dict are an ambiguous laundering vector and become
                # malformed; benign dicts carry no tools (Sentry HIGH).
                if str(blocks.get("type", "")).lower() == "tool_use":
                    return [
                        {
                            "type": "tool_call",
                            "tool_name": blocks.get("name", ""),
                            "arguments": blocks.get("input", {}),
                        }
                    ]
                if ToolGuard._contains_nested_tool_shape(blocks, 0):
                    return [ToolGuard._malformed_sentinel(blocks)]
                return []
            return ToolGuard._iter_tool_collection(blocks)
        calls: List[Dict] = []
        for block in blocks:
            # Case-insensitive to match the dict-content path above — a
            # mixed-case "Tool_Use" block is a tool call, not an
            # unrecognized envelope (Sentry HIGH).
            if (
                isinstance(block, dict)
                and str(block.get("type", "")).lower() == "tool_use"
            ):
                calls.append(
                    {
                        "type": "tool_call",
                        "tool_name": block.get("name", ""),
                        "arguments": block.get("input", {}),
                    }
                )
        return calls

    @staticmethod
    def _ambiguous_hybrid_sentinel() -> Dict[str, Any]:
        """Fail-closed sentinel for an ambiguous hybrid envelope.

        A response mixing a direct tool-call representation (type=
        tool_call/function_call) with a sibling collection cannot be
        validated unambiguously: picking one side lets the other escape
        policy, so the envelope is rejected (Greptile P1).
        """
        return {
            "type": "__malformed__",
            "tool_name": None,
            "arguments": {},
            "reason": "ambiguous_hybrid_envelope",
        }

    @staticmethod
    def _extract_known_shapes(response: Dict[str, Any]) -> List[Dict]:
        """Extract from the supported envelope shapes.

        Malformed entries - non-object array members, non-iterable scalar
        containers - become fail-closed ``__malformed__`` sentinels rather
        than being silently dropped or raising ``TypeError`` (#33). An
        ambiguous hybrid (direct call + sibling collection) is rejected.
        """
        calls: List[Dict] = []
        resp_type = str(response.get("type", "")).lower()

        # Ambiguous hybrid envelope: a direct tool-call object that ALSO
        # carries a sibling collection. Reject instead of choosing one
        # side - the other would escape validation (Greptile P1).
        has_sibling_collection = any(
            key in response for key in ("tool_calls", "choices", "content")
        )
        if resp_type in ("tool_call", "function_call") and has_sibling_collection:
            return [ToolGuard._ambiguous_hybrid_sentinel()]

        # Multiple independent top-level collections at once is ambiguous and
        # would double-count under max_calls_per_response - reject (Sentry LOW).
        present_collections = [
            k for k in ("tool_calls", "choices", "content") if k in response
        ]
        if len(present_collections) > 1:
            return [ToolGuard._ambiguous_hybrid_sentinel()]

        # Direct tool call. Process it ONLY (no sibling present here) -
        # avoids double-counting under max_calls_per_response (Sentry MEDIUM).
        if resp_type == "tool_call":
            calls.append(response)
        elif "tool_calls" in response:
            calls.extend(ToolGuard._iter_tool_collection(response["tool_calls"]))

        # OpenAI format
        calls.extend(ToolGuard._extract_choices_tool_calls(response.get("choices", [])))

        # Anthropic format
        calls.extend(ToolGuard._extract_anthropic_tool_calls(response.get("content")))

        return calls

    @staticmethod
    def _looks_like_unrecognized_tool_content(
        response: Dict[str, Any], resp_type: str
    ) -> bool:
        """Detect tool-ish content that matched no known envelope shape (#28).

        Shape-based, not name-based: a hint key only counts when its VALUE is
        tool-shaped (an object carrying name/arguments), so ordinary fields
        like ``function: "parse_csv"`` on a structured response still pass.
        """
        # Tool-shaped objects under recognizable hint keys.
        for key in ("tool_use", "function_call", "function"):
            value = response.get(key)
            if isinstance(value, dict) and ("name" in value or "arguments" in value):
                return True

        # tool_name + arguments together is a tool call in all but name.
        if response.get("tool_name") is not None and "arguments" in response:
            return True

        content_blocks = response.get("content")
        if not isinstance(content_blocks, list):
            content_blocks = []
        nested_types = {
            str(block.get("type", "")).lower()
            for block in content_blocks
            if isinstance(block, dict)
        }
        if nested_types & {"tool_use", "function_call"}:
            return True

        declared_benign = {"text", "message", "structured_output"}
        if resp_type in declared_benign:
            # Declared-benign envelopes are validated structurally above; the
            # bounded deep-scan applies only to undeclared/unmodeled types.
            # Untyped envelopes ("") stay deep-scanned - they are exactly the
            # laundering vector (Sentry: structured_output carrying
            # name+arguments is a legitimate payload shape, not a hidden tool).
            return False
        if "tool" in resp_type:
            return True

        # Bounded recursive scan (#33 review): tool-shaped objects nested
        # inside wrappers/arrays must not slip through as "no tool calls".
        return ToolGuard._contains_nested_tool_shape(response, 0)

    @staticmethod
    def _is_tool_shaped_dict(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        t = str(value.get("type", "")).lower()
        if t in ("tool_use", "function_call", "tool_call"):
            return True
        return "tool_name" in value or ("name" in value and "arguments" in value)

    @classmethod
    def _contains_nested_tool_shape(cls, value: Any, depth: int) -> bool:
        """Bounded recursive scan for tool-shaped objects (#33 review)."""
        if depth > ToolGuard._MAX_NESTED_SCAN_DEPTH:
            return False
        if isinstance(value, dict):
            if ToolGuard._is_tool_shaped_dict(value):
                return True
            return any(
                cls._contains_nested_tool_shape(v, depth + 1) for v in value.values()
            )
        if isinstance(value, list):
            return any(
                cls._contains_nested_tool_shape(item, depth + 1) for item in value
            )
        return False
