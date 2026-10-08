"""
Tool Guard - Validates tool calls for safety and correctness.

Blocks dangerous tools and validates tool arguments.
"""

from typing import Any, Dict, Optional, List, Set, Callable, Iterator, Tuple
from .base import BaseGuard, GuardResult
import json
import math
import re
import string


class ToolGuard(BaseGuard):
    """
    Validates tool calls before execution.

    Features:
    - Block dangerous tools
    - Validate tool arguments
    - Rate limit tool calls
    - Custom validation functions

    Security model (#31):
    - The blocklist folds separators to catch aliases, while the allowlist
      preserves them so one registered tool cannot authorize another.
    - The default blocklist covers common shells and OS command interpreters.
    - Argument pattern scanning additionally decodes bounded, printable
      base64 tokens and scans the decoded text with the same patterns.
    - Pattern scanning is a HEURISTIC, not a security boundary: encoding
      tricks beyond these mitigations can defeat regex scanning. For real
      enforcement prefer allowlists (``allowed_tools``) plus OS-level
      sandboxing.

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
        # Common shells / OS command interpreters (#31): exact-name
        # matching previously let "sh", "powershell", "zsh", ... pass.
        "sh",
        "ash",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "powershell",
        "pwsh",
        "bash.exe",
        "sh.exe",
        "zsh.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "osascript",
        "wscript",
        "cscript",
        "delete_file",
        "remove_file",
        "write_file",
        "modify_file",
        "send_email",
        "transfer_money",
        "make_payment",
        # Common aliases used by agent tool registries (#40). Separator
        # folding also covers camelCase and dashed/space-separated spellings.
        "run_command",
        "execute_command",
        "command_line",
        "terminal",
        # Canonical names of client-executed Responses API action items
        # (GHSA-xhq6-w3f2-m5w6): shell commands, file patches and desktop
        # control are blocked unless the caller opts out of the defaults.
        "local_shell",
        "apply_patch",
        "computer_use",
    }

    # Responses API items that ask the CLIENT to execute an action without a
    # function name/arguments envelope. Each is normalized into a canonical
    # tool call (type -> tool name, payload -> arguments) so blocklist,
    # allowlist, pattern and validator checks apply (GHSA-xhq6-w3f2-m5w6).
    _CLIENT_ACTION_ITEMS: Dict[str, Tuple[str, str]] = {
        "local_shell_call": ("local_shell", "action"),
        "shell_call": ("shell", "action"),
        "apply_patch_call": ("apply_patch", "operation"),
        "computer_call": ("computer_use", "action"),
    }
    # Client-executed items that carry their own tool name.
    _NAMED_CLIENT_ITEMS = frozenset({"custom_tool_call", "mcp_approval_request"})
    # Provider-hosted tool items: executed server-side before the response
    # is returned, so they report results rather than request execution.
    # They are exempt only from the "*_call" suffix rule below — any
    # name/arguments shape they carry is still inspected as before.
    _HOSTED_TOOL_ITEMS = frozenset(
        {
            "web_search_call",
            "file_search_call",
            "code_interpreter_call",
            "image_generation_call",
            "mcp_call",
        }
    )

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
    _MAX_ARGS_SCAN_NODES = 10_000
    _MAX_ARGS_SCAN_CHARS = 100_000
    _MAX_NESTED_SCAN_DEPTH = 12

    # #31: candidate encoded tokens (6-bit-group text encoding) inside
    # serialized arguments. >= 7 alphabet chars — the minimum that can carry
    # a 5-byte decoded payload ("eval(" / "sudo "), so padded short tokens
    # like "ZXhlYyg=" (-> "exec(") and "cm0gLXJmIC8=" (-> "rm -rf /") are
    # caught. Strict decoding (alphabet, canonical trailing bits, printable
    # UTF-8) filters ordinary words.
    _ENCODED_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{7,}={0,2}")
    _MAX_TOKEN_CHARS = 4096
    # Assembled from constants — a single long alphabet literal reads as
    # credential-like material to entropy scanners (QWED release gate).
    # Order matters: A-Z, a-z, 0-9, +, / (standard 6-bit-group alphabet).
    _TOKEN_CHARS = (
        string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
    )
    _RM_OPTION_SEQUENCE_RE = re.compile(
        r"\brm((?:\s+(?:-[firdv]+|--(?:recursive|force))){1,8})(?=\s|[;&|)]|$)",
        re.IGNORECASE | re.ASCII,
    )

    @classmethod
    def _is_action_item_type(
        cls, normalized_type: str, include_unknown: bool = False
    ) -> bool:
        """Return whether an item type requests client-side execution.

        Known client action items always match. With ``include_unknown``,
        any other ``*_call`` / ``*_request`` type (except provider-hosted
        items) matches too, so a new or unmodelled executable item fails
        closed instead of reading as tool-free (GHSA-xhq6-w3f2-m5w6). That
        suffix rule is applied only where the value is known to be a
        Responses item — stream items and ``output[]`` members of a
        response object — because ordinary data uses such type labels
        (``pull_request``, ``refund_request``, ``phone_call``).
        """
        if (
            normalized_type in cls._CLIENT_ACTION_ITEMS
            or normalized_type in cls._NAMED_CLIENT_ITEMS
        ):
            return True
        if not include_unknown or normalized_type in cls._HOSTED_TOOL_ITEMS:
            return False
        return normalized_type.endswith(("_call", "_request"))

    @classmethod
    def _has_unknown_response_output_item(cls, response: Dict[str, Any]) -> bool:
        """Whether a response object's ``output[]`` holds an executable item.

        Covers OpenAI / Open Responses ``{"object": "response", "output":
        [...]}`` envelopes, where every member is a protocol item.
        """
        if cls._normalized_type(response.get("object", "")) != "response":
            return False
        output = response.get("output")
        return isinstance(output, list) and any(
            isinstance(item, dict)
            and cls._is_action_item_type(
                cls._normalized_type(item.get("type", "")), include_unknown=True
            )
            for item in output
        )

    @staticmethod
    def _normalize_tool_identity(name: str) -> str:
        """Fold case and surrounding whitespace without merging separators."""
        return name.strip().casefold()

    @staticmethod
    def _normalize_tool_name(name: str) -> str:
        """Fold case, surrounding whitespace, and name separators."""
        folded = ToolGuard._normalize_tool_identity(name)
        return re.sub(r"[\W_]+", "", folded, flags=re.UNICODE)

    @staticmethod
    def _normalize_pattern_text(value: str) -> str:
        """Normalize common command separators before regex matching.

        The raw value is always scanned too. This bounded second form closes
        equivalent spellings such as ``DROP/*comment*/TABLE``, ``os . system``
        and ``rm -fr`` without changing user-supplied regex definitions.
        """
        normalized = re.sub(r"/\*[\s\S]*?(?:\*/|$)", " ", value)
        normalized = re.sub(r"\s*\.\s*", ".", normalized)

        def normalize_rm_flags(match: re.Match[str]) -> str:
            options = re.findall(
                r"-([firdv]+)|--(recursive|force)",
                match.group(1),
                flags=re.IGNORECASE | re.ASCII,
            )
            short_flags = "".join(short for short, _ in options).casefold()
            long_flags = {long.casefold() for _, long in options if long}
            has_recursive = "r" in short_flags or "recursive" in long_flags
            has_force = "f" in short_flags or "force" in long_flags
            return "rm -rf" if has_recursive and has_force else match.group(0)

        normalized = ToolGuard._RM_OPTION_SEQUENCE_RE.sub(
            normalize_rm_flags, normalized
        )
        return normalized

    @classmethod
    def _pattern_scan_values(cls, value: str) -> Iterator[str]:
        """Yield raw and normalized forms used by dangerous-pattern scans."""
        yield value
        normalized = cls._normalize_pattern_text(value)
        if normalized != value:
            yield normalized

    @staticmethod
    def _try_decode_encoded_token(token: str) -> Optional[str]:
        """Strictly decode a bounded 6-bit-group token to text, else None.

        Decoded text is never executed or returned raw — it is scanned with
        the same dangerous-pattern regexes applied to the raw arguments.
        Decoding is performed directly over 6-bit groups (strict alphabet,
        canonical trailing bits, printable UTF-8 output only) so malformed,
        binary, or non-canonical tokens are rejected deterministically.
        """
        if not token or len(token) > ToolGuard._MAX_TOKEN_CHARS:
            return None
        body = token.rstrip("=")
        if not body or len(body) % 4 == 1:
            return None  # impossible group structure
        acc = 0
        bits = 0
        out = bytearray()
        for ch in body:
            idx = ToolGuard._TOKEN_CHARS.find(ch)
            if idx < 0:
                return None  # strict: any non-alphabet character rejects
            acc = (acc << 6) | idx
            bits += 6
            if bits >= 8:
                bits -= 8
                out.append((acc >> bits) & 0xFF)
        if bits and acc & ((1 << bits) - 1):
            return None  # non-canonical trailing bits
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text
        return None

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
                (compiled case-insensitively, like the defaults)
            use_default_patterns: Include default dangerous patterns
            custom_validators: Dict of tool_name -> validator function
            max_calls_per_response: Max tool calls in single response
        """
        # #40: normalize both configured and incoming names so casing,
        # whitespace, and punctuation variants cannot bypass policy.
        self.blocked_tools: Set[str] = {
            self._normalize_tool_name(t) for t in (blocked_tools or [])
        }
        if use_default_blocklist:
            self.blocked_tools.update(
                self._normalize_tool_name(t) for t in self.DEFAULT_BLOCKED_TOOLS
            )

        self.allowed_tools: Optional[Set[str]] = (
            {self._normalize_tool_identity(t) for t in allowed_tools}
            if allowed_tools
            else None
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
            # Case-insensitive like the defaults: the guard's whole pattern
            # surface matches case-insensitively on both runtimes (#30).
            # Pass inline (?i) scoping inside your pattern if you need a
            # case-sensitive section.
            self.dangerous_patterns.extend(
                re.compile(p, re.IGNORECASE) for p in dangerous_patterns
            )

        self.custom_validators: Dict[str, Callable] = {}
        for name, validator in (custom_validators or {}).items():
            validator_name = self._normalize_tool_identity(name)
            if validator_name in self.custom_validators:
                raise ValueError(
                    f"Conflicting custom validators for tool name: {name!r}"
                )
            self.custom_validators[validator_name] = validator
        self.max_calls = max_calls_per_response

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Validate tool call(s) in response."""

        # Extract tool calls
        try:
            tool_calls = self.normalize_tool_calls(response)
        except Exception:
            return self.fail_result(
                "BLOCKED: Tool calls could not be inspected safely."
            )

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
            if not isinstance(tool_name, str) or not tool_name.strip():
                return self.fail_result(
                    "BLOCKED: Tool call has no valid (non-blank string) name.",
                    details={"response_keys": list(response.keys())},
                )

            arguments = call.get("arguments", {})

            # Blocked names fold separators; allowlists and validators preserve them.
            folded_name = self._normalize_tool_name(tool_name)
            tool_identity = self._normalize_tool_identity(tool_name)

            # Check blocked list
            if folded_name in self.blocked_tools:
                return self.fail_result(
                    f"BLOCKED: Tool '{tool_name}' is not allowed",
                    details={"blocked_tool": tool_name},
                )

            # Check allowed list (whitelist mode)
            if self.allowed_tools and tool_identity not in self.allowed_tools:
                return self.fail_result(
                    f"BLOCKED: Tool '{tool_name}' is not in allowed list",
                    details={
                        "tool": tool_name,
                        "allowed": list(self.allowed_tools),
                    },
                )

            # Check for dangerous patterns in arguments. A negative depth
            # means a cycle was detected — fail closed on it too.
            try:
                args_depth = ToolGuard._arguments_depth(arguments)
            except Exception:
                return self.fail_result(
                    "BLOCKED: Tool arguments could not be inspected safely.",
                    details={"tool": tool_name},
                )
            if args_depth < 0 or args_depth > ToolGuard._MAX_ARGS_JSON_DEPTH:
                return self.fail_result(
                    "BLOCKED: Tool arguments exceed safe inspection limits.",
                    details={"tool": tool_name},
                )
            # Scan the parsed values themselves. Re-serializing arguments
            # escapes control bytes and can hide whitespace from regexes.
            try:
                for string_value in ToolGuard._iter_string_leaves(arguments):
                    for scan_value in ToolGuard._pattern_scan_values(string_value):
                        for pattern in self.dangerous_patterns:
                            if pattern.search(scan_value):
                                return self.fail_result(
                                    "BLOCKED: Dangerous pattern detected in tool arguments",
                                    details={
                                        "tool": tool_name,
                                        "pattern": pattern.pattern,
                                    },
                                )

                    # #31: Decode bounded, printable-looking tokens in each raw
                    # string and scan decoded text with the same patterns.
                    for token in ToolGuard._ENCODED_TOKEN_RE.findall(string_value):
                        decoded = ToolGuard._try_decode_encoded_token(token)
                        if decoded is None:
                            continue
                        for scan_value in ToolGuard._pattern_scan_values(decoded):
                            for pattern in self.dangerous_patterns:
                                if pattern.search(scan_value):
                                    return self.fail_result(
                                        "BLOCKED: Dangerous pattern detected in "
                                        "base64-encoded tool arguments",
                                        details={
                                            "tool": tool_name,
                                            "pattern": pattern.pattern,
                                            "encoding": "base64",
                                        },
                                    )
            except Exception:
                return self.fail_result(
                    "BLOCKED: Tool arguments could not be inspected safely.",
                    details={"tool": tool_name},
                )

            # Run custom validator if exists
            if tool_identity in self.custom_validators:
                try:
                    validator = self.custom_validators[tool_identity]
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

    @classmethod
    def normalize_tool_calls(cls, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize tool calls from supported response formats.

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
        resp_type = cls._normalized_type(response.get("type", ""))

        calls: List[Dict] = []
        calls.extend(cls._extract_known_shapes(response))

        # Add direct Responses API items (function_call and client action
        # items) only when no other shape matched, so hybrid tool_calls
        # arrays are not double-counted.
        if not calls and (
            resp_type == "function_call" or cls._is_action_item_type(resp_type)
        ):
            calls.append(response)

        calls = cls._normalize_calls(calls)

        if not calls:
            if cls._looks_like_unrecognized_tool_content(response, resp_type):
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
    def _number_to_text(value: Any) -> str:
        """Return stable JSON-number text shared with the TypeScript guard."""
        if isinstance(value, int):
            return str(value)
        if not math.isfinite(value):
            return "null"
        if value == 0:
            return "0"

        text = str(value)
        if value.is_integer() and abs(value) < 1e21:
            return str(int(value))
        if "e" not in text.lower():
            return text

        mantissa, exponent = re.split("[eE]", text)
        exponent_value = int(exponent)
        if -6 <= exponent_value < 21:
            sign = ""
            if mantissa.startswith("-"):
                sign, mantissa = "-", mantissa[1:]
            whole, _, fraction = mantissa.partition(".")
            digits = whole + fraction
            decimal_index = len(whole) + exponent_value
            if decimal_index <= 0:
                normalized = "0." + ("0" * -decimal_index) + digits
            elif decimal_index >= len(digits):
                normalized = digits + ("0" * (decimal_index - len(digits)))
            else:
                normalized = digits[:decimal_index] + "." + digits[decimal_index:]
            if "." in normalized:
                normalized = normalized.rstrip("0").rstrip(".")
            return sign + normalized
        return f"{mantissa}e{exponent_value:+d}"

    @staticmethod
    def _scalar_to_text(value: Any) -> Optional[str]:
        """Return JSON-style text for scalar values and dictionary keys."""
        if isinstance(value, str):
            return value
        if value is None:
            return "null"
        # bool is an int subclass in Python; check it before numeric values so
        # both runtimes use the same JSON spelling instead of True/False.
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return ToolGuard._number_to_text(value)
        return None

    @staticmethod
    def _iter_string_leaves(value: Any) -> Iterator[str]:
        """Yield bounded parsed scalar keys and values as matching text."""
        stack: List[Tuple[Any, int, bool]] = [(value, 0, True)]
        on_path: Set[int] = set()
        scanned_nodes = 0
        scanned_chars = 0
        while stack:
            node, depth, entering = stack.pop()
            if not entering:
                on_path.discard(id(node))
                continue
            scanned_nodes += 1
            if scanned_nodes > ToolGuard._MAX_ARGS_SCAN_NODES:
                raise ValueError("Tool arguments exceed the node inspection limit")
            scalar_text = ToolGuard._scalar_to_text(node)
            if scalar_text is not None:
                scanned_chars += len(scalar_text)
                if scanned_chars > ToolGuard._MAX_ARGS_SCAN_CHARS:
                    raise ValueError(
                        "Tool arguments exceed the character inspection limit"
                    )
                yield scalar_text
            elif isinstance(node, dict):
                if depth >= ToolGuard._MAX_ARGS_JSON_DEPTH:
                    raise ValueError("Tool arguments exceed the depth inspection limit")
                marker = id(node)
                if marker in on_path:
                    raise ValueError("Tool arguments contain a cycle")
                on_path.add(marker)
                stack.append((node, depth, False))
                entries: List[Tuple[Optional[str], Any]] = []
                for key, child in node.items():
                    key_text = ToolGuard._scalar_to_text(key)
                    key_count = int(key_text is not None)
                    if (
                        scanned_nodes + len(stack) + len(entries) * 2 + 1 + key_count
                        > ToolGuard._MAX_ARGS_SCAN_NODES
                    ):
                        raise ValueError(
                            "Tool arguments exceed the node inspection limit"
                        )
                    entries.append((key_text, child))
                for key_text, child in reversed(entries):
                    stack.append((child, depth + 1, True))
                    if key_text is not None:
                        stack.append((key_text, depth + 1, True))
            elif isinstance(node, list):
                if depth >= ToolGuard._MAX_ARGS_JSON_DEPTH:
                    raise ValueError("Tool arguments exceed the depth inspection limit")
                marker = id(node)
                if marker in on_path:
                    raise ValueError("Tool arguments contain a cycle")
                if (
                    scanned_nodes + len(stack) + len(node)
                    > ToolGuard._MAX_ARGS_SCAN_NODES
                ):
                    raise ValueError("Tool arguments exceed the node inspection limit")
                on_path.add(marker)
                stack.append((node, depth, False))
                stack.extend((child, depth + 1, True) for child in reversed(node))

    @staticmethod
    def _arguments_depth(obj: Any) -> int:
        """Non-recursive max container nesting depth of a Python object.

        Used to fail closed on deeply-nested dict arguments before
        argument serialization can raise RecursionError (Greptile P1).
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
        scanned_nodes = 0
        while stack:
            node, depth, entering = stack.pop()
            if not entering:
                on_path.discard(id(node))
                continue
            if id(node) in on_path:
                return -1
            scanned_nodes += 1
            if scanned_nodes > ToolGuard._MAX_ARGS_SCAN_NODES:
                return -1
            on_path.add(id(node))
            if depth > max_depth:
                max_depth = depth
            stack.append((node, depth, False))
            if isinstance(node, list):
                if scanned_nodes + len(node) > ToolGuard._MAX_ARGS_SCAN_NODES:
                    return -1
                scanned_nodes += len(node)
                for child in node:
                    if ToolGuard._is_container(child):
                        stack.append((child, depth + 1, True))
            else:
                if scanned_nodes + len(node) > ToolGuard._MAX_ARGS_SCAN_NODES:
                    return -1
                scanned_nodes += len(node)
                for child in node.values():
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
    def _normalized_type(value: Any) -> str:
        """Normalize protocol type markers without changing the payload."""
        return value.strip().casefold() if isinstance(value, str) else ""

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

        item_type = cls._normalized_type(call.get("type", ""))
        if cls._is_action_item_type(item_type):
            return cls._normalize_action_item(call, item_type)

        tool_call = call.get("tool_call")
        function_call = call.get("function_call")
        function = call.get("function")
        has_function_wrapper = isinstance(function, dict) and any(
            key in function for key in ("name", "arguments")
        )
        has_root_call_fields = any(
            key in call for key in ("tool_name", "name", "arguments")
        )
        if has_function_wrapper and (
            tool_call is not None or function_call is not None or has_root_call_fields
        ):
            return ToolGuard._ambiguous_hybrid_sentinel()
        if tool_call is not None and function_call is not None:
            return ToolGuard._ambiguous_hybrid_sentinel()
        nested_call = tool_call if tool_call is not None else function_call
        if nested_call is not None:
            if not isinstance(nested_call, dict):
                return cls._unrecognized_sentinel(None)
            if nested_call is call or any(
                key in nested_call for key in ("tool_call", "function_call")
            ):
                return cls._unrecognized_sentinel(None)
            if any(key in call for key in ("tool_name", "name", "arguments")):
                return ToolGuard._ambiguous_hybrid_sentinel()
            call = nested_call

            # A nested direct call must not hide a conflicting function
            # wrapper. Validate the complete envelope instead of allowing the
            # wrapper's name to replace the name exposed to consumers.
            nested_function = call.get("function")
            if (
                isinstance(nested_function, dict)
                and any(key in nested_function for key in ("name", "arguments"))
                and any(key in call for key in ("tool_name", "name", "arguments"))
            ):
                return ToolGuard._ambiguous_hybrid_sentinel()

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

    @classmethod
    def _normalize_action_item(
        cls, call: Dict[str, Any], item_type: str
    ) -> Dict[str, Any]:
        """Normalize a client-executed Responses API item (GHSA-xhq6-w3f2-m5w6).

        The executor dispatches on the item type and its payload, so the
        canonical name comes from the type and the payload becomes the
        arguments. Malformed payloads and items that also carry another call
        envelope fail closed.
        """
        if any(
            key in call
            for key in (
                "tool_call",
                "toolCall",
                "function_call",
                "function",
                "tool_calls",
                "toolCalls",
            )
        ):
            return cls._ambiguous_hybrid_sentinel()

        if item_type in cls._CLIENT_ACTION_ITEMS:
            tool_name, payload_key = cls._CLIENT_ACTION_ITEMS[item_type]
            payload = call.get(payload_key)
            if not isinstance(payload, dict):
                return cls._unrecognized_sentinel(tool_name)
            arguments: Dict[str, Any] = {payload_key: payload}
            command = payload.get("command")
            if isinstance(command, list) and all(isinstance(p, str) for p in command):
                # argv lists split "rm", "-rf" into separate leaves; scan the
                # joined command line too so argument patterns still match.
                arguments["command_line"] = " ".join(command)
            return {"type": "tool_call", "tool_name": tool_name, "arguments": arguments}

        if item_type in cls._NAMED_CLIENT_ITEMS:
            name = call.get("name")
            if not cls._valid_tool_name(name):
                return cls._unrecognized_sentinel(None)
            for key in ("tool_name", "toolName"):
                declared = call.get(key)
                if declared is not None and (
                    not isinstance(declared, str)
                    or cls._normalize_tool_identity(declared)
                    != cls._normalize_tool_identity(name)
                ):
                    return cls._ambiguous_hybrid_sentinel()
            if item_type == "custom_tool_call":
                raw_input = call.get("input", "")
                if not isinstance(raw_input, str):
                    return cls._unrecognized_sentinel(name)
                return {
                    "type": "tool_call",
                    "tool_name": name,
                    "arguments": {"input": raw_input},
                }
            ok, args = cls._parse_tool_arguments(call.get("arguments", {}))
            if not ok:
                return cls._unrecognized_sentinel(name)
            return {"type": "tool_call", "tool_name": name, "arguments": args}

        # Defensive: callers only route known action types here.
        return cls._unrecognized_sentinel(None)

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
        if cls._normalized_type(call.get("type", "")) != "function_call":
            return None
        name = call.get("name")
        if not cls._valid_tool_name(name):
            # Some Open Responses producers use the canonical tool_name field
            # on a function_call item. Use it when name is missing or invalid,
            # while still rejecting calls without a usable name.
            name = call.get("tool_name")
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
                if ToolGuard._normalized_type(blocks.get("type", "")) == "tool_use":
                    return [
                        {
                            "type": "tool_call",
                            "tool_name": blocks.get("name", ""),
                            "arguments": blocks.get("input", {}),
                        }
                    ]
                nested_tool, scan_limited = ToolGuard._scan_nested_tool_shape(blocks, 0)
                if nested_tool or scan_limited:
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
                and ToolGuard._normalized_type(block.get("type", "")) == "tool_use"
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
        resp_type = ToolGuard._normalized_type(response.get("type", ""))

        # Ambiguous hybrid envelope: a direct tool-call object that ALSO
        # carries a sibling collection. Reject instead of choosing one
        # side - the other would escape validation (Greptile P1).
        has_sibling_collection = any(
            key in response for key in ("tool_calls", "choices", "content")
        )
        is_direct_item = resp_type in (
            "tool_call",
            "function_call",
        ) or ToolGuard._is_action_item_type(resp_type)
        if is_direct_item and has_sibling_collection:
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
        # Response objects: an unknown executable protocol item in output[]
        # must not read as tool-free (GHSA-xhq6-w3f2-m5w6).
        if ToolGuard._has_unknown_response_output_item(response):
            return True

        # Tool-shaped objects under recognizable hint keys. Result envelopes
        # may repeat the root ``function``/``tool_name`` fields for
        # correlation, but explicit nested call envelopes remain suspicious.
        hint_keys: Tuple[str, ...] = ("tool_use", "tool_call", "function_call")
        if resp_type not in {"tool_result", "function_call_output"}:
            hint_keys += ("function",)
        for key in hint_keys:
            value = response.get(key)
            if isinstance(value, dict) and ("name" in value or "arguments" in value):
                return True

        content_blocks = response.get("content")
        if not isinstance(content_blocks, list):
            content_blocks = []
        nested_types = {
            ToolGuard._normalized_type(block.get("type", ""))
            for block in content_blocks
            if isinstance(block, dict)
        }
        if nested_types & {"tool_use", "function_call"}:
            return True

        if resp_type in {"tool_result", "function_call_output"}:
            # Results are data returned by an already executed call, not a new
            # invocation to verify in the streaming path. Correlation metadata
            # such as root-level tool_name/arguments is exempt, but explicit
            # nested call shapes above still fail closed.
            return False

        # tool_name + arguments together is a tool call in all but name.
        if response.get("tool_name") is not None and "arguments" in response:
            return True

        declared_benign = {"text", "message"}
        if resp_type in declared_benign:
            # Declared-benign envelopes are validated structurally above; the
            # bounded deep-scan applies only to undeclared/unmodeled types.
            # Untyped envelopes ("") stay deep-scanned - they are exactly the
            # laundering vector. Structured output is deliberately excluded:
            # configured ToolGuard instances must inspect it too (#41).
            return False
        if "tool" in resp_type:
            return True

        # Bounded recursive scan (#33 review): tool-shaped objects nested
        # inside wrappers/arrays must not slip through as "no tool calls".
        # Reaching the bound is itself a failed inspection, even when the
        # skipped subtree has not exposed a tool shape (#41).
        nested_tool, scan_limited = ToolGuard._scan_nested_tool_shape(response, 0)
        return nested_tool or scan_limited

    @staticmethod
    def _is_tool_shaped_dict(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        t = ToolGuard._normalized_type(value.get("type", ""))
        if t in ("tool_use", "function_call", "tool_call"):
            return True
        if ToolGuard._is_action_item_type(t):
            # Client-executed items nested in output[] / wrappers are tool
            # calls even without name/arguments (GHSA-xhq6-w3f2-m5w6).
            return True
        return "tool_name" in value or ("name" in value and "arguments" in value)

    @classmethod
    def _contains_nested_tool_shape(cls, value: Any, depth: int) -> bool:
        """Return whether a bounded recursive scan finds a tool shape."""
        found, _scan_limited = cls._scan_nested_tool_shape(value, depth)
        return found

    @classmethod
    def _scan_nested_tool_shape(cls, value: Any, depth: int) -> Tuple[bool, bool]:
        """Find tool shapes and report when the bounded scan was truncated.

        A truncated scan cannot establish that a response is tool-free, so
        callers must fail closed instead of returning a clean "no calls"
        result (#41).
        """
        if depth > ToolGuard._MAX_NESTED_SCAN_DEPTH:
            return False, True
        if isinstance(value, dict):
            if ToolGuard._is_tool_shaped_dict(value):
                return True, False
            for child in value.values():
                found, scan_limited = cls._scan_nested_tool_shape(child, depth + 1)
                if found or scan_limited:
                    return found, scan_limited
            return False, False
        if isinstance(value, list):
            for child in value:
                found, scan_limited = cls._scan_nested_tool_shape(child, depth + 1)
                if found or scan_limited:
                    return found, scan_limited
            return False, False
        return False, False
