"""
Safety Guard - Comprehensive safety checks for AI responses.

Combines multiple safety checks into a single guard.
"""

import ast
import json
from typing import Any, Callable, Dict, Optional, List, Set, Tuple
from .base import BaseGuard, GuardResult
import math
import re


class SafetyGuard(BaseGuard):
    """
    Comprehensive safety guard for AI responses.

    Features:
    - PII detection (emails, phones, SSN, credit cards)
    - Prompt injection detection
    - Harmful content patterns
    - Budget/limit enforcement

    Usage:
        guard = SafetyGuard(
            check_pii=True,
            check_injection=True,
            max_cost=100.0,
        )
    """

    name = "SafetyGuard"
    description = "Comprehensive safety checks"
    _INJECTION_TEXT_FIELDS = frozenset(
        {"text", "content", "message", "output_text", "output", "arguments"}
    )

    # PII patterns
    PII_PATTERNS = {
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    }

    # Prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+(instructions?|prompts?)",
        r"disregard\s+(previous|all|above)",
        r"forget\s+(everything|all|your\s+instructions)",
        r"you\s+are\s+now\s+",
        r"act\s+as\s+if\s+you\s+are",
        r"pretend\s+(you|to\s+be)",
        r"new\s+instructions?\s*:",
        # Requires instruction-override context after the role prefix — a bare
        # "system:" label matches ordinary config text ("system: healthy",
        # "Operating system: Linux") and blocked legitimate responses
        # (Sentry/Greptile P1, PR #34). Filler between the marker and the
        # override term is unbounded but cannot cross another "system:"
        # marker (so rotation history/flooding cannot blow up matching —
        # verified linear on adversarial input) and cannot cross sentence
        # boundaries (periods excluded, so benign multi-sentence text like
        # "system: operational. The team will reveal results" stays passing).
        # Directives include disclose/leak/expose alongside reveal
        # (Greptile P1, PR #34). Mirrored in npm guards.ts.
        r"system\s*:\s*(?:(?!\bsystem\s*:)[A-Za-z]+[,:;!?]?\s+)*"
        + r"(?:ignore|disregard|forget|override|you\s+are|"
        + r"act\s+as|pretend|new\s+instructions?|bypass|reveal|disclose|"
        + r"leak|expose)\b",
        r"<\|.*?\|>",  # Special tokens
        r"\[\[.*?\]\]",  # Bracket commands
    ]

    # Harmful content patterns. The value part excludes benign placeholder
    # labels ("password: required", "api_key: not set") that are common in
    # ordinary status text but still matches real credentials
    # ("api_key=sk-12345") (Sentry/Greptile P1, PR #34). Mirrored in npm.
    # The exemption alternatives must match the ENTIRE value — the old \b
    # let "password=required-secret" bypass (placeholder prefix + suffix),
    # and (?=\s|$) let "password=required actual-secret" bypass (credential
    # hidden after whitespace, which \S+ cannot reach). Each alternative now
    # asserts only whitespace/punctuation until end-of-string next
    # (Greptile/CodeRabbit/Sentry P1, PR #34).
    _CREDENTIAL_EXEMPTION = (
        r"(?!(?:required|optional|none|null|redacted|omitted|placeholder|"
        r"invalid|expired|not[_\s]?(?:set|provided)|n/?a)"
        r"(?=[\s.,;:!?)}\]]*$)"
        r"|\*{3,}(?=[\s.,;:!?)}\]]*$)"
        r"|x{3,}(?=[\s.,;:!?)}\]]*$))\S+"
    )

    _CREDENTIAL_PATTERNS = (
        r"password\s*[=:]\s*" + _CREDENTIAL_EXEMPTION,
        r"api[_-]?key\s*[=:]\s*" + _CREDENTIAL_EXEMPTION,
        r"secret\s*[=:]\s*" + _CREDENTIAL_EXEMPTION,
        # Value-aware label form (same placeholder exemption as above) —
        # "private[_-]?key" bare-matching blocked benign labels such as
        # "private_key: not set" (Greptile P1, PR #34). The [\s_-]? class
        # also catches the spaced "private key: <value>" form.
        r"private[\s_-]?key\s*[=:]\s*" + _CREDENTIAL_EXEMPTION,
    )

    _JSON_CREDENTIAL_RE = re.compile(
        r"""["'](password|api[_-]?key|secret|private[\s_-]?key)["']\s*:\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')""",
        re.IGNORECASE,
    )

    # Credential-shaped tail tokens for guidance-prose detection below.
    # Provider prefixes are literal alternations (linear, no nesting).
    _CRED_PREFIX_RE = re.compile(
        r"sk-|ghp_|glpat-|xox[baprs]?-|eyJ|akia|-----BEGIN", re.IGNORECASE
    )

    HARMFUL_PATTERNS = [
        *_CREDENTIAL_PATTERNS,
        # Generic PEM header: dashed BEGIN [TYPE] PRIVATE KEY — covers
        # RSA/DSA/EC plus generic "BEGIN PRIVATE KEY", OPENSSH and ENCRYPTED
        # variants that were missed (CodeRabbit, PR #34). The leading dashes
        # are required: without them the case-insensitive pattern matches
        # ordinary prose like "begin private key rotation" (CodeRabbit).
        r"-{3,}\s*BEGIN\s+(?:[A-Z0-9]+\s+)*PRIVATE\s+KEY",
    ]

    # A guidance-prose value needs enough tokens to read as a sentence;
    # shorter values stay on the strict placeholder rule. Six is the
    # documented boundary (Greptile P1, PR #34): five-token passphrases
    # ("correct horse battery staple extra") still block, while longer
    # guidance ("must be at least 8 characters") passes. This boundary is
    # policy, not science — prose-shaped exfiltration and guidance prose
    # are indistinguishable by construction, so any fixed threshold falls
    # to N+1 words; high-entropy/prefixed/hyphenated/digit credentials
    # are still caught by shape regardless of length.
    _PROSE_MIN_TOKENS = 6

    # `label = placeholder + tail` splitter for the placeholder-track
    # exemption below. Mirrors the four credential labels.
    _LABEL_VALUE_RE = re.compile(
        r"\b(password|api[_-]?key|secret|private[\s_-]?key)\s*[=:]\s*"
        r"(\S+)([\s\S]*)",
        re.IGNORECASE,
    )

    def __init__(
        self,
        check_pii: bool = True,
        check_injection: bool = True,
        check_harmful: bool = True,
        check_budget: bool = True,
        pii_allow_list: Optional[Set[str]] = None,
        max_cost: Optional[float] = None,
        max_tokens: Optional[int] = None,
        custom_patterns: Optional[List[str]] = None,
    ):
        """
        Initialize SafetyGuard.

        Args:
            check_pii: Check for personally identifiable information
            check_injection: Check for prompt injection attempts
            check_harmful: Check for harmful content patterns
            check_budget: Enforce cost/token limits
            pii_allow_list: PII types to allow (e.g., {"email"})
            max_cost: Maximum cost in dollars
            max_tokens: Maximum token count
            custom_patterns: Additional patterns to check
        """
        self.check_pii = check_pii
        self.check_injection = check_injection
        self.check_harmful = check_harmful
        self.check_budget = check_budget
        self.pii_allow_list = pii_allow_list or set()
        self.max_cost = max_cost
        self.max_tokens = max_tokens
        self.custom_patterns = [re.compile(p, re.I) for p in (custom_patterns or [])]

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Run all safety checks."""

        (
            content,
            leaf_strings,
            injection_parts,
            limit_error,
        ) = self._collect_bounded_content(response)
        if limit_error is not None:
            return self.fail_result(
                "Safety check failed: response exceeds inspection limits",
                details={"resource_limit": limit_error},
            )

        context = context or {}

        issues: List[Dict] = []

        # PII check
        if self.check_pii:
            pii_found = self._check_pii(content)
            if pii_found:
                issues.append(
                    {
                        "type": "pii",
                        "severity": "warning",
                        "details": pii_found,
                    }
                )

        # Injection check
        if self.check_injection:
            injections = self._check_injection(injection_parts)
            if injections:
                issues.append(
                    {
                        "type": "injection",
                        "severity": "error",
                        "details": injections,
                    }
                )

        # Harmful content check — evaluated per collected string, not on
        # the joined content (Greptile P1, PR #34): placeholder exemptions
        # must occupy the complete field value. On joined content,
        # extraction artifacts (the response's own `type` field appended
        # as e.g. " text") defeat the end-of-string anchor and turn
        # benign labels ("password: required") into false positives,
        # while a credential hidden after whitespace
        # ("password=required actual-secret") must still block.
        if self.check_harmful:
            harmful = self._check_harmful_parts(leaf_strings)
            if harmful:
                issues.append(
                    {
                        "type": "harmful",
                        "severity": "error",
                        "details": harmful,
                    }
                )

        # Budget check
        if self.check_budget:
            budget_issues = self._check_budget(response, context)
            if budget_issues:
                issues.append(
                    {
                        "type": "budget",
                        "severity": "error",
                        "details": budget_issues,
                    }
                )

        # Custom patterns
        for pattern in self.custom_patterns:
            if pattern.search(content):
                issues.append(
                    {
                        "type": "custom_pattern",
                        "severity": "error",
                        "pattern": pattern.pattern,
                    }
                )

        # Determine result
        errors = [i for i in issues if i.get("severity") == "error"]
        warnings = [i for i in issues if i.get("severity") == "warning"]

        if errors:
            return self.fail_result(
                message=f"Safety check failed: {len(errors)} critical issue(s)",
                details={"issues": issues},
            )
        elif warnings:
            return self.warn_result(
                message=f"Safety warnings: {len(warnings)} warning(s)",
                details={"issues": issues},
            )

        return self.pass_result(message="All safety checks passed")

    _MAX_CONTENT_DEPTH = 12
    _MAX_CONTENT_NODES = 10_000
    _MAX_CONTENT_CHARS = 100_000
    _MAX_FIELD_LABEL_CHARS = 10_000
    _MAX_CREDENTIAL_SCAN_CHARS = 2 * _MAX_CONTENT_CHARS + _MAX_FIELD_LABEL_CHARS

    def _collect_bounded_content(
        self, response: Any
    ) -> Tuple[str, List[str], List[str], Optional[str]]:
        """Collect scan text and credential leaves within fixed resource caps."""
        content_parts: List[str] = []
        label_parts: List[str] = []
        injection_parts: List[str] = []
        leaf_strings: List[str] = []
        active: Set[int] = set()
        node_count = 0
        content_chars = 0
        leaf_chars = 0
        label_chars = 0
        limit_error: Optional[str] = None

        def add_content(text: str) -> bool:
            nonlocal content_chars, limit_error
            separator_cost = 1 if content_parts else 0
            if content_chars + separator_cost + len(text) > self._MAX_CONTENT_CHARS:
                limit_error = "scanned content exceeds the character limit"
                return False
            content_parts.append(text)
            content_chars += separator_cost + len(text)
            return True

        def collect(
            value: Any,
            depth: int,
            field_name: Optional[str] = None,
            stringify_content: bool = False,
            injection_sequence: Optional[List[List[str]]] = None,
        ) -> None:
            nonlocal node_count, leaf_chars, label_chars, limit_error
            if limit_error is not None:
                return

            node_count += 1
            if node_count > self._MAX_CONTENT_NODES:
                limit_error = "response node count exceeds the inspection limit"
                return
            if depth > self._MAX_CONTENT_DEPTH:
                limit_error = "response nesting exceeds the inspection depth"
                return

            if isinstance(value, str):
                label_cost = len(field_name) + 1 if field_name is not None else 0
                scan_cost = len(value) + label_cost
                leaf_cost = len(value) + (scan_cost if field_name is not None else 0)
                if leaf_chars + leaf_cost > self._MAX_CREDENTIAL_SCAN_CHARS:
                    limit_error = "credential scan exceeds the character limit"
                    return
                if not add_content(value):
                    return

                leaf_strings.append(value)
                if field_name is not None:
                    leaf_strings.append(f"{field_name}={value}")
                    injection_parts.append(f"{field_name} {value}")
                if stringify_content and injection_sequence is not None:
                    injection_sequence[-1].append(value)
                leaf_chars += leaf_cost
                return

            if isinstance(value, dict):
                identity = id(value)
                if identity in active:
                    limit_error = "response contains a cycle"
                    return
                active.add(identity)
                owns_object_sequence = stringify_content and injection_sequence is None
                object_sequence: Optional[List[List[str]]] = (
                    [[]] if owns_object_sequence else injection_sequence
                )
                has_field = False
                last_field_is_text = False
                for key, child in value.items():
                    if not isinstance(key, str):
                        limit_error = "response contains a non-string object key"
                        break
                    is_text_field = key.casefold() in self._INJECTION_TEXT_FIELDS
                    if object_sequence is not None and (has_field or not is_text_field):
                        object_sequence.append([])
                    has_field = True
                    last_field_is_text = is_text_field
                    label_cost = len(key) + 1
                    if label_chars + label_cost > self._MAX_FIELD_LABEL_CHARS:
                        limit_error = "field labels exceed the inspection limit"
                        break
                    label_chars += label_cost
                    # Field names are attacker-controlled input too. Include
                    # them in the scan corpus without consuming the value
                    # character budget, preserving the documented value cap.
                    label_parts.append(key)
                    injection_parts.append(key)
                    if stringify_content:
                        node_count += 1
                        if node_count > self._MAX_CONTENT_NODES:
                            limit_error = (
                                "response node count exceeds the inspection limit"
                            )
                            break
                    include_content = stringify_content or (
                        depth == 0 and key in ("output", "arguments")
                    )
                    child_field = key if isinstance(child, str) else None
                    collect(
                        child,
                        depth + 1,
                        child_field,
                        include_content,
                        object_sequence if is_text_field else None,
                    )
                    if limit_error is not None:
                        break
                active.remove(identity)
                if injection_sequence is not None and (
                    not has_field or not last_field_is_text
                ):
                    injection_sequence.append([])
                if owns_object_sequence and object_sequence is not None:
                    injection_parts.extend(
                        " ".join(sequence)
                        for sequence in object_sequence
                        if len(sequence) > 1
                    )
                return

            if isinstance(value, list):
                identity = id(value)
                if identity in active:
                    limit_error = "response contains a cycle"
                    return
                active.add(identity)
                owns_sequence = stringify_content and injection_sequence is None
                own_sequence: Optional[List[List[str]]] = (
                    [[]] if owns_sequence else injection_sequence
                )
                for child in value:
                    collect(
                        child,
                        depth + 1,
                        stringify_content=stringify_content,
                        injection_sequence=own_sequence,
                    )
                    if limit_error is not None:
                        break
                active.remove(identity)
                if owns_sequence and own_sequence is not None:
                    injection_parts.extend(
                        " ".join(sequence)
                        for sequence in own_sequence
                        if len(sequence) > 1
                    )
                return

            if isinstance(value, int) and not isinstance(value, bool):
                if value.bit_length() > self._MAX_CONTENT_CHARS * 4:
                    limit_error = "scanned content exceeds the character limit"
                elif stringify_content:
                    try:
                        if not add_content(str(value)):
                            return
                    except (MemoryError, ValueError):
                        limit_error = "scanned content exceeds the character limit"
                return

            if isinstance(value, float):
                if stringify_content:
                    add_content(str(value))
                return

            if value is None or isinstance(value, bool):
                if stringify_content:
                    add_content(
                        "null" if value is None else ("true" if value else "false")
                    )
                return

            if stringify_content:
                limit_error = "response contains a non-JSON value"

        collect(response, 0)
        return (
            " ".join(content_parts + label_parts),
            leaf_strings,
            content_parts + injection_parts,
            limit_error,
        )

    def _check_pii(self, content: str) -> List[str]:
        """Check for PII in content."""
        found = []

        if "email" not in self.pii_allow_list and self._contains_email(content):
            found.append("email")

        for pii_type, pattern in self.PII_PATTERNS.items():
            if pii_type in self.pii_allow_list:
                continue
            if re.search(pattern, content, re.I):
                found.append(pii_type)

        return found

    @staticmethod
    def _contains_email(content: str) -> bool:
        """Find email-like text with a single forward/backward pass."""
        local_chars = (
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-"
        )
        cursor = 0
        while True:
            at = content.find("@", cursor)
            if at < 0:
                return False
            cursor = at + 1

            local_start = at - 1
            while local_start >= 0 and content[local_start] in local_chars:
                local_start -= 1
            if local_start == at - 1:
                continue

            domain_chars = 0
            tld_chars = 0
            found_tld = False
            after_dot = False
            malformed_domain = False
            pos = at + 1
            while pos < len(content):
                char = content[pos]
                is_alpha = "a" <= char <= "z" or "A" <= char <= "Z"
                is_digit = "0" <= char <= "9"
                if not (is_alpha or is_digit or char in ".-"):
                    break
                if char == ".":
                    if domain_chars == 0 or content[pos - 1] == ".":
                        malformed_domain = True
                    after_dot = domain_chars > 0
                    tld_chars = 0
                elif after_dot:
                    if is_alpha:
                        tld_chars += 1
                        if tld_chars >= 2:
                            found_tld = True
                    else:
                        after_dot = False
                domain_chars += 1
                pos += 1
            if not malformed_domain and found_tld:
                return True
            cursor = max(cursor, pos)

    def _check_injection(self, parts: List[str]) -> List[str]:
        """Check prompt injection per value and field name."""
        found = []

        for pattern in self.INJECTION_PATTERNS:
            if any(re.search(pattern, part, re.I) for part in parts):
                found.append(pattern)

        return found

    def _collect_leaf_strings(self, response: Any, _depth: int = 0) -> List[str]:
        """Collect every string leaf for per-field harmful evaluation.

        Unlike `_extract_content` (which joins everything for PII/injection
        scanning), leaves stay separate so a placeholder exemption is judged
        against its own field value, not against joined extraction
        artifacts. Dict entries contribute both the bare value and the
        `key=value` form: the bare value alone drops the field context
        that credential patterns match on, so `{"password": "hunter2"}`
        would otherwise verify uninspected (Greptile P1, PR #34). The
        strict placeholder exemption still judges the `key=value` form,
        so `{"password": "required"}` keeps passing. Bounded by
        `_MAX_CONTENT_DEPTH` like the recursive extractor, so cyclic
        structures terminate.
        """
        return self._collect_bounded_content(response)[1]

    def _has_digit_word(self, token: str) -> bool:
        """True when the token holds a 6+ alnum run containing a digit."""
        run = 0
        has_digit = False
        for c in token:
            if "a" <= c <= "z" or "A" <= c <= "Z" or "0" <= c <= "9" or c == "_":
                run += 1
                if "0" <= c <= "9":
                    has_digit = True
            else:
                if run >= 6 and has_digit:
                    return True
                run = 0
                has_digit = False
        return run >= 6 and has_digit

    def _token_is_cred_shaped(self, token: str) -> bool:
        """True when a prose token looks like credential material.

        Plain string scans only — no nested quantifiers, so there is no
        backtracking surface (unlike the ReDoS-prone alternations this
        replaces for prose tails). A token carrying `=`/`:` is label
        structure (e.g. `password=required`), not a measurable value, so
        the length rule skips it — the strict placeholder rule still
        judges short values.
        """
        if SafetyGuard._CRED_PREFIX_RE.search(token):
            return True
        if len(token) >= 16 and "=" not in token and ":" not in token:
            return True
        if ("-" in token or "_" in token) and (
            any("0" <= c <= "9" for c in token) or len(token) >= 12
        ):
            return True
        return self._has_digit_word(token)

    def _is_guidance_prose(self, text: str) -> bool:
        """True when a leaf reads as guidance prose, not a credential value.

        Multiline values (`password: required\\nContact admin`) and
        explanatory values (`password=must be at least 8 characters`) must
        pass, while a placeholder followed by credential-shaped material
        (`password=required\\nsk-live-xyz`) must still block (Sentry and
        Greptile P1, PR #34). Short values stay on the strict placeholder
        rule — `secret=none backdoor` blocks there, not here.
        """
        tokens = text.split()
        if len(tokens) < self._PROSE_MIN_TOKENS:
            return False
        return not any(self._token_is_cred_shaped(t) for t in tokens)

    def _placeholder_tail_allows(self, leaf: str) -> bool:
        """True when a placeholder-led value has a benign tail.

        `password=required\\nContact admin` passes (placeholder + two
        shapeless tail tokens), while `secret=none backdoor` still blocks
        (single tail token stays strict) — verified against the pinned
        matrix in tests/test_guards.py.
        """
        match = self._LABEL_VALUE_RE.search(leaf)
        if not match:
            return False
        _, first, rest = match.groups()
        probe = f"{match.group(1)}={first}"
        if any(
            re.search(pattern, probe, re.I) for pattern in self._CREDENTIAL_PATTERNS
        ):
            return False
        tail = rest.split()
        if not tail:
            return True
        if any(self._token_is_cred_shaped(t) for t in tail):
            return False
        return len(tail) >= 2

    @staticmethod
    def _decode_json_credential_value(raw: str) -> str:
        """Decode JSON or JSON-like quoted values before placeholder checks."""
        try:
            decoded = json.loads(raw) if raw.startswith('"') else ast.literal_eval(raw)
            if isinstance(decoded, str):
                return decoded
        except (ValueError, SyntaxError, TypeError):
            pass
        return raw[1:-1]

    def _check_harmful_parts(self, parts: List[str]) -> List[str]:
        """Match harmful patterns against each collected string separately."""
        found = []
        for part in parts:
            scan_parts = [part]
            scan_parts.extend(
                f"{match.group(1)}={self._decode_json_credential_value(match.group(2))}"
                for match in self._JSON_CREDENTIAL_RE.finditer(part)
            )
            for scan_part in scan_parts:
                if self._is_guidance_prose(scan_part):
                    continue
                if self._placeholder_tail_allows(scan_part):
                    continue
                for pattern in self.HARMFUL_PATTERNS:
                    if re.search(pattern, scan_part, re.I) and pattern not in found:
                        found.append(pattern)
        return found

    @staticmethod
    def _is_usable_amount(value: Any) -> bool:
        """True when a model-reported usage amount is a usable number (#31).

        ``response["usage"]`` is supplied by the very output under
        verification, so anything that is not a finite, non-negative real
        number (strings, bools, negatives, NaN/inf) is rejected — failing
        closed rather than letting a malformed report silence the cap.
        """
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value >= 0
        )

    def _check_budget(
        self,
        response: Dict,
        context: Dict,
    ) -> List[str]:
        """Check budget/limit constraints.

        Trust model (#31): ``response["usage"]`` is model-reported and
        untrusted — a compromised model can under-report usage, or send
        negative/non-numeric values to defeat the cap. Reported values are
        validated (must be finite non-negative numbers) and anything else
        fails closed. Under-reporting cannot be detected from the response
        itself: for authoritative enforcement, supply trusted-side
        accounting via ``context["total_cost"]`` / ``context["total_tokens"]``
        (added on top of the reported usage) or reconcile against signed
        provider reports.
        """
        issues = []

        usage = response.get("usage")
        malformed_usage = usage is not None and not isinstance(usage, dict)
        if not isinstance(usage, dict):
            usage = {}

        if malformed_usage:
            # #31 review (Greptile P1): a present non-dict usage value is
            # malformed model output — reject it once, regardless of how
            # many caps are configured (Sentry: no duplicate messages).
            issues.append(
                "Response usage is not an object — failing closed (untrusted input)."
            )
            return issues

        # Check cost
        if self.max_cost is not None:
            issue = self._usage_cap_issue(
                reported=usage.get("cost"),
                trusted_total=context.get("total_cost"),
                trusted_key="total_cost",
                kind="cost",
                cap=self.max_cost,
                exceed=lambda total: f"Cost exceeds limit: ${total} > ${self.max_cost}",
            )
            if issue:
                issues.append(issue)

        # Check tokens
        if self.max_tokens is not None:
            issue = self._usage_cap_issue(
                reported=usage.get("total_tokens"),
                trusted_total=context.get("total_tokens"),
                trusted_key="total_tokens",
                kind="token count",
                cap=self.max_tokens,
                exceed=lambda total: f"Tokens exceed limit: {total} > {self.max_tokens}",
            )
            if issue:
                issues.append(issue)

        return issues

    @staticmethod
    def _usage_cap_issue(
        reported: Any,
        trusted_total: Any,
        trusted_key: str,
        kind: str,
        cap: float,
        exceed: Callable[[float], str],
    ) -> Optional[str]:
        """Return the budget issue for one cap, or None when within budget.

        Trust model: ``reported`` comes from the model output (untrusted) —
        it must be a finite non-negative number; missing accounting fails
        closed unless the caller supplies trusted-side totals
        (``context[trusted_key]``). Even trusted-side totals are validated:
        a non-numeric context value must fail closed, not crash the guard
        with a TypeError (Sentry).
        """
        if trusted_total is not None and not SafetyGuard._is_usable_amount(
            trusted_total
        ):
            return (
                f"Context {trusted_key} is not a finite non-negative number "
                "— failing closed."
            )
        if reported is None:
            if trusted_total is None:
                # #31 review: missing accounting must not silently pass a
                # configured cap — either the response reports usage or the
                # caller supplies trusted-side context totals.
                return (
                    f"No usage {kind} reported and no trusted context "
                    f"{trusted_key} — budget cap cannot be verified "
                    "(fail-closed)."
                )
            reported = 0
        elif not SafetyGuard._is_usable_amount(reported):
            return (
                f"Model-reported usage {kind} is not a finite non-negative "
                "number — failing closed (untrusted input)."
            )
        total = (trusted_total or 0) + reported
        if total > cap:
            return exceed(total)
        return None
