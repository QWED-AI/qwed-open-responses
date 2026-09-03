"""
Safety Guard - Comprehensive safety checks for AI responses.

Combines multiple safety checks into a single guard.
"""

from typing import Any, Dict, Optional, List, Set
from .base import BaseGuard, GuardResult
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

    # PII patterns
    PII_PATTERNS = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
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
        # (Sentry/Greptile P1, PR #34). Bounded neutral filler (up to three
        # words) is allowed between the marker and the override term, so
        # "system: please reveal ..." is caught without matching unbounded
        # prose (CodeRabbit, PR #34). Mirrored in npm guards.ts.
        r"system\s*:\s*(?:[A-Za-z]+[.,;:!?]?\s+){0,3}(?:ignore|disregard|forget|override|you\s+are|"
        r"act\s+as|pretend|new\s+instructions?|bypass|reveal)\b",
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
        r"(?=[\s.,;:!?)\]]*$)"
        r"|\*{3,}(?=[\s.,;:!?)\]]*$)"
        r"|x{3,}(?=[\s.,;:!?)\]]*$))\S+"
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
    # shorter values stay on the strict placeholder rule. Five is the
    # documented boundary: 4-token passphrases ("correct horse battery
    # staple") still block while 5+-token guidance passes (Greptile P1).
    _PROSE_MIN_TOKENS = 5

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

        content = self._extract_content(response)
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
            injections = self._check_injection(content)
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
            harmful = self._check_harmful_parts(self._collect_leaf_strings(response))
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
    _KNOWN_CONTENT_KEYS = ("content", "output", "text", "arguments")

    def _extract_content(self, response: Dict, _depth: int = 0) -> str:
        """Extract text content from response — recursively (#29).

        Walks all string values at any nesting depth (bounded to prevent
        DoS on deeply-nested payloads) so the guard can see content inside
        the canonical OpenAI shape (choices[].message.content), Anthropic
        envelopes, and arbitrary nested structures.
        """
        parts = self._known_content_parts(response)

        if _depth < self._MAX_CONTENT_DEPTH:
            for key, value in response.items():
                if not self._should_traverse(key, value):
                    continue
                parts.append(self._nested_content(value, _depth + 1))

        return " ".join(parts)

    def _should_traverse(self, key: str, value: Any) -> bool:
        """Decide whether a response entry still needs recursive scanning.

        - Unknown keys holding strings ARE scanned (nested scalars must be
          checked for injection/PII — Greptile P1).
        - Known content keys had their string forms collected verbatim above;
          their container forms are traversed so nothing hides inside them.
        - output/arguments dicts were already stringified above — skipping
          avoids duplicate collection.
        """
        if isinstance(value, str):
            # content/output/text strings were collected verbatim above;
            # a string under 'arguments' was NOT (only dicts are) and must
            # still be scanned for injection/PII.
            if key == "arguments":
                return True
            return key not in self._KNOWN_CONTENT_KEYS
        if isinstance(value, dict):
            return key not in ("output", "arguments")
        if isinstance(value, list):
            return True
        return False  # other scalars carry no scannable text

    @staticmethod
    def _known_content_parts(response: Dict) -> List[str]:
        """Collect strings from the well-known top-level content keys."""
        parts = []

        if isinstance(response.get("content"), str):
            parts.append(response["content"])
        if isinstance(response.get("output"), str):
            parts.append(response["output"])
        if isinstance(response.get("text"), str):
            parts.append(response["text"])

        # Handle nested structures
        if isinstance(response.get("output"), dict):
            parts.append(str(response["output"]))
        if isinstance(response.get("arguments"), dict):
            parts.append(str(response["arguments"]))

        return parts

    def _nested_content(self, value: Any, depth: int) -> str:
        """Recursively collect strings from unrecognized nesting levels."""
        if depth > self._MAX_CONTENT_DEPTH:
            return ""
        if isinstance(value, dict):
            return self._extract_content(value, depth)
        if isinstance(value, list):
            # Increment depth for list children too — otherwise list-only
            # nesting never reaches _MAX_CONTENT_DEPTH and a deeply (or
            # cyclically) nested list recurses until RecursionError (T-Rex P1).
            collected = [self._nested_content(item, depth + 1) for item in value]
            return " ".join(collected)
        if isinstance(value, str):
            return value
        return ""

    def _check_pii(self, content: str) -> List[str]:
        """Check for PII in content."""
        found = []

        for pii_type, pattern in self.PII_PATTERNS.items():
            if pii_type in self.pii_allow_list:
                continue
            if re.search(pattern, content, re.I):
                found.append(pii_type)

        return found

    def _check_injection(self, content: str) -> List[str]:
        """Check for prompt injection patterns."""
        found = []

        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, content, re.I):
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
        if _depth > self._MAX_CONTENT_DEPTH:
            return []
        if isinstance(response, str):
            return [response]
        if isinstance(response, dict):
            leaves: List[str] = []
            for key, value in response.items():
                if isinstance(value, str):
                    leaves.append(value)
                    leaves.append(f"{key}={value}")
                else:
                    leaves.extend(self._collect_leaf_strings(value, _depth + 1))
            return leaves
        if isinstance(response, list):
            leaves = []
            for item in response:
                leaves.extend(self._collect_leaf_strings(item, _depth + 1))
            return leaves
        return []

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

    def _check_harmful_parts(self, parts: List[str]) -> List[str]:
        """Match harmful patterns against each collected string separately."""
        found = []
        for part in parts:
            if self._is_guidance_prose(part):
                continue
            if self._placeholder_tail_allows(part):
                continue
            for pattern in self.HARMFUL_PATTERNS:
                if re.search(pattern, part, re.I) and pattern not in found:
                    found.append(pattern)
        return found

    def _check_budget(
        self,
        response: Dict,
        context: Dict,
    ) -> List[str]:
        """Check budget/limit constraints."""
        issues = []

        # Check cost
        if self.max_cost:
            current_cost = context.get("total_cost", 0)
            response_cost = response.get("usage", {}).get("cost", 0)
            if current_cost + response_cost > self.max_cost:
                issues.append(
                    f"Cost exceeds limit: ${current_cost + response_cost} > ${self.max_cost}"
                )

        # Check tokens
        if self.max_tokens:
            current_tokens = context.get("total_tokens", 0)
            response_tokens = response.get("usage", {}).get("total_tokens", 0)
            if current_tokens + response_tokens > self.max_tokens:
                issues.append(
                    f"Tokens exceed limit: {current_tokens + response_tokens} > {self.max_tokens}"
                )

        return issues
