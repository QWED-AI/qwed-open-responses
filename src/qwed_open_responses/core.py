"""
QWED Open Responses - Core Verifier.

The ResponseVerifier is the main entry point for verifying AI responses.
It orchestrates multiple guards to ensure responses are safe and correct.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json


def _canonical_json(obj: Any) -> str:
    """Canonical JSON serialization for digest computation (#31).

    No ``default=str``: values JSON cannot represent must fail closed
    (TypeError -> ``_safe_binding`` returns None) instead of masking
    mutations behind a lossy string conversion.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _canonicalize_numbers(obj: Any) -> Any:
    """Collapse integral floats to ints so digests are runtime-portable.

    Python serializes ``1.0`` as ``1.0`` while JavaScript emits ``1`` for
    the same value — binding digests must match across runtimes (#31
    review). Non-integral floats keep their repr in both runtimes.
    """
    if isinstance(obj, float) and obj.is_integer() and abs(obj) < 1e15:
        return int(obj)
    if isinstance(obj, dict):
        return {k: _canonicalize_numbers(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_canonicalize_numbers(v) for v in obj]
    return obj


def _binding_digest(response: Any, guard_names: List[str]) -> str:
    """SHA-256 digest over the response AND the guard list (#31 review).

    Covering the guard names too means neither the verified payload nor the
    verification metadata can be altered without invalidating the binding.
    """
    payload = _canonical_json(
        _canonicalize_numbers({"guards": guard_names, "response": response})
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class GuardResult:
    """Result from a single guard check."""

    guard_name: str
    passed: bool
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    severity: str = "error"  # "error", "warning", "info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guard": self.guard_name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
            "severity": self.severity,
        }


@dataclass
class VerificationResult:
    """
    Result of verifying an AI response.

    Attributes:
        verified: True if all guards passed (warnings are not failures
            unless the verifier was created with ``allow_warnings=False``;
            see ``warnings``)
        response: The original response (potentially modified)
        guards_passed: Number of guards that passed
        guards_failed: Number of guards that failed
        guard_results: Individual results from each guard
        blocked: True if response was blocked (critical failure)
        block_reason: Why the response was blocked
        timestamp: When verification occurred
        binding: Tamper-evidence set by ``ResponseVerifier.verify`` —
            SHA-256 digest covering the verified response AND the guard
            names. ``None`` on hand-constructed results.

    .. warning::
        ``VerificationResult`` is a plain, publicly constructible dataclass
        (#31) and carries **no cryptographic attestation**: anyone can mint
        ``VerificationResult(verified=True, ...)``. Only trust results
        produced in-process by your own verifier; treat results received
        from external parties as untrusted. The ``binding`` hash ties a
        result to the exact response payload and guard list, so replaying
        or reattaching it is detected via :meth:`verify_binding` — but a
        binding is public, recomputable data and authenticates nothing: an
        external caller can mint a result with a matching binding. Require
        trusted in-process provenance or cryptographic attestation (tracked
        in qwed-verification #319) before acting on results you did not
        produce yourself.
    """

    verified: bool
    response: Any
    guards_passed: int = 0
    guards_failed: int = 0
    guard_results: List[GuardResult] = field(default_factory=list)
    blocked: bool = False
    block_reason: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    binding: Optional[Dict[str, Any]] = None

    @property
    def warnings(self) -> List[GuardResult]:
        """Guard results that passed with a warning (#31).

        Warnings are a separate visible state — they neither fail
        ``verified`` nor block, unless the verifier was created with
        ``allow_warnings=False``.
        """
        return [g for g in self.guard_results if g.severity == "warning"]

    def verify_binding(self, response: Any = None) -> bool:
        """Recompute the digest and compare it to ``binding`` (#31).

        Returns True only when this result carries a binding set by
        ``ResponseVerifier.verify`` AND the digest matches. The digest
        covers the response payload and the guard list, so a result cannot
        be replayed against a different response, or have its verification
        metadata (guards) altered, without detection. A hand-forged result
        with no binding fails immediately.

        Note: this detects mismatches only — it does not authenticate the
        result itself (a binding is public, recomputable data). See the
        class docstring for the trust model.
        """
        if not self.binding:
            return False
        try:
            expected = _binding_digest(
                self.response if response is None else response,
                self.binding.get("guards", []),
            )
        except (ValueError, TypeError, RecursionError):
            # Cyclic / non-serializable payload — cannot match any binding.
            return False
        return expected == self.binding.get("digest")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "guards_passed": self.guards_passed,
            "guards_failed": self.guards_failed,
            "warning_count": len(self.warnings),
            "guard_results": [g.to_dict() for g in self.guard_results],
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "timestamp": self.timestamp,
            "binding": self.binding,
        }

    def __str__(self) -> str:
        if self.verified:
            return f"[OK] Verified ({self.guards_passed} guards passed)"
        else:
            return f"[FAIL] Not verified ({self.guards_failed} guards failed)"


class ResponseVerifier:
    """
    Main verifier for AI responses.

    Usage:
        verifier = ResponseVerifier()

        # Verify with default guards
        result = verifier.verify(response)

        # Verify with custom guards
        result = verifier.verify(response, guards=[
            SchemaGuard(schema=my_schema),
            ToolGuard(blocked_tools=["execute_sql"]),
            MathGuard(),
        ])

        if result.verified:
            # Safe to use response
            process(result.response)
        else:
            # Handle failure
            for guard_result in result.guard_results:
                if not guard_result.passed:
                    log_error(guard_result.message)
    """

    def __init__(
        self,
        default_guards: Optional[List["BaseGuard"]] = None,
        strict_mode: bool = True,
        allow_warnings: bool = True,
    ):
        """
        Initialize the verifier.

        Args:
            default_guards: Guards to use when none specified
            strict_mode: If True, any guard failure blocks response
            allow_warnings: If True, warnings don't block (only errors)
        """
        self.default_guards = default_guards or []
        self.strict_mode = strict_mode
        self.allow_warnings = allow_warnings

    def verify(
        self,
        response: Any,
        guards: Optional[List["BaseGuard"]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """
        Verify an AI response against a set of guards.

        Args:
            response: The AI response to verify (dict, str, or Response object)
            guards: Guards to apply (uses default_guards if None)
            context: Additional context for guards (e.g., conversation history)

        Returns:
            VerificationResult with verification status and details
        """
        guards_to_use = guards if guards is not None else self.default_guards
        context = context or {}

        # Parse response if needed
        parsed_response = self._parse_response(response)

        def _safe_binding(resp: Any, names: List[str]) -> Optional[Dict[str, Any]]:
            """Binding digest, or ``None`` when the response cannot be bound.

            Cyclic / non-serializable response graphs raise inside the JSON
            canonicalizer (#31 review, Greptile P1) — callers must fail
            closed with a failed VerificationResult instead of crashing.
            """
            try:
                return {
                    "guards": names,
                    "digest": _binding_digest(resp, names),
                }
            except (ValueError, TypeError, RecursionError):
                return None

        # Fail-closed: zero guards must never produce verified=True (#27).
        # Absence of verification is not success — it is the opposite.
        if not guards_to_use:
            return VerificationResult(
                verified=False,
                response=parsed_response,
                guards_passed=0,
                guards_failed=0,
                guard_results=[
                    GuardResult(
                        guard_name="ResponseVerifier",
                        passed=False,
                        message="No guards configured — verification cannot be performed. "
                        "Pass at least one guard or set default_guards.",
                        severity="error",
                    )
                ],
                blocked=self.strict_mode,
                block_reason="No guards configured — fail-closed (zero-guard verify).",
                binding=_safe_binding(parsed_response, []),
            )

        # Run all guards
        guard_results: List[GuardResult] = []
        guards_passed = 0
        guards_failed = 0
        blocked = False
        block_reason = None

        for guard in guards_to_use:
            try:
                result = guard.check(parsed_response, context)
                guard_results.append(result)

                # #31 semantics: a warning PASSES the guard (see
                # BaseGuard.warn_result) but remains visible as a warning
                # via VerificationResult.warnings. It only fails/blocks
                # verification when warnings are not allowed.
                failed = not result.passed
                if result.severity == "warning" and not self.allow_warnings:
                    failed = True

                if failed:
                    guards_failed += 1

                    # Check if this blocks
                    if self.strict_mode and (
                        result.severity == "error"
                        or (result.severity == "warning" and not self.allow_warnings)
                    ):
                        blocked = True
                        block_reason = result.message
                else:
                    guards_passed += 1

            except Exception as e:
                # Guard threw exception - treat as failure
                guard_results.append(
                    GuardResult(
                        guard_name=guard.name,
                        passed=False,
                        message=f"Guard error: {str(e)}",
                        severity="error",
                    )
                )
                guards_failed += 1

        # Determine overall verification status
        verified = guards_failed == 0

        guard_names = [getattr(g, "name", type(g).__name__) for g in guards_to_use]

        binding = _safe_binding(parsed_response, guard_names)
        if binding is None:
            # #31 review (Greptile P1): a cyclic / non-serializable response
            # must yield a failed VerificationResult, never an exception.
            guard_results.append(
                GuardResult(
                    guard_name="ResponseVerifier",
                    passed=False,
                    message=(
                        "Response could not be bound — cyclic or "
                        "non-serializable structure. Failing closed."
                    ),
                    severity="error",
                )
            )
            return VerificationResult(
                verified=False,
                response=parsed_response,
                guards_passed=guards_passed,
                guards_failed=guards_failed + 1,
                guard_results=guard_results,
                blocked=self.strict_mode,
                block_reason=(
                    "Response could not be bound — cyclic or "
                    "non-serializable structure."
                    if self.strict_mode
                    else None
                ),
            )

        return VerificationResult(
            verified=verified,
            response=parsed_response,
            guards_passed=guards_passed,
            guards_failed=guards_failed,
            guard_results=guard_results,
            blocked=blocked,
            block_reason=block_reason,
            # #31: tamper-evidence binding — the digest covers the response
            # AND the guard list, so neither can be altered or replayed
            # elsewhere without detection. Not a signature; see the class
            # docstring.
            binding=binding,
        )

    def verify_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        guards: Optional[List["BaseGuard"]] = None,
    ) -> VerificationResult:
        """
        Convenience method to verify a tool call.

        Args:
            tool_name: Name of the tool being called
            arguments: Arguments to the tool
            guards: Guards to apply

        Returns:
            VerificationResult with verification status
        """
        tool_call = {
            "type": "tool_call",
            "tool_name": tool_name,
            "arguments": arguments,
        }
        return self.verify(tool_call, guards)

    def verify_structured_output(
        self,
        output: Dict[str, Any],
        schema: Optional[Dict[str, Any]] = None,
        guards: Optional[List["BaseGuard"]] = None,
    ) -> VerificationResult:
        """
        Convenience method to verify a structured output.

        Args:
            output: The structured output from the AI
            schema: JSON Schema to validate against. Required unless
                ``guards`` are supplied (#31) — with neither, nothing
                would be verified.
            guards: Additional guards to apply

        Returns:
            VerificationResult with verification status

        Raises:
            ValueError: If both ``schema`` and ``guards`` are empty —
                the call would otherwise verify nothing (#31).
        """
        from .guards import SchemaGuard

        if schema is None and not guards:
            raise ValueError(
                "verify_structured_output requires a JSON schema or at least "
                "one guard — with neither, nothing would be verified (#31)."
            )

        guards_list = list(guards) if guards else []

        # {} is a valid JSON Schema (matches anything) — distinguish a
        # supplied schema from an omitted one (#31 review).
        if schema is not None:
            guards_list.insert(0, SchemaGuard(schema=schema))

        structured = {
            "type": "structured_output",
            "output": output,
        }
        return self.verify(structured, guards_list)

    @staticmethod
    def _json_scalar_type_name(parsed: Any) -> str:
        """Type label for a rejected non-object JSON value (mirrors npm)."""
        if isinstance(parsed, list):
            return "list"
        if parsed is None:
            return "null"
        return type(parsed).__name__

    def _parse_response(self, response: Any) -> Dict[str, Any]:
        """Parse response into a standard format."""
        if isinstance(response, dict):
            return response
        elif isinstance(response, str):
            # Try to parse as JSON
            try:
                parsed = json.loads(response)
            except json.JSONDecodeError:
                return {"type": "text", "content": response}
            # JSON scalars/arrays are rejected like direct non-dict inputs
            # (Sentry HIGH, PR #34): an array payload bypasses per-item
            # inspection, so its content would verify without ever being
            # checked. Mirrors npm parseResponse.
            if not isinstance(parsed, dict):
                raise ValueError(
                    f"Cannot parse JSON response of type "
                    f"{self._json_scalar_type_name(parsed)}. Expected object."
                )
            return parsed
        elif hasattr(response, "model_dump"):
            # Pydantic model
            return response.model_dump()
        elif hasattr(response, "dict"):
            # Older pydantic
            return response.dict()
        else:
            raise ValueError(
                f"Cannot parse response of type {type(response).__name__}. "
                "Expected dict, str, or Pydantic model."
            )


# Import guards for type hints
from .guards.base import BaseGuard
