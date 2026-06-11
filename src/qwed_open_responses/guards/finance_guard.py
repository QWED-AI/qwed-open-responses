from __future__ import annotations

from typing import Any, Dict
from .base import BaseGuard, GuardResult

NPV_VERIFICATION_FAILED = "NPV verification failed"


class FinanceGuard(BaseGuard):
    name = "FinanceGuard"
    description = "Verifies structured financial outputs against deterministic rules"

    def __init__(self):
        super().__init__()
        try:
            from qwed_finance import FinanceVerifier

            self.math_engine = FinanceVerifier()
        except ImportError as err:
            raise ImportError(
                "qwed-finance is required. Install with: pip install qwed-open-responses[finance]"
            ) from err

    def check(
        self, response: Dict[str, Any], context: dict[str, Any] | None = None
    ) -> GuardResult:
        if not isinstance(response, dict):
            return self.fail_result(
                f"Invalid response type: expected dict, got {type(response).__name__}"
            )
        ctx = self._resolve_context(context, response)
        return self.verify_output(ctx, response)

    def _resolve_context(
        self,
        context: str | dict[str, Any] | None,
        content: Dict[str, Any],
    ) -> str:
        if isinstance(context, str):
            return context
        if isinstance(context, dict):
            ctx = context.get("context", context.get("type", ""))
            if ctx:
                return ctx
        return content.get("context", content.get("type", ""))

    def _build_npv_failure_message(self, result: Any) -> str:
        if hasattr(result, "message") and result.message is not None:
            return result.message
        parts = []
        for attr, label in [
            ("difference", "difference"),
            ("computed_value", "computed"),
            ("llm_value", "llm_val"),
        ]:
            val = getattr(result, attr, None)
            if val is not None:
                parts.append(f"{label}={val}")
        if parts:
            return f"{NPV_VERIFICATION_FAILED} ({'; '.join(parts)})"
        return NPV_VERIFICATION_FAILED

    def _verify_npv(self, content: Dict[str, Any]) -> GuardResult:
        result = self.math_engine.verify_npv(
            cashflows=content["cashflows"],
            rate=content.get("discount_rate", 0.0),
            llm_output=content["npv"],
        )
        if isinstance(result, dict):
            if not result.get("verified", False):
                return self.fail_result(result.get("message", NPV_VERIFICATION_FAILED))
            return self.pass_result()
        if hasattr(result, "verified") and not result.verified:
            return self.fail_result(self._build_npv_failure_message(result))
        if hasattr(result, "verified") and result.verified:
            return self.pass_result()
        return self.fail_result(NPV_VERIFICATION_FAILED)

    def verify_output(self, context: str, content: Dict[str, Any]) -> GuardResult:
        has_cashflows = "cashflows" in content
        has_npv = "npv" in content

        if context == "payment_instruction":
            return self.fail_result(
                "ISO verification for payment_instruction not implemented"
            )

        if has_cashflows and has_npv:
            return self._verify_npv(content)

        if has_cashflows and not has_npv:
            return self.fail_result("Missing required field: 'npv' for NPV calculation")
        if has_npv and not has_cashflows:
            return self.fail_result(
                "Missing required field: 'cashflows' for NPV calculation"
            )

        return self.fail_result(f"Unrecognized finance context: {context}")
