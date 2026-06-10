from typing import Any, Dict, Optional, Union
from .base import BaseGuard, GuardResult


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
        self, response: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> GuardResult:
        content = response if isinstance(response, dict) else {}
        ctx = self._resolve_context(context, content)
        return self.verify_output(ctx, content)

    def _resolve_context(
        self,
        context: Optional[Union[str, Dict[str, Any]]],
        content: Dict[str, Any],
    ) -> str:
        if isinstance(context, str):
            return context
        if isinstance(context, dict):
            ctx = context.get("context", "")
            if ctx:
                return ctx
        return content.get("context", content.get("type", ""))

    def verify_output(self, context: str, content: Dict[str, Any]) -> GuardResult:
        if "cashflows" in content and "npv" in content:
            result = self.math_engine.verify_npv(
                cashflows=content["cashflows"],
                rate=content.get("discount_rate", 0.0),
                llm_output=content["npv"],
            )
            verified = False
            message = "NPV verification failed"
            if isinstance(result, dict):
                verified = result.get("verified", False)
                message = result.get("message", message)
            elif hasattr(result, "verified"):
                verified = result.verified
                message = getattr(result, "message", message)
            if not verified:
                return self.fail_result(message)
            return self.pass_result()

        if context == "payment_instruction":
            return self.fail_result(
                "ISO verification not available (install with: pip install qwed-open-responses[finance])"
            )

        return self.fail_result(f"Unrecognized finance context: {context}")
