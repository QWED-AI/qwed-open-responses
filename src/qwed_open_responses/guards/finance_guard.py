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
        if not isinstance(response, dict):
            return self.fail_result(
                f"Invalid response type: expected dict, got {type(response).__name__}"
            )
        ctx = self._resolve_context(context, response)
        return self.verify_output(ctx, response)

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

    def _verify_npv(self, content: Dict[str, Any]) -> GuardResult:
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
            if hasattr(result, "message"):
                message = result.message
            else:
                diff = getattr(result, "difference", None)
                computed = getattr(result, "computed_value", None)
                llm_val = getattr(result, "llm_value", None)
                parts = []
                if diff is not None:
                    parts.append(f"difference={diff}")
                if computed is not None:
                    parts.append(f"computed={computed}")
                if llm_val is not None:
                    parts.append(f"llm_val={llm_val}")
                if parts:
                    message = f"NPV verification failed ({'; '.join(parts)})"
        if not verified:
            return self.fail_result(message)
        return self.pass_result()

    def verify_output(self, context: str, content: Dict[str, Any]) -> GuardResult:
        if "cashflows" in content and "npv" in content:
            return self._verify_npv(content)

        if context == "payment_instruction":
            raise NotImplementedError(
                "ISO verification for payment_instruction not implemented"
            )

        return self.fail_result(f"Unrecognized finance context: {context}")
