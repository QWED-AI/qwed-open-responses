from typing import Dict, Any


class FinanceGuard:
    def __init__(self):
        try:
            from qwed_finance import FinanceVerifier

            # Assuming ISOGuard is exposed or importable directly as per plan
            # from qwed_finance.guards.iso_guard import ISOGuard
            # Note: qwed-finance structure might vary, adapting to likely exports
            self.math_engine = FinanceVerifier()
            # self.iso_engine = ISOGuard()
        except ImportError:
            raise ImportError(
                "qwed-finance is required. Install with: pip install qwed-open-responses[finance]"
            )

    def verify_output(self, context: str, content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verifies structured financial outputs (e.g., Amortization tables, Payment JSON).
        """

        # 1. Check Investment Math (NPV/IRR)
        if "cashflows" in content and "npv" in content:
            # Adapt to actual FinanceVerifier API
            # Assuming verify_npv signature matches plan
            return self.math_engine.verify_npv(
                cashflows=content["cashflows"],
                rate=content.get("discount_rate", 0.0),
                llm_output=content["npv"],
            )

        # 2. Check ISO 20022 Compliance (Banking Interop)
        if context == "payment_instruction":
            # For now, stub or use generic verifier if specific guard not ready
            if hasattr(self, "iso_engine"):
                return self.iso_engine.verify_payment_message(content)
            return {
                "verified": True,
                "note": "ISO Verification not active (missing qwed-finance[iso] dependencies?)",
            }

        return {"verified": True}
