from typing import Dict, Any, Optional


class TaxGuard:
    def __init__(self):
        try:
            # Lazy import to enforce optional dependency
            from qwed_tax.verifier import TaxVerifier

            self.engine = TaxVerifier()
        except ImportError:
            raise ImportError(
                "qwed-tax is required. Install with: pip install qwed-open-responses[tax]"
            )

    def verify_tool_call(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Intercepts LLM tool calls (e.g., 'process_payroll', 'send_remittance')
        and verifies them against deterministic tax laws.
        """

        # 1. Payroll & Withholding (FICA/IRS)
        if tool_name == "process_payroll":
            # Assuming facade methods or direct guard access
            # For now, we stub the logic map based on qwed-tax capabilities
            # Ideally qwed-tax exposes a clean verification API for these arguments
            return self._verify_payroll(arguments)

        # 2. International Remittance (LRS Limits - The "Gambling" Trap)
        elif tool_name == "send_international_wire":
            # Use RemittanceGuard from qwed-tax
            from qwed_tax.jurisdictions.india.remittance_guard import RemittanceGuard

            guard = RemittanceGuard()
            result = guard.verify_lrs_limit(
                amount_usd=arguments.get("amount_usd", 0),
                purpose=arguments.get("purpose", ""),
                financial_year_usage=arguments.get("ytd_usage", 0),
            )
            return {
                "verified": result.verified,
                "error": result.message if not result.verified else None,
            }

        # 3. Crypto Tax (Loss Set-Off Rules)
        elif tool_name == "calculate_crypto_tax":
            from qwed_tax.jurisdictions.india.crypto_guard import CryptoTaxGuard

            guard = CryptoTaxGuard()
            result = guard.verify_set_off(
                losses=arguments.get("losses", {}), gains=arguments.get("gains", {})
            )
            return {
                "verified": result.verified,
                "error": result.message if not result.verified else None,
            }

        return {"verified": False, "error": f"No tax guard for tool: {tool_name}"}

    def _verify_payroll(self, arguments):
        if not isinstance(arguments, dict):
            return {
                "verified": False,
                "error": "Invalid payroll arguments: expected object",
            }

        required = ["gross_ytd", "claimed_tax"]
        missing = [f for f in required if f not in arguments]
        if missing:
            return {
                "verified": False,
                "error": f"Missing required payroll fields: {', '.join(missing)}",
            }

        from qwed_tax.jurisdictions.us.payroll_guard import PayrollGuard

        guard = PayrollGuard()
        result = guard.verify_fica_tax(
            gross_ytd=arguments["gross_ytd"],
            current=arguments.get("current", 0),
            claimed_tax=arguments["claimed_tax"],
        )
        return {
            "verified": result.verified,
            "error": result.message if not result.verified else None,
        }
