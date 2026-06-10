from typing import Any, Dict
from .base import BaseGuard, GuardResult


class TaxGuard(BaseGuard):
    name = "TaxGuard"
    description = "Verifies LLM tool calls against deterministic tax laws"

    def __init__(self):
        super().__init__()
        try:
            from qwed_tax.verifier import TaxVerifier

            self.engine = TaxVerifier()
        except ImportError as err:
            raise ImportError(
                "qwed-tax is required. Install with: pip install qwed-open-responses[tax]"
            ) from err

    def check(
        self, response: Dict[str, Any], context: dict | None = None
    ) -> GuardResult:
        if not isinstance(response, dict):
            return self.fail_result(
                f"Invalid response type: expected dict, got {type(response).__name__}"
            )
        tool_name = response.get("tool_name", "")
        arguments = response.get("arguments", {})
        return self.verify_tool_call(tool_name, arguments)

    def verify_tool_call(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> GuardResult:
        if tool_name == "process_payroll":
            return self._verify_payroll(arguments)

        elif tool_name == "send_international_wire":
            from qwed_tax.jurisdictions.india.remittance_guard import RemittanceGuard

            guard = RemittanceGuard()
            result = guard.verify_lrs_limit(
                amount_usd=arguments.get("amount_usd", 0),
                purpose=arguments.get("purpose", ""),
                financial_year_usage=arguments.get("ytd_usage", 0),
            )
            if not result.verified:
                return self.fail_result(result.message)
            return self.pass_result()

        elif tool_name == "calculate_crypto_tax":
            from qwed_tax.jurisdictions.india.crypto_guard import CryptoTaxGuard

            guard = CryptoTaxGuard()
            result = guard.verify_set_off(
                losses=arguments.get("losses", {}), gains=arguments.get("gains", {})
            )
            if not result.verified:
                return self.fail_result(result.message)
            return self.pass_result()

        return self.fail_result(f"No tax guard for tool: {tool_name}")

    def _verify_payroll(self, arguments: Dict[str, Any]) -> GuardResult:
        if not isinstance(arguments, dict):
            return self.fail_result("Invalid payroll arguments: expected object")

        required = ["gross_ytd", "claimed_tax"]
        missing = [f for f in required if f not in arguments]
        if missing:
            return self.fail_result(
                f"Missing required payroll fields: {', '.join(missing)}"
            )

        from qwed_tax.jurisdictions.us.payroll_guard import PayrollGuard

        guard = PayrollGuard()
        result = guard.verify_fica_tax(
            gross_ytd=arguments["gross_ytd"],
            current=arguments.get("current", 0),
            claimed_tax=arguments["claimed_tax"],
        )
        if not result.verified:
            return self.fail_result(result.message)
        return self.pass_result()
