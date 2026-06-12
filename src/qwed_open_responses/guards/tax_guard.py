from __future__ import annotations

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
        self, response: Dict[str, Any], context: dict[str, Any] | None = None
    ) -> GuardResult:
        if not isinstance(response, dict):
            return self.fail_result(
                f"Invalid response type: expected dict, got {type(response).__name__}"
            )
        tool_name = response.get("tool_name", "")
        arguments = response.get("arguments", {})
        return self.verify_tool_call(tool_name, arguments)

    def _check_result(self, result: Any, default_error: str) -> GuardResult:
        verified = result["verified"] if isinstance(result, dict) else result.verified
        if not verified:
            msg = (
                result.get("error", default_error)
                if isinstance(result, dict)
                else getattr(result, "message", default_error)
            )
            if msg is None:
                msg = default_error
            return self.fail_result(msg)
        return self.pass_result()

    def verify_tool_call(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> GuardResult:
        if not isinstance(arguments, dict):
            return self.fail_result("Invalid arguments: expected object")
        if tool_name == "process_payroll":
            return self._verify_payroll(arguments)
        if tool_name == "send_international_wire":
            return self._verify_international_wire(arguments)
        if tool_name == "calculate_crypto_tax":
            return self._verify_crypto_tax(arguments)
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
        return self._check_result(result, "FICA tax verification failed")

    def _verify_international_wire(self, arguments: Dict[str, Any]) -> GuardResult:
        from qwed_tax.guards.remittance_guard import RemittanceGuard

        guard = RemittanceGuard()
        result = guard.verify_lrs_limit(
            amount_usd=arguments.get("amount_usd", 0),
            purpose=arguments.get("purpose", ""),
            financial_year_usage=arguments.get("ytd_usage", 0),
        )
        return self._check_result(result, "LRS limit exceeded")

    def _verify_crypto_tax(self, arguments: Dict[str, Any]) -> GuardResult:
        from qwed_tax.jurisdictions.india.guards.crypto_guard import CryptoTaxGuard

        guard = CryptoTaxGuard()
        result = guard.verify_set_off(
            losses=arguments.get("losses", {}), gains=arguments.get("gains", {})
        )
        return self._check_result(result, "Set-off limit breached")
