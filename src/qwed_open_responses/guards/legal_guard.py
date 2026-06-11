from __future__ import annotations

from typing import Any, Dict, List
from .base import BaseGuard, GuardResult


class LegalGuard(BaseGuard):
    name = "LegalGuard"
    description = "Verifies AI-generated contract analysis against legal rules"

    def __init__(self):
        super().__init__()
        try:
            from qwed_legal.guards.jurisdiction_guard import JurisdictionGuard
            from qwed_legal.guards.clause_guard import ClauseGuard
            from qwed_legal.guards.deadline_guard import DeadlineGuard

            self.jurisdiction_engine = JurisdictionGuard()
            self.clause_engine = ClauseGuard()
            self.deadline_engine = DeadlineGuard()
        except ImportError as err:
            raise ImportError(
                "qwed-legal is required. Install with: pip install qwed-open-responses[legal]"
            ) from err

    def check(
        self,
        response: Dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> GuardResult:
        if not isinstance(response, dict):
            return self.fail_result(
                f"Invalid response type: expected dict, got {type(response).__name__}"
            )
        return self.verify_contract_review(response)

    def _check_jurisdiction(self, contract_data: Dict[str, Any]) -> str | None:
        if "governing_law" not in contract_data or "forum" not in contract_data:
            return None
        parties = contract_data.get(
            "parties_countries", [contract_data.get("jurisdiction", "")]
        )
        j_check = self.jurisdiction_engine.verify_choice_of_law(
            parties_countries=parties,
            governing_law=contract_data["governing_law"],
            forum=contract_data["forum"],
        )
        verified = (
            j_check.get("verified", True)
            if isinstance(j_check, dict)
            else getattr(j_check, "verified", True)
        )
        if verified:
            return None
        if isinstance(j_check, dict):
            return j_check.get("risk", "Jurisdiction Mismatch")
        return getattr(j_check, "message", "Jurisdiction Mismatch")

    def _check_prohibited_clauses(
        self, clauses: List[Dict[str, Any]], jurisdiction: str
    ) -> List[str]:
        flags = []
        for clause in clauses:
            c_type = clause.get("type", "")
            if c_type == "non_compete" and (
                "CA" in jurisdiction or "CALIFORNIA" in jurisdiction
            ):
                flags.append(
                    "PROHIBITED_CLAUSE: Non-compete clauses are unenforceable in California."
                )
        return flags

    def _check_missing_clauses(self, clauses: List[Dict[str, Any]]) -> List[str]:
        required_clauses = ["termination", "governing_law", "force_majeure"]
        present_types = [c.get("type") for c in clauses]
        missing = [req for req in required_clauses if req not in present_types]
        if missing:
            return [f"COMPLETENESS_WARNING: Missing standard clauses: {missing}"]
        return []

    def _check_nda_terms(self, contract_data: Dict[str, Any]) -> str | None:
        if (
            contract_data.get("type") == "NDA"
            and contract_data.get("term_years", 0) > 5
        ):
            return (
                f"UNREASONABLE_TERM: {contract_data['term_years']} year term for NDA "
                "exceeds standard commercial practice (typically 2-5 years)."
            )
        return None

    def verify_contract_review(
        self,
        contract_data: Dict[str, Any],
        _context: dict[str, Any] | None = None,
    ) -> GuardResult:
        hard_flags = []
        warnings_list = []

        j_flag = self._check_jurisdiction(contract_data)
        if j_flag:
            hard_flags.append(j_flag)

        jurisdiction = contract_data.get("jurisdiction", "").upper()
        clauses = contract_data.get("clauses", [])

        hard_flags.extend(self._check_prohibited_clauses(clauses, jurisdiction))
        warnings_list.extend(self._check_missing_clauses(clauses))

        nda_flag = self._check_nda_terms(contract_data)
        if nda_flag:
            hard_flags.append(nda_flag)

        if hard_flags:
            details: Dict[str, Any] = {"flags": hard_flags}
            if warnings_list:
                details["warnings"] = warnings_list
            return self.fail_result("; ".join(hard_flags), details=details)

        if warnings_list:
            return self.warn_result(
                "; ".join(warnings_list), details={"flags": warnings_list}
            )

        return self.pass_result()
