from typing import Any, Dict, List, Optional
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
        except ImportError:
            raise ImportError(
                "qwed-legal is required. Install with: pip install qwed-open-responses[legal]"
            )

    def check(
        self, response: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> GuardResult:
        return self.verify_contract_review(response)

    def verify_contract_review(self, contract_data: Dict[str, Any]) -> GuardResult:
        flags = []

        if "governing_law" in contract_data and "forum" in contract_data:
            j_check = self.jurisdiction_engine.verify_choice_of_law(
                governing_law=contract_data["governing_law"],
                forum_location=contract_data["forum"],
            )
            if not j_check.get("verified", True):
                flags.append(j_check.get("risk", "Jurisdiction Mismatch"))

        jurisdiction = contract_data.get("jurisdiction", "").upper()
        clauses = contract_data.get("clauses", [])

        for clause in clauses:
            c_type = clause.get("type", "")
            if c_type == "non_compete" and (
                "CA" in jurisdiction or "CALIFORNIA" in jurisdiction
            ):
                flags.append(
                    "PROHIBITED_CLAUSE: Non-compete clauses are unenforceable in California."
                )

        required_clauses = ["termination", "governing_law", "force_majeure"]
        present_types = [c.get("type") for c in clauses]
        missing = [req for req in required_clauses if req not in present_types]
        if missing:
            flags.append(
                f"COMPLETENESS_WARNING: Missing standard clauses: {missing}"
            )

        if (
            contract_data.get("type") == "NDA"
            and contract_data.get("term_years", 0) > 5
        ):
            flags.append(
                f"UNREASONABLE_TERM: {contract_data['term_years']} year term for NDA "
                "exceeds standard commercial practice (typically 2-5 years)."
            )

        if flags:
            return self.fail_result("; ".join(flags), details={"flags": flags})
        return self.pass_result()
