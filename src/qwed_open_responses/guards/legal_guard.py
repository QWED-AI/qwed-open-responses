from typing import Dict, Any, List, Optional

class LegalGuard:
    def __init__(self):
        try:
            # Lazy imports from the qwed-legal ecosystem
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

    def verify_contract_review(self, contract_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verifies AI-generated contract analysis or drafted clauses.
        Input schema expected: {
            "type": "NDA",
            "jurisdiction": "CA",
            "clauses": [{"type": "non_compete", "text": "..."}],
            "parties": ["..."],
            "term_years": 10,
            "governing_law": "California",
            "forum": "San Francisco"
        }
        """
        report = {"verified": True, "flags": []}

        # 1. Jurisdiction Conflict Check
        # Source: QWED-Legal v0.2.0 Spec
        if "governing_law" in contract_data and "forum" in contract_data:
            j_check = self.jurisdiction_engine.verify_choice_of_law(
                governing_law=contract_data["governing_law"],
                forum_location=contract_data["forum"]
            )
            if not j_check.get("verified", True): # Adapting to likely return type
                report["verified"] = False
                report["flags"].append(j_check.get("risk", "Jurisdiction Mismatch"))

        # 2. Prohibited Clause Check (Public Policy)
        # Example: Non-Competes are largely void in California (Cal. B&P Code 16600)
        jurisdiction = contract_data.get("jurisdiction", "").upper()
        clauses = contract_data.get("clauses", [])
        
        # Simple structured clause iteration
        for clause in clauses:
            c_type = clause.get("type", "")
            if c_type == "non_compete" and ("CA" in jurisdiction or "CALIFORNIA" in jurisdiction):
                report["verified"] = False
                report["flags"].append(
                    "PROHIBITED_CLAUSE: Non-compete clauses are unenforceable in California."
                )

        # 3. Contract Completeness (Missing Essentials)
        required_clauses = ["termination", "governing_law", "force_majeure"]
        present_types = [c.get("type") for c in clauses]
        missing = [req for req in required_clauses if req not in present_types]
        
        if missing:
            # Soft flag (Warning) rather than Block
            report["flags"].append(f"COMPLETENESS_WARNING: Missing standard clauses: {missing}")

        # 4. Reasonableness Check (The 10-Year NDA Test)
        if contract_data.get("type") == "NDA" and contract_data.get("term_years", 0) > 5:
             report["verified"] = False
             report["flags"].append(
                 f"UNREASONABLE_TERM: {contract_data['term_years']} year term for NDA exceeds standard commercial practice (typically 2-5 years)."
             )

        return report
