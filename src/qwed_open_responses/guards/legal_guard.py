from __future__ import annotations

from typing import Any, Dict, List
from .base import BaseGuard, GuardResult

_US_STATE_ABBREVIATIONS = frozenset(
    {
        "AL",
        "AK",
        "AZ",
        "AR",
        "CA",
        "CO",
        "CT",
        "DE",
        "FL",
        "GA",
        "HI",
        "ID",
        "IL",
        "IN",
        "IA",
        "KS",
        "KY",
        "LA",
        "ME",
        "MD",
        "MA",
        "MI",
        "MN",
        "MS",
        "MO",
        "MT",
        "NE",
        "NV",
        "NH",
        "NJ",
        "NM",
        "NY",
        "NC",
        "ND",
        "OH",
        "OK",
        "OR",
        "PA",
        "RI",
        "SC",
        "SD",
        "TN",
        "TX",
        "UT",
        "VT",
        "VA",
        "WA",
        "WV",
        "WI",
        "WY",
        "DC",
        "AS",
        "GU",
        "MP",
        "PR",
        "VI",
    }
)

_US_STATE_NAMES = frozenset(
    {
        "ALABAMA",
        "ALASKA",
        "ARIZONA",
        "ARKANSAS",
        "CALIFORNIA",
        "COLORADO",
        "CONNECTICUT",
        "DELAWARE",
        "FLORIDA",
        "GEORGIA",
        "HAWAII",
        "IDAHO",
        "ILLINOIS",
        "INDIANA",
        "IOWA",
        "KANSAS",
        "KENTUCKY",
        "LOUISIANA",
        "MAINE",
        "MARYLAND",
        "MASSACHUSETTS",
        "MICHIGAN",
        "MINNESOTA",
        "MISSISSIPPI",
        "MISSOURI",
        "MONTANA",
        "NEBRASKA",
        "NEVADA",
        "NEW HAMPSHIRE",
        "NEW JERSEY",
        "NEW MEXICO",
        "NEW YORK",
        "NORTH CAROLINA",
        "NORTH DAKOTA",
        "OHIO",
        "OKLAHOMA",
        "OREGON",
        "PENNSYLVANIA",
        "RHODE ISLAND",
        "SOUTH CAROLINA",
        "SOUTH DAKOTA",
        "TENNESSEE",
        "TEXAS",
        "UTAH",
        "VERMONT",
        "VIRGINIA",
        "WASHINGTON",
        "WEST VIRGINIA",
        "WISCONSIN",
        "WYOMING",
        "DISTRICT OF COLUMBIA",
    }
)

JURISDICTION_MISMATCH = "Jurisdiction Mismatch"


def _normalize_country(code: str) -> str:
    if not isinstance(code, str):
        return ""
    normalized = code.strip().upper()
    if not normalized:
        return ""
    if normalized in _US_STATE_NAMES or normalized in _US_STATE_ABBREVIATIONS:
        return "US"
    return normalized


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

    def _check_jurisdiction(
        self, contract_data: Dict[str, Any]
    ) -> tuple[str | None, list[str]]:
        warnings: list[str] = []
        if "governing_law" not in contract_data or "forum" not in contract_data:
            return None, warnings
        parties_raw = contract_data.get("parties_countries")
        if not isinstance(parties_raw, (list, tuple)):
            parties_raw = [_normalize_country(contract_data.get("jurisdiction", ""))]
        parties = [p for p in parties_raw if p]
        if not parties:
            warnings.append(
                "Jurisdiction check skipped (missing party country information)"
            )
            return None, warnings
        try:
            j_check = self.jurisdiction_engine.verify_choice_of_law(
                parties_countries=parties,
                governing_law=contract_data["governing_law"],
                forum=contract_data["forum"],
            )
        except Exception:
            warnings.append("Jurisdiction check skipped: internal error (API mismatch)")
            return None, warnings
        if isinstance(j_check, dict):
            if not j_check.get("verified", True):
                return j_check.get("risk", JURISDICTION_MISMATCH), warnings
            return None, warnings
        if hasattr(j_check, "conflicts"):
            j_warnings = getattr(j_check, "warnings", [])
            if isinstance(j_warnings, list):
                warnings.extend(j_warnings)
            if j_check.conflicts:
                return getattr(j_check, "message", JURISDICTION_MISMATCH), warnings
            return None, warnings
        if not getattr(j_check, "verified", True):
            return JURISDICTION_MISMATCH, warnings
        return None, warnings

    def _check_prohibited_clauses(
        self, clauses: List[Dict[str, Any]], jurisdiction: str
    ) -> List[str]:
        flags = []
        for clause in clauses:
            if not isinstance(clause, dict):
                continue
            c_type = clause.get("type", "")
            if c_type == "non_compete" and jurisdiction in ("CA", "CALIFORNIA"):
                flags.append(
                    "PROHIBITED_CLAUSE: Non-compete clauses are unenforceable in California."
                )
        return flags

    def _check_missing_clauses(self, clauses: List[Dict[str, Any]]) -> List[str]:
        required_clauses = ["termination", "governing_law", "force_majeure"]
        present_types = [c.get("type") for c in clauses if isinstance(c, dict)]
        missing = [req for req in required_clauses if req not in present_types]
        if missing:
            return [f"COMPLETENESS_WARNING: Missing standard clauses: {missing}"]
        return []

    def _check_nda_terms(self, contract_data: Dict[str, Any]) -> str | None:
        term_years = contract_data.get("term_years")
        if (
            contract_data.get("type") == "NDA"
            and isinstance(term_years, (int, float))
            and term_years > 5
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

        j_flag, j_warnings = self._check_jurisdiction(contract_data)
        if j_flag:
            hard_flags.append(j_flag)
        warnings_list.extend(j_warnings)

        j_val = contract_data.get("jurisdiction")
        jurisdiction = j_val.strip().upper() if isinstance(j_val, str) else ""
        clauses = contract_data.get("clauses") or []

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
                "; ".join(warnings_list), details={"warnings": warnings_list}
            )

        return self.pass_result()
