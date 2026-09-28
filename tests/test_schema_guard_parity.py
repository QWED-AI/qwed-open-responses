import json
from pathlib import Path

import pytest

from qwed_open_responses import SchemaGuard


PARITY_CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "schema_guard_parity.json").read_text(
        encoding="utf-8"
    )
)


@pytest.mark.parametrize("case", PARITY_CASES, ids=lambda case: case["name"])
def test_python_schema_guard_matches_shared_validation_cases(case):
    result = SchemaGuard(
        schema=case["schema"],
        allow_additional_properties=case.get("allowAdditionalProperties", False),
    ).check({"output": case["data"]})

    assert result.passed is case["expected"]
