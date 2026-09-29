import json
from pathlib import Path

import jsonschema
import pytest

from qwed_open_responses import SchemaGuard
from qwed_open_responses.guards import schema_guard as schema_guard_module


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


@pytest.mark.parametrize(
    ("timestamp", "uri", "expected"),
    [
        ("2026-09-29T12:00:00Z", "https://example.com/path", True),
        ("2026-13-40T99:99:99Z", "https://example.com/path", False),
        ("2026-09-29T12:00:00Z", "not a uri", False),
    ],
)
def test_date_time_and_uri_formats_do_not_depend_on_optional_checkers(
    monkeypatch, timestamp, uri, expected
):
    monkeypatch.setattr(schema_guard_module.jsonschema.FormatChecker, "checkers", {})
    monkeypatch.setattr(
        schema_guard_module.jsonschema.Draft7Validator.FORMAT_CHECKER,
        "checkers",
        {},
    )
    guard = SchemaGuard(
        schema={
            "type": "object",
            "properties": {
                "timestamp": {"type": "string", "format": "date-time"},
                "uri": {"type": "string", "format": "uri"},
            },
        }
    )

    result = guard.check({"output": {"timestamp": timestamp, "uri": uri}})

    assert result.passed is expected
