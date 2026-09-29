"""
Schema Guard - Validates AI response against JSON Schema.

Ensures structured outputs match the expected schema.
"""

from datetime import datetime
import re
from typing import Any, Dict, Optional, List, Set, Tuple
from urllib.parse import unquote, urlsplit
import uuid
from .base import BaseGuard, GuardResult

try:
    import jsonschema

    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def _is_valid_uuid_format(value: Any) -> bool:
    if not isinstance(value, str):
        return True

    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False

    canonical_value = str(parsed)
    normalized_value = value.lower()
    return normalized_value in (
        canonical_value,
        f"urn:uuid:{canonical_value}",
    )


_DATE_TIME_FORMAT = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
_URI_INVALID_CHARACTERS = re.compile(r"[^\x21-\x7e]|[<>\"{}|\\^`]")
_URI_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def _is_valid_date_time_format(value: Any) -> bool:
    if not isinstance(value, str):
        return True

    if not _DATE_TIME_FORMAT.fullmatch(value):
        return False

    normalized_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(normalized_value)
    except ValueError:
        return False
    return True


def _is_valid_uri_format(value: Any) -> bool:
    if not isinstance(value, str):
        return True

    if _URI_INVALID_CHARACTERS.search(value) or _URI_INVALID_PERCENT_ESCAPE.search(
        value
    ):
        return False

    try:
        parsed_value = urlsplit(value)
        parsed_value.port
    except ValueError:
        return False
    return bool(parsed_value.scheme)


def _resolve_local_schema_reference(
    root_schema: Dict[str, object], reference: str
) -> Optional[object]:
    if reference == "#":
        return root_schema
    if not reference.startswith("#/"):
        return None

    referenced_schema: object = root_schema
    for token in reference[2:].split("/"):
        token = unquote(token).replace("~1", "/").replace("~0", "~")
        if not isinstance(referenced_schema, dict) or token not in referenced_schema:
            return None
        referenced_schema = referenced_schema[token]
    return referenced_schema


def _collect_root_object_fields(
    root_schema: Dict[str, object],
) -> Tuple[Set[str], Set[str], bool, bool]:
    property_names: Set[str] = set()
    pattern_names: Set[str] = set()
    visited_schema_ids: Set[int] = set()
    visited_references: Set[str] = set()
    declares_object = False
    references_resolved = True

    def visit(schema: object) -> None:
        nonlocal declares_object, references_resolved
        if not isinstance(schema, dict) or id(schema) in visited_schema_ids:
            return
        visited_schema_ids.add(id(schema))

        schema_type = schema.get("type")
        properties = schema.get("properties")
        pattern_properties = schema.get("patternProperties")
        if (
            schema_type == "object"
            or (isinstance(schema_type, list) and "object" in schema_type)
            or "properties" in schema
            or "patternProperties" in schema
        ):
            declares_object = True

        if isinstance(properties, dict):
            property_names.update(name for name in properties if isinstance(name, str))
        if isinstance(pattern_properties, dict):
            pattern_names.update(
                name for name in pattern_properties if isinstance(name, str)
            )

        reference = schema.get("$ref")
        if isinstance(reference, str) and reference not in visited_references:
            visited_references.add(reference)
            referenced_schema = _resolve_local_schema_reference(root_schema, reference)
            if referenced_schema is None:
                references_resolved = False
            else:
                visit(referenced_schema)

        for keyword in ("allOf", "anyOf", "oneOf"):
            branches = schema.get(keyword)
            if isinstance(branches, list):
                for branch in branches:
                    visit(branch)

        for keyword in ("if", "then", "else"):
            visit(schema.get(keyword))

        dependencies = schema.get("dependencies")
        if isinstance(dependencies, dict):
            for dependency in dependencies.values():
                if isinstance(dependency, dict):
                    visit(dependency)

    visit(root_schema)
    return property_names, pattern_names, declares_object, references_resolved


class SchemaGuard(BaseGuard):
    """
    Validates that AI responses match a JSON Schema.

    Usage:
        guard = SchemaGuard(schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer", "minimum": 0}
            },
            "required": ["name", "age"]
        })

        result = guard.check({"name": "John", "age": 30})  # Passes
        result = guard.check({"name": "John", "age": -5})  # Fails (age < 0)
    """

    name = "SchemaGuard"
    description = "Validates response against JSON Schema"

    def __init__(
        self,
        schema: Dict[str, Any],
        strict: bool = True,
        allow_additional_properties: bool = False,
    ):
        """
        Initialize SchemaGuard.

        Args:
            schema: JSON Schema to validate against
            strict: If True, fail on any schema violation
            allow_additional_properties: If True, do not add a default
                ``additionalProperties: false`` constraint. Explicit schema
                keywords always take precedence.
        """
        if not HAS_JSONSCHEMA:
            raise ImportError(
                "jsonschema is required for SchemaGuard. "
                "Install with: pip install jsonschema"
            )

        validator_schema = schema.copy()
        (
            property_names,
            pattern_names,
            declares_object,
            references_resolved,
        ) = _collect_root_object_fields(validator_schema)
        root_all_of = validator_schema.get("allOf")
        root_reference_can_be_rewritten = (
            "$ref" not in validator_schema
            or "allOf" not in validator_schema
            or isinstance(root_all_of, list)
        )
        if (
            not allow_additional_properties
            and declares_object
            and references_resolved
            and root_reference_can_be_rewritten
            and "additionalProperties" not in validator_schema
        ):
            root_reference = validator_schema.pop("$ref", None)
            if isinstance(root_reference, str):
                validator_schema["allOf"] = [
                    {"$ref": root_reference},
                    *(root_all_of if isinstance(root_all_of, list) else []),
                ]

            root_properties = validator_schema.get("properties")
            if "properties" not in validator_schema or isinstance(
                root_properties, dict
            ):
                root_properties = dict(root_properties or {})
                for property_name in property_names:
                    root_properties.setdefault(property_name, {})
                if root_properties:
                    validator_schema["properties"] = root_properties

            root_patterns = validator_schema.get("patternProperties")
            if "patternProperties" not in validator_schema or isinstance(
                root_patterns, dict
            ):
                root_patterns = dict(root_patterns or {})
                for pattern_name in pattern_names:
                    root_patterns.setdefault(pattern_name, {})
                if root_patterns:
                    validator_schema["patternProperties"] = root_patterns

            validator_schema["additionalProperties"] = False

        self.schema = validator_schema
        self.strict = strict
        self.allow_additional_properties = allow_additional_properties

        format_checker = jsonschema.FormatChecker()
        format_checker.checks("uuid", raises=(ValueError, TypeError, AttributeError))(
            _is_valid_uuid_format
        )
        format_checker.checks("date-time", raises=(ValueError, TypeError))(
            _is_valid_date_time_format
        )
        format_checker.checks("uri", raises=(ValueError, TypeError))(
            _is_valid_uri_format
        )

        self.validator = jsonschema.Draft7Validator(
            validator_schema, format_checker=format_checker
        )

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Validate response against schema."""

        # Get the actual output to validate
        if "output" in response:
            data = response["output"]
        elif "content" in response:
            data = response["content"]
        else:
            data = response

        # Collect all errors
        errors: List[str] = []
        for error in self.validator.iter_errors(data):
            errors.append(f"{error.json_path}: {error.message}")

        if errors:
            return self.fail_result(
                message=f"Schema validation failed: {len(errors)} error(s)",
                details={
                    "errors": errors[:10],  # Limit to first 10
                    "total_errors": len(errors),
                },
            )

        return self.pass_result(
            message="Schema validation passed",
            details={"schema_valid": True},
        )


class RequiredFieldsGuard(BaseGuard):
    """
    Ensures specific fields are present in the response.

    Usage:
        guard = RequiredFieldsGuard(fields=["name", "email", "address"])
    """

    name = "RequiredFieldsGuard"
    description = "Checks for required fields"

    def __init__(self, fields: List[str]):
        """
        Args:
            fields: List of field names that must be present
        """
        self.required_fields = fields

    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Check for required fields."""

        data = response.get("output", response)

        if not isinstance(data, dict):
            return self.fail_result("Response is not a dictionary")

        missing = [f for f in self.required_fields if f not in data]

        if missing:
            return self.fail_result(
                message=f"Missing required fields: {', '.join(missing)}",
                details={"missing_fields": missing},
            )

        return self.pass_result()
