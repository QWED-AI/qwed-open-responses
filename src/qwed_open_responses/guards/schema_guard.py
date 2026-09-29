"""
Schema Guard - Validates AI response against JSON Schema.

Ensures structured outputs match the expected schema.
"""

from datetime import datetime
import re
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple
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


_EMAIL_FORMAT = re.compile(
    r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
    re.IGNORECASE | re.ASCII,
)


def _is_valid_email_format(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    return bool(_EMAIL_FORMAT.fullmatch(value))


_DATE_TIME_FORMAT = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[Tt]"
    r"(?:[01]\d|2[0-3]):[0-5]\d:(?P<second>[0-5]\d|60)(?:\.\d+)?"
    r"(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
_URI_INVALID_CHARACTERS = re.compile(r"[^\x21-\x7e]|[<>\"{}|\\^`]")
_URI_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def _is_valid_date_time_format(value: Any) -> bool:
    if not isinstance(value, str):
        return True

    match = _DATE_TIME_FORMAT.fullmatch(value)
    if match is None:
        return False

    normalized_value = value[:10] + "T" + value[11:]
    if match.group("second") == "60":
        if value[11:16] != "23:59":
            return False
        normalized_value = normalized_value[:17] + "59" + normalized_value[19:]
    if value[-1:].lower() == "z":
        normalized_value = normalized_value[:-1] + "+00:00"
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


class _RootObjectFields(NamedTuple):
    property_names: Set[str]
    pattern_names: Set[str]
    declares_object: bool
    references_resolved: bool
    property_activations: Dict[str, Set[Tuple[str, ...]]]
    pattern_activations: Dict[str, Set[Tuple[str, ...]]]
    activation_schemas: Dict[str, object]


def _collect_root_object_fields(root_schema: Dict[str, object]) -> _RootObjectFields:
    property_names: Set[str] = set()
    pattern_names: Set[str] = set()
    property_activations: Dict[str, Set[Tuple[str, ...]]] = {}
    pattern_activations: Dict[str, Set[Tuple[str, ...]]] = {}
    activation_schemas: Dict[str, object] = {}
    visited_schema_ids: Set[Tuple[int, Tuple[str, ...]]] = set()
    declares_object = False
    references_resolved = True

    def add_activation(
        activation: Tuple[str, ...], marker: str, predicate: object
    ) -> Tuple[str, ...]:
        activation_schemas.setdefault(marker, predicate)
        return tuple(sorted(set(activation) | {marker}))

    def visit(schema: object, activation: Tuple[str, ...] = ()) -> None:
        nonlocal declares_object, references_resolved
        if not isinstance(schema, dict):
            return

        visit_key = (id(schema), activation)
        if visit_key in visited_schema_ids:
            return
        visited_schema_ids.add(visit_key)

        reference = schema.get("$ref")
        if isinstance(reference, str):
            referenced_schema = _resolve_local_schema_reference(root_schema, reference)
            if referenced_schema is None:
                if not activation:
                    references_resolved = False
            else:
                visit(referenced_schema, activation)
            # Draft 7 ignores every sibling of $ref.
            return

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
            names = {name for name in properties if isinstance(name, str)}
            property_names.update(names)
            for name in names:
                property_activations.setdefault(name, set()).add(activation)
        if isinstance(pattern_properties, dict):
            names = {name for name in pattern_properties if isinstance(name, str)}
            pattern_names.update(names)
            for name in names:
                pattern_activations.setdefault(name, set()).add(activation)

        all_of = schema.get("allOf")
        if isinstance(all_of, list):
            for branch in all_of:
                visit(branch, activation)

        for keyword in ("anyOf", "oneOf"):
            branches = schema.get(keyword)
            if isinstance(branches, list):
                for index, branch in enumerate(branches):
                    branch_activation = add_activation(
                        activation,
                        f"{keyword}:{id(schema)}:{index}",
                        branch,
                    )
                    visit(branch, branch_activation)

        dependencies = schema.get("dependencies")
        if isinstance(dependencies, dict):
            for dependency_name, dependency in dependencies.items():
                if isinstance(dependency, dict):
                    dependency_activation = add_activation(
                        activation,
                        f"dependency:{id(schema)}:{dependency_name}",
                        {"required": [dependency_name]},
                    )
                    visit(dependency, dependency_activation)

        if "if" in schema:
            condition = schema.get("if")
            if "then" in schema:
                then_activation = add_activation(
                    activation, f"if:{id(schema)}:then", condition
                )
                visit(schema.get("then"), then_activation)
            if "else" in schema:
                else_activation = add_activation(
                    activation,
                    f"if:{id(schema)}:else",
                    {"not": condition},
                )
                visit(schema.get("else"), else_activation)

    root_reference = root_schema.get("$ref")
    if isinstance(root_reference, str):
        referenced_schema = _resolve_local_schema_reference(root_schema, root_reference)
        if referenced_schema is None:
            references_resolved = False
        else:
            visit(referenced_schema)
    else:
        visit(root_schema)

    return _RootObjectFields(
        property_names,
        pattern_names,
        declares_object,
        references_resolved,
        property_activations,
        pattern_activations,
        activation_schemas,
    )


def _activation_schema(
    activation: Tuple[str, ...], activation_schemas: Dict[str, object]
) -> object:
    schemas = [activation_schemas[marker] for marker in activation]
    return schemas[0] if len(schemas) == 1 else {"allOf": schemas}


def _conditional_field_constraints(
    fields: _RootObjectFields,
) -> List[Dict[str, object]]:
    constraints: List[Dict[str, object]] = []
    base_property_names = sorted(
        name
        for name, activations in fields.property_activations.items()
        if () in activations
    )
    base_pattern_names = sorted(
        name
        for name, activations in fields.pattern_activations.items()
        if () in activations
    )

    for property_name, activations in fields.property_activations.items():
        if () in activations:
            continue
        constraints.append(
            {
                "if": {"type": "object", "required": [property_name]},
                "then": {
                    "anyOf": [
                        _activation_schema(activation, fields.activation_schemas)
                        for activation in sorted(activations)
                    ]
                },
            }
        )

    for pattern_name, activations in fields.pattern_activations.items():
        if () in activations:
            continue
        allowed_name_schemas: List[object] = [{"not": {"pattern": pattern_name}}]
        if base_property_names:
            allowed_name_schemas.insert(0, {"enum": base_property_names})
        allowed_name_schemas.extend(
            {"pattern": base_pattern_name} for base_pattern_name in base_pattern_names
        )
        property_name_schema: object = (
            allowed_name_schemas[0]
            if len(allowed_name_schemas) == 1
            else {"anyOf": allowed_name_schemas}
        )
        constraints.append(
            {
                "if": {
                    "allOf": [
                        {"type": "object"},
                        {
                            "not": {
                                "anyOf": [
                                    _activation_schema(
                                        activation, fields.activation_schemas
                                    )
                                    for activation in sorted(activations)
                                ]
                            }
                        },
                    ]
                },
                "then": {
                    "type": "object",
                    "propertyNames": property_name_schema,
                },
            }
        )

    return constraints


_DRAFT7_VALIDATION_KEYWORDS = {
    "$ref",
    "additionalItems",
    "items",
    "contains",
    "additionalProperties",
    "properties",
    "patternProperties",
    "dependencies",
    "propertyNames",
    "const",
    "enum",
    "type",
    "format",
    "multipleOf",
    "maximum",
    "exclusiveMaximum",
    "minimum",
    "exclusiveMinimum",
    "maxLength",
    "minLength",
    "pattern",
    "maxItems",
    "minItems",
    "uniqueItems",
    "maxProperties",
    "minProperties",
    "required",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
}


def _wrap_root_reference(
    root_schema: Dict[str, object],
    reference: str,
    closure_schema: Dict[str, object],
    conditional_constraints: List[Dict[str, object]],
) -> Dict[str, object]:
    wrapper = {
        key: value
        for key, value in root_schema.items()
        if key not in _DRAFT7_VALIDATION_KEYWORDS
    }
    wrapper["allOf"] = [{"$ref": reference}, closure_schema, *conditional_constraints]
    return wrapper


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
        root_fields = _collect_root_object_fields(validator_schema)
        if (
            not allow_additional_properties
            and root_fields.declares_object
            and root_fields.references_resolved
            and "additionalProperties" not in validator_schema
        ):
            conditional_constraints = _conditional_field_constraints(root_fields)
            root_reference = validator_schema.get("$ref")
            if isinstance(root_reference, str):
                closure_properties: Dict[str, object] = {
                    property_name: {} for property_name in root_fields.property_names
                }
                closure_patterns: Dict[str, object] = {
                    pattern_name: {} for pattern_name in root_fields.pattern_names
                }
                closure_object_schema: Dict[str, object] = {
                    "type": "object",
                    "additionalProperties": False,
                }
                if closure_properties:
                    closure_object_schema["properties"] = closure_properties
                if closure_patterns:
                    closure_object_schema["patternProperties"] = closure_patterns
                closure_schema: Dict[str, object] = {
                    "anyOf": [
                        {"not": {"type": "object"}},
                        closure_object_schema,
                    ]
                }
                validator_schema = _wrap_root_reference(
                    validator_schema,
                    root_reference,
                    closure_schema,
                    conditional_constraints,
                )
            else:
                root_properties = validator_schema.get("properties")
                if "properties" not in validator_schema or isinstance(
                    root_properties, dict
                ):
                    merged_properties = dict(root_properties or {})
                    for property_name in root_fields.property_names:
                        merged_properties.setdefault(property_name, {})
                    if merged_properties:
                        validator_schema["properties"] = merged_properties

                root_patterns = validator_schema.get("patternProperties")
                if "patternProperties" not in validator_schema or isinstance(
                    root_patterns, dict
                ):
                    merged_patterns = dict(root_patterns or {})
                    for pattern_name in root_fields.pattern_names:
                        merged_patterns.setdefault(pattern_name, {})
                    if merged_patterns:
                        validator_schema["patternProperties"] = merged_patterns

                validator_schema["additionalProperties"] = False
                if conditional_constraints:
                    root_all_of = validator_schema.get("allOf")
                    if "allOf" not in validator_schema or isinstance(root_all_of, list):
                        validator_schema["allOf"] = [
                            *(root_all_of if isinstance(root_all_of, list) else []),
                            *conditional_constraints,
                        ]

        self.schema = validator_schema
        self.strict = strict
        self.allow_additional_properties = allow_additional_properties

        format_checker = jsonschema.FormatChecker()
        format_checker.checks("email", raises=(ValueError, TypeError))(
            _is_valid_email_format
        )
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
