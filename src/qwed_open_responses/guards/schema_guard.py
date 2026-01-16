"""
Schema Guard - Validates AI response against JSON Schema.

Ensures structured outputs match the expected schema.
"""

from typing import Any, Dict, Optional, List
from .base import BaseGuard, GuardResult

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


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
            allow_additional_properties: If True, allow extra fields
        """
        if not HAS_JSONSCHEMA:
            raise ImportError(
                "jsonschema is required for SchemaGuard. "
                "Install with: pip install jsonschema"
            )
        
        self.schema = schema
        self.strict = strict
        self.allow_additional_properties = allow_additional_properties
        
        # Compile the validator
        self.validator = jsonschema.Draft7Validator(schema)
    
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
