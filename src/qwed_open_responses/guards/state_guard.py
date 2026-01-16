"""
State Guard - Validates state machine transitions.

Ensures AI responses follow valid state transitions.
"""

from typing import Any, Dict, Optional, List, Set
from .base import BaseGuard, GuardResult


class StateGuard(BaseGuard):
    """
    Validates state machine transitions.
    
    Usage:
        guard = StateGuard(
            transitions={
                "pending": ["processing", "cancelled"],
                "processing": ["completed", "failed"],
                "completed": [],  # Terminal state
                "failed": ["pending"],  # Can retry
            },
            current_state="pending",
        )
        
        result = guard.check({"new_state": "processing"})  # Passes
        result = guard.check({"new_state": "completed"})   # Fails (invalid)
    """
    
    name = "StateGuard"
    description = "Validates state machine transitions"
    
    def __init__(
        self,
        transitions: Dict[str, List[str]],
        current_state: Optional[str] = None,
        state_field: str = "state",
        new_state_field: str = "new_state",
    ):
        """
        Initialize StateGuard.
        
        Args:
            transitions: Dict mapping state -> list of valid next states
            current_state: Current state (can also be passed in context)
            state_field: Field name for current state in response
            new_state_field: Field name for new state in response
        """
        self.transitions = transitions
        self.current_state = current_state
        self.state_field = state_field
        self.new_state_field = new_state_field
        
        # Build set of all valid states
        self.valid_states: Set[str] = set(transitions.keys())
        for next_states in transitions.values():
            self.valid_states.update(next_states)
    
    def check(
        self,
        response: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """Validate state transition."""
        
        data = response.get("output", response)
        context = context or {}
        
        # Get current state
        current = (
            context.get("current_state") or 
            self.current_state or
            data.get(self.state_field)
        )
        
        # Get new state
        new_state = data.get(self.new_state_field) or data.get("status")
        
        if not new_state:
            return self.pass_result(message="No state change detected")
        
        # Validate new state exists
        if new_state not in self.valid_states:
            return self.fail_result(
                f"Invalid state: '{new_state}'",
                details={
                    "invalid_state": new_state,
                    "valid_states": list(self.valid_states),
                },
            )
        
        # If no current state, allow any valid state
        if not current:
            return self.pass_result(
                message=f"State set to '{new_state}'",
                details={"new_state": new_state},
            )
        
        # Validate transition
        valid_next = self.transitions.get(current, [])
        if new_state not in valid_next:
            return self.fail_result(
                f"Invalid transition: '{current}' -> '{new_state}'",
                details={
                    "current_state": current,
                    "requested_state": new_state,
                    "valid_next_states": valid_next,
                },
            )
        
        return self.pass_result(
            message=f"Valid transition: '{current}' -> '{new_state}'",
            details={
                "from": current,
                "to": new_state,
            },
        )
