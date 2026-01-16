"""
LangChain Integration for QWED Open Responses.

Provides callback handlers to verify tool calls and agent actions.
"""

from typing import Any, Dict, List, Optional, Union
from ..core import ResponseVerifier, VerificationResult
from ..guards.base import BaseGuard

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.agents import AgentAction, AgentFinish
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseCallbackHandler = object


class QWEDCallbackHandler(BaseCallbackHandler if HAS_LANGCHAIN else object):
    """
    LangChain callback handler that verifies agent actions.
    
    Usage:
        from qwed_open_responses.middleware.langchain import QWEDCallbackHandler
        from qwed_open_responses import ToolGuard, SafetyGuard
        
        callback = QWEDCallbackHandler(
            guards=[ToolGuard(), SafetyGuard()],
            block_on_failure=True,
        )
        
        agent = create_agent(callbacks=[callback])
    """
    
    def __init__(
        self,
        guards: Optional[List[BaseGuard]] = None,
        block_on_failure: bool = True,
        on_block: Optional[callable] = None,
        verbose: bool = False,
    ):
        """
        Initialize the callback handler.
        
        Args:
            guards: Guards to apply to agent actions
            block_on_failure: If True, raise exception on guard failure
            on_block: Callback function when action is blocked
            verbose: Print verification results
        """
        if not HAS_LANGCHAIN:
            raise ImportError(
                "langchain is required for LangChain integration. "
                "Install with: pip install qwed-open-responses[langchain]"
            )
        
        super().__init__()
        self.verifier = ResponseVerifier(default_guards=guards or [])
        self.block_on_failure = block_on_failure
        self.on_block = on_block
        self.verbose = verbose
        
        # Track verification history
        self.verification_history: List[VerificationResult] = []
    
    def on_agent_action(
        self,
        action: "AgentAction",
        **kwargs: Any,
    ) -> Any:
        """Verify agent action before execution."""
        
        # Build tool call dict
        tool_call = {
            "type": "tool_call",
            "tool_name": action.tool,
            "arguments": action.tool_input if isinstance(action.tool_input, dict) else {"input": action.tool_input},
        }
        
        # Verify
        result = self.verifier.verify(tool_call)
        self.verification_history.append(result)
        
        if self.verbose:
            print(f"[QWED] Tool: {action.tool} -> {result}")
        
        if not result.verified:
            if self.on_block:
                self.on_block(action, result)
            
            if self.block_on_failure:
                raise ToolCallBlocked(
                    f"Tool call blocked: {result.block_reason}",
                    action=action,
                    result=result,
                )
        
        return None
    
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> Any:
        """Called when tool starts - verify input."""
        
        tool_name = serialized.get("name", "unknown")
        
        tool_call = {
            "type": "tool_call",
            "tool_name": tool_name,
            "arguments": {"input": input_str},
        }
        
        result = self.verifier.verify(tool_call)
        
        if self.verbose:
            print(f"[QWED] Tool start: {tool_name} -> {result}")
        
        if not result.verified and self.block_on_failure:
            raise ToolCallBlocked(
                f"Tool blocked: {result.block_reason}",
                result=result,
            )
        
        return None
    
    def on_agent_finish(
        self,
        finish: "AgentFinish",
        **kwargs: Any,
    ) -> Any:
        """Verify final agent output."""
        
        output = {
            "type": "agent_output",
            "output": finish.return_values,
        }
        
        result = self.verifier.verify(output)
        
        if self.verbose:
            print(f"[QWED] Agent finish -> {result}")
        
        return None
    
    def get_verification_summary(self) -> Dict[str, Any]:
        """Get summary of all verifications."""
        total = len(self.verification_history)
        passed = sum(1 for r in self.verification_history if r.verified)
        failed = total - passed
        
        return {
            "total_verifications": total,
            "passed": passed,
            "failed": failed,
            "success_rate": passed / total if total > 0 else 1.0,
        }


class ToolCallBlocked(Exception):
    """Raised when a tool call is blocked by guards."""
    
    def __init__(
        self,
        message: str,
        action: Optional["AgentAction"] = None,
        result: Optional[VerificationResult] = None,
    ):
        super().__init__(message)
        self.action = action
        self.result = result
