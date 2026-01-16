"""
LlamaIndex Integration for QWED Open Responses.

Provides callback handlers to verify query engine outputs.
"""

from typing import Any, Dict, List, Optional
from ..core import ResponseVerifier, VerificationResult
from ..guards.base import BaseGuard

try:
    from llama_index.core.callbacks import CallbackManager
    from llama_index.core.callbacks.base_handler import BaseCallbackHandler
    from llama_index.core.callbacks.schema import CBEventType, EventPayload

    HAS_LLAMAINDEX = True
except ImportError:
    HAS_LLAMAINDEX = False
    BaseCallbackHandler = object
    CBEventType = None


class QWEDLlamaIndexHandler(BaseCallbackHandler if HAS_LLAMAINDEX else object):
    """
    LlamaIndex callback handler that verifies outputs.

    Usage:
        from qwed_open_responses.middleware.llamaindex import QWEDLlamaIndexHandler
        from qwed_open_responses import ToolGuard, SafetyGuard

        handler = QWEDLlamaIndexHandler(
            guards=[ToolGuard(), SafetyGuard()],
        )

        callback_manager = CallbackManager([handler])
        query_engine = index.as_query_engine(callback_manager=callback_manager)
    """

    def __init__(
        self,
        guards: Optional[List[BaseGuard]] = None,
        block_on_failure: bool = True,
        verify_retrieval: bool = True,
        verify_synthesis: bool = True,
        verbose: bool = False,
    ):
        """
        Initialize the handler.

        Args:
            guards: Guards to apply to outputs
            block_on_failure: If True, raise exception on guard failure
            verify_retrieval: Verify retrieved nodes
            verify_synthesis: Verify synthesized responses
            verbose: Print verification results
        """
        if not HAS_LLAMAINDEX:
            raise ImportError(
                "llama-index is required for LlamaIndex integration. "
                "Install with: pip install qwed-open-responses[llamaindex]"
            )

        super().__init__(
            event_starts_to_ignore=[],
            event_ends_to_ignore=[],
        )

        self.verifier = ResponseVerifier(default_guards=guards or [])
        self.block_on_failure = block_on_failure
        self.verify_retrieval = verify_retrieval
        self.verify_synthesis = verify_synthesis
        self.verbose = verbose

        # Track verification history
        self.verification_history: List[VerificationResult] = []

    def on_event_start(
        self,
        event_type: "CBEventType",
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs,
    ) -> str:
        """Called when event starts."""
        return event_id

    def on_event_end(
        self,
        event_type: "CBEventType",
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs,
    ) -> None:
        """Called when event ends - verify output."""

        if payload is None:
            return

        # Verify retrieval
        if self.verify_retrieval and event_type == CBEventType.RETRIEVE:
            nodes = payload.get(EventPayload.NODES, [])
            for node in nodes:
                self._verify_node(node)

        # Verify synthesis/LLM response
        if self.verify_synthesis and event_type == CBEventType.SYNTHESIZE:
            response = payload.get(EventPayload.RESPONSE)
            if response:
                self._verify_response(response)

        # Verify function/tool calls
        if event_type == CBEventType.FUNCTION_CALL:
            function_call = payload.get(EventPayload.FUNCTION_CALL)
            if function_call:
                self._verify_function_call(function_call)

    def _verify_node(self, node: Any) -> None:
        """Verify a retrieved node."""
        node_dict = {
            "type": "retrieval_node",
            "content": getattr(node, "text", str(node)),
            "metadata": getattr(node, "metadata", {}),
        }

        result = self.verifier.verify(node_dict)
        self.verification_history.append(result)

        if self.verbose:
            print(f"[QWED] Retrieval node -> {result}")

        if not result.verified and self.block_on_failure:
            raise RetrievalBlocked(
                f"Retrieved node blocked: {result.block_reason}",
                node=node,
                result=result,
            )

    def _verify_response(self, response: Any) -> None:
        """Verify a synthesized response."""
        response_dict = {
            "type": "synthesis_response",
            "content": str(response),
        }

        result = self.verifier.verify(response_dict)
        self.verification_history.append(result)

        if self.verbose:
            print(f"[QWED] Synthesis response -> {result}")

        if not result.verified and self.block_on_failure:
            raise ResponseBlocked(
                f"Response blocked: {result.block_reason}",
                response=response,
                result=result,
            )

    def _verify_function_call(self, function_call: Dict) -> None:
        """Verify a function/tool call."""
        call_dict = {
            "type": "tool_call",
            "tool_name": function_call.get("name", "unknown"),
            "arguments": function_call.get("arguments", {}),
        }

        result = self.verifier.verify(call_dict)
        self.verification_history.append(result)

        if self.verbose:
            tool_name = function_call.get("name", "unknown")
            print(f"[QWED] Function call: {tool_name} -> {result}")

        if not result.verified and self.block_on_failure:
            raise FunctionCallBlocked(
                f"Function call blocked: {result.block_reason}",
                function_call=function_call,
                result=result,
            )

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        """Start a new trace."""
        pass

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """End the current trace."""
        pass

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


class RetrievalBlocked(Exception):
    """Raised when a retrieved node is blocked."""

    def __init__(
        self,
        message: str,
        node: Any = None,
        result: Optional[VerificationResult] = None,
    ):
        super().__init__(message)
        self.node = node
        self.result = result


class ResponseBlocked(Exception):
    """Raised when a response is blocked."""

    def __init__(
        self,
        message: str,
        response: Any = None,
        result: Optional[VerificationResult] = None,
    ):
        super().__init__(message)
        self.response = response
        self.result = result


class FunctionCallBlocked(Exception):
    """Raised when a function call is blocked."""

    def __init__(
        self,
        message: str,
        function_call: Dict = None,
        result: Optional[VerificationResult] = None,
    ):
        super().__init__(message)
        self.function_call = function_call
        self.result = result
