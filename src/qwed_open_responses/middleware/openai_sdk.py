"""
OpenAI SDK Integration for QWED Open Responses.

Provides a verified wrapper around OpenAI client.
"""

from typing import Any, Dict, List, Optional
from ..core import ResponseVerifier, VerificationResult
from ..guards.base import BaseGuard

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


class VerifiedOpenAI:
    """
    OpenAI client wrapper with automatic verification.
    
    Usage:
        from qwed_open_responses.middleware.openai_sdk import VerifiedOpenAI
        from qwed_open_responses import ToolGuard, SchemaGuard
        
        client = VerifiedOpenAI(
            api_key="sk-...",
            guards=[ToolGuard(), SchemaGuard(schema=my_schema)],
        )
        
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[...],
            tools=[...],
        )
        # Response is automatically verified
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        guards: Optional[List[BaseGuard]] = None,
        block_on_failure: bool = True,
        **kwargs,
    ):
        """
        Initialize verified OpenAI client.
        
        Args:
            api_key: OpenAI API key
            guards: Guards to apply to responses
            block_on_failure: If True, raise on verification failure
            **kwargs: Additional args passed to OpenAI client
        """
        if not HAS_OPENAI:
            raise ImportError(
                "openai is required for OpenAI integration. "
                "Install with: pip install qwed-open-responses[openai]"
            )
        
        self._client = openai.OpenAI(api_key=api_key, **kwargs)
        self._verifier = ResponseVerifier(default_guards=guards or [])
        self._block_on_failure = block_on_failure
        
        # Create verified wrappers
        self.chat = VerifiedChat(self)
        self.responses = VerifiedResponses(self)
    
    def verify(self, response: Any) -> VerificationResult:
        """Verify a response."""
        # Convert OpenAI response to dict
        if hasattr(response, "model_dump"):
            response_dict = response.model_dump()
        elif hasattr(response, "dict"):
            response_dict = response.dict()
        else:
            response_dict = {"raw": str(response)}
        
        return self._verifier.verify(response_dict)


class VerifiedChat:
    """Verified chat completions wrapper."""
    
    def __init__(self, parent: VerifiedOpenAI):
        self._parent = parent
        self.completions = VerifiedCompletions(parent)


class VerifiedCompletions:
    """Verified completions endpoint."""
    
    def __init__(self, parent: VerifiedOpenAI):
        self._parent = parent
    
    def create(self, **kwargs) -> Any:
        """Create chat completion with verification."""
        response = self._parent._client.chat.completions.create(**kwargs)
        
        result = self._parent.verify(response)
        
        if not result.verified and self._parent._block_on_failure:
            raise ResponseBlocked(
                f"Response blocked: {result.block_reason}",
                response=response,
                result=result,
            )
        
        # Attach verification result to response
        response._qwed_verification = result
        return response


class VerifiedResponses:
    """Verified Responses API wrapper (for OpenAI Responses API)."""
    
    def __init__(self, parent: VerifiedOpenAI):
        self._parent = parent
    
    def create(self, **kwargs) -> Any:
        """Create response with verification."""
        # Note: This is for the new Responses API when available
        # For now, falls back to chat completions
        if hasattr(self._parent._client, "responses"):
            response = self._parent._client.responses.create(**kwargs)
        else:
            # Fallback to chat completions
            response = self._parent._client.chat.completions.create(**kwargs)
        
        result = self._parent.verify(response)
        
        if not result.verified and self._parent._block_on_failure:
            raise ResponseBlocked(
                f"Response blocked: {result.block_reason}",
                response=response,
                result=result,
            )
        
        response._qwed_verification = result
        return response


class ResponseBlocked(Exception):
    """Raised when a response is blocked by guards."""
    
    def __init__(
        self,
        message: str,
        response: Any = None,
        result: Optional[VerificationResult] = None,
    ):
        super().__init__(message)
        self.response = response
        self.result = result
