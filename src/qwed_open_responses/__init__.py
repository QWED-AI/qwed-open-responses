"""
QWED Open Responses - Verification Guards for AI Agent Outputs.

Verify AI responses before execution. Works with OpenAI Responses API,
LangChain, LlamaIndex, and other AI agent frameworks.

Usage:
    from qwed_open_responses import ResponseVerifier, ToolGuard, SchemaGuard
    
    verifier = ResponseVerifier()
    result = verifier.verify(response, guards=[ToolGuard(), SchemaGuard()])
"""

from .core import (
    ResponseVerifier,
    VerificationResult,
    GuardResult,
)

from .guards import (
    BaseGuard,
    SchemaGuard,
    MathGuard,
    ToolGuard,
    StateGuard,
    ArgumentGuard,
    SafetyGuard,
)

__version__ = "0.1.0"
__all__ = [
    # Core
    "ResponseVerifier",
    "VerificationResult",
    "GuardResult",
    # Guards
    "BaseGuard",
    "SchemaGuard",
    "MathGuard",
    "ToolGuard",
    "StateGuard",
    "ArgumentGuard",
    "SafetyGuard",
]
