"""
QWED Open Responses - Middleware Package.

Framework integrations for LangChain, LlamaIndex, OpenAI SDK.
"""

# Lazy imports to avoid requiring all dependencies
def __getattr__(name):
    if name == "QWEDCallbackHandler":
        from .langchain import QWEDCallbackHandler
        return QWEDCallbackHandler
    elif name == "VerifiedOpenAI":
        from .openai_sdk import VerifiedOpenAI
        return VerifiedOpenAI
    raise AttributeError(f"module 'qwed_open_responses.middleware' has no attribute '{name}'")
