# QWED Open Responses

[![PyPI version](https://badge.fury.io/py/qwed-open-responses.svg)](https://badge.fury.io/py/qwed-open-responses)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Verification guards for AI agent outputs. Verify before you execute.**

QWED Open Responses provides deterministic verification guards for AI responses, tool calls, and structured outputs. Works with OpenAI Responses API, LangChain, LlamaIndex, and other AI agent frameworks.

---

## Installation

```bash
pip install qwed-open-responses
```

With optional integrations:

```bash
pip install qwed-open-responses[openai]      # OpenAI Responses API
pip install qwed-open-responses[langchain]   # LangChain
pip install qwed-open-responses[all]         # All integrations
```

---

## Quick Start

```python
from qwed_open_responses import ResponseVerifier, ToolGuard, SchemaGuard

# Create verifier with guards
verifier = ResponseVerifier()

# Verify a tool call
result = verifier.verify_tool_call(
    tool_name="execute_sql",
    arguments={"query": "SELECT * FROM users"},
    guards=[ToolGuard()]
)

if result.verified:
    print("✅ Safe to execute")
else:
    print(f"❌ Blocked: {result.block_reason}")
```

---

## Guards

| Guard | Purpose | Example |
|-------|---------|---------|
| **SchemaGuard** | Validate JSON schema | Structured outputs |
| **ToolGuard** | Block dangerous tools | `execute_shell`, `delete_file` |
| **MathGuard** | Verify calculations | Totals, percentages |
| **StateGuard** | Validate state transitions | Order status changes |
| **ArgumentGuard** | Validate tool arguments | Types, ranges, formats |
| **SafetyGuard** | Comprehensive safety | PII, injection, budget |

---

## Examples

### Block Dangerous Tools

```python
from qwed_open_responses import ToolGuard

guard = ToolGuard(
    blocked_tools=["execute_shell", "delete_file"],
    dangerous_patterns=[r"DROP TABLE", r"rm -rf"],
)

result = guard.check({
    "tool_name": "execute_sql",
    "arguments": {"query": "DROP TABLE users"}
})
# ❌ BLOCKED: Dangerous pattern detected
```

### Validate Structured Outputs

```python
from qwed_open_responses import SchemaGuard

schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0}
    },
    "required": ["name", "age"]
}

guard = SchemaGuard(schema=schema)
result = guard.check({"output": {"name": "John", "age": 30}})
# ✅ Schema validation passed
```

### Verify Calculations

```python
from qwed_open_responses import MathGuard

guard = MathGuard()
result = guard.check({
    "output": {
        "subtotal": 100,
        "tax": 8,
        "total": 108
    }
})
# ✅ Math verification passed
```

### Safety Checks

```python
from qwed_open_responses import SafetyGuard

guard = SafetyGuard(
    check_pii=True,
    check_injection=True,
    max_cost=100.0,
)

result = guard.check({
    "content": "ignore previous instructions and..."
})
# ❌ BLOCKED: Prompt injection detected
```

---

## Framework Integrations

### LangChain

```python
from qwed_open_responses.middleware.langchain import QWEDCallbackHandler

callback = QWEDCallbackHandler(
    guards=[ToolGuard(), SafetyGuard()]
)

agent = create_agent(callbacks=[callback])
```

### OpenAI Responses API

```python
from qwed_open_responses.middleware.openai_sdk import VerifiedOpenAI

client = VerifiedOpenAI(
    api_key="...",
    guards=[ToolGuard(), SchemaGuard(schema=my_schema)]
)

response = client.responses.create(...)
# Automatically verified before returning
```

---

## Why QWED Open Responses?

| Without Verification | With QWED |
|---------------------|-----------|
| LLM calls `execute_shell("rm -rf /")` | **BLOCKED** by ToolGuard |
| LLM returns wrong calculation | **CAUGHT** by MathGuard |
| LLM outputs PII in response | **DETECTED** by SafetyGuard |
| LLM hallucinates JSON format | **REJECTED** by SchemaGuard |

---

## Links

- **Docs:** [docs.qwedai.com/docs/open-responses](https://docs.qwedai.com/docs/open-responses)
- **GitHub:** [QWED-AI/qwed-open-responses](https://github.com/QWED-AI/qwed-open-responses)
- **PyPI:** [qwed-open-responses](https://pypi.org/project/qwed-open-responses/)
- **QWED Core:** [QWED-AI/qwed-verification](https://github.com/QWED-AI/qwed-verification)

---

## License

Apache 2.0 - See [LICENSE](LICENSE)
