# QWED Open Responses

[![PyPI](https://img.shields.io/pypi/v/qwed-open-responses?color=blue&label=PyPI)](https://pypi.org/project/qwed-open-responses/)
[![npm](https://img.shields.io/npm/v/qwed-open-responses?color=green&label=npm)](https://www.npmjs.com/package/qwed-open-responses)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://github.com/QWED-AI/qwed-open-responses/actions/workflows/ci.yml/badge.svg)](https://github.com/QWED-AI/qwed-open-responses/actions)
[![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-open-responses?style=social)](https://github.com/QWED-AI/qwed-open-responses)
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification#%EF%B8%8F-what-does-verified-by-qwed-mean)

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
pip install qwed-open-responses[tax]         # Tax Verification (Payroll, Crypto)
pip install qwed-open-responses[finance]     # Finance Verification (NPV, ISO 20022)
pip install qwed-open-responses[all]         # All integrations
```

---

## 💡 What QWED Open Responses Is (and Isn't)

### ✅ QWED Open Responses IS:
- **Verification middleware** for AI agents (OpenAI, LangChain, LlamaIndex)
- **Deterministic** — uses symbolic logic and formal verification rules
- **Framework-agnostic** — works with any LLM or agent framework
- **A safety layer** — prevents dangerous tool calls and incorrect outputs

### ❌ QWED Open Responses is NOT:
- ~~An agent framework~~ — use LangChain or AutoGen for that
- ~~A prompt engineering tool~~ — use DSPy for that
- ~~A vector database~~ — use Pinecone or Weaviate for that
- ~~A vaguely defined "guardrail"~~ — we use mathematical proofs, not regex

> **Think of QWED as the "firewall" for your AI agent's actions and outputs.**
> 
> LangChain builds the agent. OpenAI powers the brain. **QWED secures the actions.**

---

## 🆚 How We're Different from Other Guardrails

| Aspect | Guardrails AI / NVIDIA NeMo | DSPy | QWED Open Responses |
|--------|-----------------------------|------|---------------------|
| **Primary Goal** | Format validation (XML/RAIL) | Prompt optimization | Deterministic verification |
| **Tool Security** | Regex-based blocking | N/A | AST analysis + whitelist |
| **Math Accuracy** | LLM self-correction | Prompt tuning | SymPy symbolic math |
| **Approach** | "Re-ask the LLM" | "Train the prompt" | "Verify legally/mathematically" |
| **Integration** | Wraps LLM calls | Replaces prompt pipeline | Middleware / Callback |
| **Determinism** | Probabilistic | Probabilistic | **100% Deterministic** |

### Use Together (Best Practice)
```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│   LangChain  │ ──► │     QWED      │ ──► │  Verified    │
│    Agent     │     │  (Middleware) │     │  Tool Call   │
└──────────────┘     └───────────────┘     └──────────────┘
```

---

## 🔒 Security & Privacy

> **Verification happens locally. No data leaves your infrastructure.**

| Concern | QWED Approach |
|---------|---------------|
| **Data Transmission** | ❌ No external API calls for verification |
| **Logic Execution** | ✅ Local Python/Z3 engines |
| **Latency** | ✅ Sub-millisecond overhead for most guards |
| **Audit** | ✅ Full logs of blocked actions |

**Perfect for:**
- Agents with access to databases or APIs
- Enterprise internal tools
- Automated financial/legal assistants

---

## ❓ FAQ

<details>
<summary><b>Does it slow down my agent?</b></summary>

Negligibly. Most guards (Schema, Tool, Argument) run in <1ms. MathGuard runs in <5ms. It's much faster than making another LLM call to double-check.
</details>

<details>
<summary><b>Can I use it with custom agents?</b></summary>

Yes! You don't need LangChain. QWED works with raw OpenAI API calls or any Python code. Just pass the output to the `Verifier`.
</details>

<details>
<summary><b>How does MathGuard work?</b></summary>

It extracts numbers and operators from the output and uses SymPy to verify if the stated result matches the calculation. It does NOT ask the LLM to check itself.
</details>

<details>
<summary><b>Is it compatible with streaming?</b></summary>

Yes, but verification usually happens on the final tool call or complete message chunk. We are working on stream-interception middleware.
</details>

---

## 🗺️ Roadmap

### ✅ Released (v1.0.0)
- [x] `ToolGuard` - Block dangerous tools/patterns
- [x] `SchemaGuard` - JSON Schema validation
- [x] `MathGuard` - SymPy calculation verification
- [x] `SafetyGuard` - PII and injection checks
- [x] `StateGuard` - Finite state machine validation
- [x] `ArgumentGuard` - Type and range checking
- [x] Integrations: OpenAI, LangChain

### 🚧 In Progress
- [ ] **LlamaIndex Integration** - First-class support
- [ ] **Streaming Verification** - Verify chunks in real-time
- [ ] **Auto-Fix** - Deterministic correction of JSON errors

### 🔮 Planned
- [ ] **Distributed Rules** - Sync rules across agent swarms
- [ ] **Policy-as-Code** - Define guards in YAML/JSON
- [ ] **Visual Dashboard** - View blocked attempts stats

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
