# QWED Open Responses (Node.js)

[![npm version](https://badge.fury.io/js/qwed-open-responses.svg)](https://badge.fury.io/js/qwed-open-responses)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Verification guards for AI agent outputs in Node.js/Express applications.**

## Installation

```bash
npm install qwed-open-responses
```

## Quick Start

```typescript
import express from 'express';
import { createQWEDMiddleware, ToolGuard, SafetyGuard } from 'qwed-open-responses';

const app = express();
app.use(express.json());

// Add verification middleware
app.use(createQWEDMiddleware({
  guards: [new ToolGuard(), new SafetyGuard()],
  blockOnFailure: true,
}));

app.post('/api/agent', (req, res) => {
  // Response will be verified before sending
  res.json({
    tool_calls: [
      { name: 'search', arguments: { query: 'weather' } }
    ]
  });
});
```

## Guards

### ToolGuard

Blocks dangerous tool calls.

```typescript
const guard = new ToolGuard({
  blockedTools: ['execute_shell', 'delete_file'],
  allowedTools: ['search', 'calculator'], // Whitelist mode
});
```

### SafetyGuard

Detects PII and prompt injection.

```typescript
const guard = new SafetyGuard({
  checkPii: true,
  checkInjection: true,
});
```

### SchemaGuard

Validates JSON structure.

```typescript
const guard = new SchemaGuard({
  type: 'object',
  required: ['name', 'age'],
});
```

### MathGuard

Verifies calculations.

```typescript
const guard = new MathGuard({ tolerance: 0.01 });
```

## Middleware Options

```typescript
createQWEDMiddleware({
  guards: [],              // Guards to apply
  blockOnFailure: true,    // Block failed responses
  verbose: false,          // Log verification results
  skipPaths: ['/health'],  // Paths to skip
  onError: (result, req, res) => {
    // Custom error handler
  },
});
```

## Verify Request Bodies

```typescript
import { verifyRequestBody, ToolGuard } from 'qwed-open-responses';

app.post('/api/execute',
  verifyRequestBody({ guards: [new ToolGuard()] }),
  (req, res) => {
    // Request body is verified
  }
);
```

## Direct Verification

```typescript
import { ResponseVerifier, ToolGuard } from 'qwed-open-responses';

const verifier = new ResponseVerifier([new ToolGuard()]);

const result = verifier.verify({
  tool_calls: [{ name: 'search', arguments: {} }]
});

if (result.verified) {
  console.log('✅ Safe to execute');
} else {
  console.log('❌ Blocked:', result.blockReason);
}
```

## Links

- **GitHub:** [QWED-AI/qwed-open-responses](https://github.com/QWED-AI/qwed-open-responses)
- **PyPI (Python):** [qwed-open-responses](https://pypi.org/project/qwed-open-responses/)
- **Docs:** [docs.qwedai.com](https://docs.qwedai.com/docs/open-responses/overview)

## License

Apache 2.0
