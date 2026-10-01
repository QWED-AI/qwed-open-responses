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

Safety inspection fails closed above 12 nesting levels, 10,000 nodes, or
100,000 content characters. JSON input strings longer than 100,000 characters
or nested beyond 100 levels also return a failed verification result.

Detects PII and prompt injection.

```typescript
const guard = new SafetyGuard({
  checkPii: true,
  checkInjection: true,
  checkHarmful: true,
  piiAllowList: ['email'],
  customPatterns: ['internal\\s+marker'],
});
```

### SchemaGuard

SchemaGuard reports the first validation error; the total error count is
unknown because validation stops after that error.

Validates JSON structure.

```typescript
const guard = new SchemaGuard({
  type: 'object',
  properties: {
    name: { type: 'string' },
    age: { type: 'integer' },
  },
  required: ['name', 'age'],
});
```

Object schemas reject undeclared root fields by default. Set
`additionalProperties: true` in the schema or pass
`{ allowAdditionalProperties: true }` as the second argument to allow them.

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

## Security Advisory

### `path-to-regexp` ReDoS (Express 5.x)

If you use Express 5.x as your server framework, the transitive dependency `path-to-regexp@8.3.0` (via `express → router`) has a [ReDoS vulnerability](https://security.snyk.io/vuln/SNYK-JS-PATHTOREGEXP-15789765). Add the following override to **your project's** `package.json`:

```json
{
  "overrides": {
    "path-to-regexp": "^8.4.0"
  }
}
```

Then run `npm install` to apply. This is not required for Express 4.x users.

## Links

- **GitHub:** [QWED-AI/qwed-open-responses](https://github.com/QWED-AI/qwed-open-responses)
- **PyPI (Python):** [qwed-open-responses](https://pypi.org/project/qwed-open-responses/)
- **Docs:** [docs.qwedai.com](https://docs.qwedai.com/docs/open-responses/overview)

## License

Apache 2.0
