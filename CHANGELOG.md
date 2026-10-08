# Changelog

All notable changes to QWED Open Responses will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.1] - 2026-10-09

### Security — client-executed Responses API items (GHSA-xhq6-w3f2-m5w6)

- **ToolGuard verifies client action items** — `local_shell_call`,
  `shell_call`, `apply_patch_call`, `computer_call`, `custom_tool_call` and
  `mcp_approval_request` items are normalized into tool calls, so the
  blocklist, allowlist, dangerous-pattern and validator checks apply to them.
  Previously they read as tool-free content and verified. Applies to direct
  items, `output[]` members of a response object, `tool_calls[]` entries and
  the streaming middleware, on both the Python and npm packages.
- **Canonical tool names** — action items are policy-checked as
  `local_shell`, `shell`, `apply_patch` and `computer_use`; custom tool and
  MCP approval items use their own `name`. `local_shell` argv lists are also
  scanned as a joined command line.
- **BREAKING: default blocklist adds `local_shell`, `apply_patch` and
  `computer_use`** — to allow these tools, construct ToolGuard with
  `use_default_blocklist=False` (Python) / `{ useDefaultBlocklist: false }`
  (TypeScript) and list them in `allowed_tools` / `allowedTools`.
- **Unknown executable items fail closed** — any other `*_call` /
  `*_request` item in a protocol position (streamed items, `output_item`
  events, `output[]` of a response object) is blocked as unrecognized.
  Provider-hosted items (`web_search_call`, `file_search_call`,
  `code_interpreter_call`, `image_generation_call`, `mcp_call`) keep their
  existing behavior. Ordinary data with such type labels elsewhere is
  unaffected.
- **Ambiguous action items fail closed** — an action item that also
  carries a `tool_call` / `function_call` / `function` / `tool_calls`
  envelope, or a named item whose `tool_name` / `toolName` disagrees with
  `name`, is rejected.

## [0.6.0] - 2026-10-02

### Security — fail-closed hardening batch (#48, #49, #50, #51, #52, #55, #57, #58, #59)

- **BREAKING: SchemaGuard rejects undeclared root fields by default** (#48)
  — when your schema does not set `additionalProperties`, SchemaGuard adds
  `additionalProperties: false` to the root object, so responses with
  undeclared top-level fields now fail instead of passing silently. Declare
  the fields, set `additionalProperties` explicitly, or opt out with
  `allow_additional_properties=True` (Python) /
  `{ allowAdditionalProperties: true }` (TypeScript).
- **SchemaGuard cross-language format parity** (#48) — `format` validation
  for `email`, `uuid`, `date-time`, `uri`, and `ipv4` now matches across the
  Python and npm packages.
- **SchemaGuard reports the first error only** (#48) — failed results carry
  a single error with the total count reported as unknown
  (`total_errors=None`, `errors_truncated=True`); fix and re-verify to
  surface the next one.
- **Resource-bounded verification** (#49) — JSON responses over 100,000
  characters or 100 nesting levels, and responses with oversized integers,
  return a failed verdict instead of raising. SafetyGuard scanning fails
  closed above 10,000 nodes, 100,000 characters, or 12 nesting levels.
- **ToolGuard name and command normalization** (#55) — blocked tool names
  are normalized for case, surrounding whitespace, dashes, underscores, and
  camelCase. The default blocklist adds `run_command`, `execute_command`,
  `command_line`, and `terminal`. Allowlist entries still require the exact
  configured separators.
- **ToolGuard raw argument scanning** (#50) — dangerous patterns run on the
  raw parsed argument strings, including nested values and JSON-encoded
  calls. Cyclic or too-deep arguments fail closed.
- **ToolGuard envelope paths fail closed** (#59) — dual-identity items,
  structured-output exemptions, string-leaf blindness, and the depth cutoff
  no longer admit unverified tool calls.
- **Streaming tool-call verification** (#52) — `verify_stream` verifies each
  tool item in its original shape before yielding it. Unknown, ambiguous, or
  nested tool-shaped items are blocked; `tool_result` and
  `function_call_output` items pass through (their correlation metadata is
  not validated). ArgumentGuard and TaxGuard cover batched and nested calls.
- **Express middleware fails closed on unparsed bodies** (#51) — the npm
  `verifyRequestBody` middleware returns HTTP 422 (`QWED_REQUEST_BLOCKED`)
  when a request declares a body but has no parsed body, even with
  `blockOnFailure: false`. Register a body parser (e.g. `express.json()`)
  before the middleware.
- **SafetyGuard field scanning and context propagation** (#57, #58) —
  field names are scanned for injection and PII while sibling fields stay
  isolated; split output values scan as one text sequence; deep nesting
  fails closed at the boundary; budget caps fail closed without trusted
  usage context; JSON-text credential forms are blocked; and npm/Python
  configuration parity (subset patterns, escaped stringify, string-args
  asymmetry).

### Changed

- **Dropped the `jsonschema[format]` extra** (#61) — plain `jsonschema`
  plus a direct `fqdn` dependency for `hostname` schemas. Removes the
  GPL-3.0 licensed `rfc3987` (flagged high by Snyk) with no behavior change:
  every asserted format is hand-rolled or stdlib-backed.
- Dependency bumps: `fast-uri` 3.1.7 → 3.1.8, `brace-expansion` 5.0.9 →
  5.0.12, `js-yaml` 3.15.1 → 3.15.2 (#53, #54, #38).
- CI: npm publish workflow token scoped to `contents: read` (#56).

## [0.5.0] - 2026-09-08

### Security — dependency CVE fixes (#26)

- **js-yaml CVE-2026-59870 patch + brace-expansion GHSA fix** (`GHSA-rgw5-rvv9-x895`).

### Fixed — fail-closed verification batch (#27, #28, #29, #33)

- **Zero guards fail closed** — `verify()` with no guards configured returns
  `verified=False` instead of a vacuous pass; all middleware defaults that
  shipped guardless constructors now deny instead of verifying nothing.
- **Malformed, hybrid, and unrecognized envelopes fail closed** — non-dict
  tool-call entries, ambiguous hybrid envelopes (direct call + sibling
  collection), and tool-shaped content in unknown shapes become explicit
  rejections instead of silent passes or crashes.
- **Depth and shape bounds** — argument nesting depth checks, deterministic
  JSON depth bound, and case-insensitive `tool_use` blocks (both runtimes).

### Changed — cross-language parity (#30, #34) and hygiene (#32)

- **Unified case-insensitive pattern superset** across Python and TypeScript
  (TS gains sudo/chmod/subprocess patterns and the harmful-content check;
  strict parsing on both sides).
- **MathGuard no longer passes vacuously**, request/trace IDs on results,
  timezone-aware UTC timestamps.
- Dependency bumps: fast-uri 3.1.4 → 3.1.7 (via `overrides` pin, #25).

### Fixed — issue #31 correctness batch

- **ToolGuard**: blocklist/allowlist matching is now case-insensitive
  (casefold on Python, full-folding casefold approximation on TS,
  including Greek final sigma); the default blocklist covers common
  shells and OS command interpreters (`sh`, `powershell`, `pwsh`, `zsh`,
  `fish`, `cmd.exe`, ...); argument pattern scanning decodes encoded
  payloads down to 7-alphabet-char tokens (padded short tokens like
  `ZXhlYyg=` → `exec(` are caught) and respects `/g`-flagged caller
  regexes (`lastIndex` reset). Custom-validator keys are normalized
  case-insensitively. Pattern scanning is documented as a heuristic, not
  a security boundary.
- **Warning semantics**: `warn_result` now PASSES the guard
  (`passed=True`, `severity="warning"`), matching its documented behavior.
  Warnings are surfaced via `VerificationResult.warnings` and no longer
  flip `verified` to False on their own; verifiers created with
  `allow_warnings=False` escalate warnings to failures/blocks as before.
- **VerificationResult**: results produced by `ResponseVerifier.verify`
  now carry a `binding` — a SHA-256 digest covering the verified response
  AND the guard list; call `verify_binding()` to detect forged or replayed
  results, or altered verification metadata. Results remain plain, publicly
  constructible dataclasses — treat externally supplied results as
  untrusted (full attestation is tracked in qwed-verification #319).
- **`verify_structured_output`** raises `ValueError` when called with
  neither a schema nor guards (it previously could verify nothing); an
  explicitly supplied empty schema `{}` is honored.
- **Binding digests are runtime-portable**: integral floats are
  canonicalized (`1.0` ≡ `1` across Python/JS), and values JSON cannot
  represent fail closed instead of digesting a lossy string conversion.
- **Cyclic / non-serializable responses** fail closed with a failed
  `VerificationResult` in both runtimes instead of raising from binding
  generation.
- **SafetyGuard budget check** validates model-reported `usage` values
  (must be finite non-negative numbers; anything else — including a
  non-object `usage` container — fails closed); zero-valued caps are
  enforced; missing usage accounting also fails closed when a cap is
  configured, unless trusted-side context totals are supplied; documents
  the trust model.
- **VerifiedOpenAI** warns loudly when created without guards (fail-closed
  verification would block every response).
- **Streaming interceptor** warns and documents that
  `block_on_failure=False` disables the trust boundary (warn-only mode).
- **README**: claims rescoped ("100% Deterministic", "formal verification
  rules", "AST analysis" → precise descriptions) and a new
  Scope & Limitations section added.

## [0.4.0] - 2026-07-26

### Security

- **Resolved all 4 Dependabot alerts** in the npm development toolchain:
  - `@babel/core` arbitrary file read via sourceMappingURL (CVE-2026-49356, Low) — fixed via Jest 30 upgrade
  - `brace-expansion` exponential-time DoS (High) — fixed via override to ^5.0.8
  - `js-yaml` quadratic-complexity DoS via merge-key chains (High) — fixed via Jest 30 upgrade
  - `js-yaml` quadratic-complexity DoS via repeated aliases (Moderate) — fixed via Jest 30 upgrade
- **Resolved fast-uri Interpretation Conflict** (High, SNYK-JS-FASTURI-17675102) — override to ^3.1.4; fresh installs of `ajv` also resolve to the patched version
- `npm audit`: 21 vulnerabilities → **0**

### Changed

- **BREAKING (advisory):** Minimum Node.js version for the npm package is now **20** (was 16). Node 16 and 18 are end-of-life. Runtime dependencies continue to work on older versions, but installation on Node <20 will emit an engine warning.
- Upgraded test toolchain: `jest` 29.7.0 → 30.4.2, `@types/jest` 29.5.11 → 30.0.0
- Hardened CI: Snyk scans now skip Dependabot PRs (missing secrets), split Python/npm dependency scans, reproducible `npm ci` scans, SonarCloud runs on Java 21 with SHA-pinned `actions/setup-java`

### Fixed

- CI: SonarCloud no longer fails on Java 17 deprecation (SonarScanner now uses system Java 21 via `SONAR_SCANNER_JAVA_EXE_PATH`)
- CI: Snyk dependency scan no longer fails on `--all-projects` detection; scans Python and npm targets explicitly with unique SARIF categories

## [0.3.0] - 2026-07-05

### Added

- Initial public release: verification guards for AI agent outputs
- Guards: `ToolGuard`, `SchemaGuard`, `MathGuard`, `SafetyGuard`, `StateGuard`, `ArgumentGuard`
- Integrations: OpenAI Responses API, LangChain
- TypeScript/Express middleware package (`npm/`)
