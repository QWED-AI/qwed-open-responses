# Changelog

All notable changes to QWED Open Responses will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
