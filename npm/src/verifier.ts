/**
 * QWED Open Responses - Response Verifier
 */

import { createHash } from 'crypto';
import { BaseGuard } from './guards';
import { VerificationResult, GuardResult, ParsedResponse, ResultBinding } from './types';

// Re-export types
export { VerificationResult, GuardResult };

/**
 * Canonical JSON serialization for digest computation (#31).
 * Mirrors Python json.dumps(sort_keys=True, separators=(",", ":")) —
 * including the default ensure_ascii=True, which escapes non-ASCII as
 * \uXXXX (surrogate pairs for astral chars) so digests match across
 * runtimes (#31 parity review).
 */
function escapeNonAscii(s: string): string {
    return s.replace(/[^\x00-\x7F]/g, (ch) => {
        const cp = ch.codePointAt(0) as number;
        if (cp > 0xffff) {
            const hi = Math.floor((cp - 0x10000) / 0x400) + 0xd800;
            const lo = ((cp - 0x10000) % 0x400) + 0xdc00;
            return (
                '\\u' + hi.toString(16).padStart(4, '0')
                + '\\u' + lo.toString(16).padStart(4, '0')
            );
        }
        return '\\u' + cp.toString(16).padStart(4, '0');
    });
}

function canonicalJson(value: any): string {
    if (value === null || typeof value !== 'object') {
        return escapeNonAscii(JSON.stringify(value) ?? 'null');
    }
    if (Array.isArray(value)) {
        return '[' + value.map((v) => canonicalJson(v)).join(',') + ']';
    }
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => escapeNonAscii(JSON.stringify(k)) + ':' + canonicalJson(value[k])).join(',') + '}';
}

/**
 * Binding digest, or undefined when the response cannot be bound.
 * Cyclic / non-serializable response graphs overflow inside the JSON
 * canonicalizer (#31 review, Greptile P1) — callers must fail closed with
 * a failed VerificationResult instead of crashing. Mirrors Python
 * ResponseVerifier._safe_binding.
 */
function safeBinding(response: any, guards: string[]): ResultBinding | undefined {
    try {
        return { guards, digest: bindingDigest(response, guards) };
    } catch {
        return undefined;
    }
}

/**
 * Digest over the response AND the guard list (#31 review): altering
 * either the verified payload or the verification metadata invalidates
 * the binding. Mirrors Python core._binding_digest.
 */
function bindingDigest(response: any, guards: string[]): string {
    return createHash('sha256')
        .update(canonicalJson({ guards, response }), 'utf8')
        .digest('hex');
}

/**
 * Re-check the binding of a VerificationResult (#31). Returns true only
 * when the result carries a binding set by ResponseVerifier.verify AND the
 * digest matches. Detects forged or replayed results, and altered guard
 * lists, attached to a different response payload. Results are NOT
 * cryptographically attested — only trust results produced in-process.
 */
export function verifyBinding(
    result: VerificationResult,
    response?: any
): boolean {
    if (!result.binding) return false;
    const payload = response === undefined ? result.response : response;
    let digest: string;
    try {
        digest = bindingDigest(payload, result.binding.guards);
    } catch {
        // Cyclic / non-serializable payload — cannot match any binding.
        return false;
    }
    return digest === result.binding.digest;
}

/**
 * Main verifier for AI responses.
 */
export class ResponseVerifier {
    private defaultGuards: BaseGuard[];
    private strictMode: boolean;
    private allowWarnings: boolean;

    constructor(
        guards: BaseGuard[] = [],
        options: { strictMode?: boolean; allowWarnings?: boolean } = {}
    ) {
        this.defaultGuards = guards;
        this.strictMode = options.strictMode ?? true;
        this.allowWarnings = options.allowWarnings ?? true;
    }

    /**
     * Verify a response against guards.
     */
    verify(
        response: any,
        guards?: BaseGuard[],
        context?: Record<string, any>
    ): VerificationResult {
        const guardsToUse = guards ?? this.defaultGuards;
        const parsedResponse = this.parseResponse(response);

        // Fail-closed: zero guards must never produce verified=true (#27).
        if (guardsToUse.length === 0) {
            return {
                verified: false,
                response: parsedResponse,
                guardsPassed: 0,
                guardsFailed: 0,
                guardResults: [{
                    guardName: 'ResponseVerifier',
                    passed: false,
                    message: 'No guards configured — verification cannot be performed. Pass at least one guard or set defaultGuards.',
                    severity: 'error',
                }],
                blocked: this.strictMode,
                blockReason: 'No guards configured — fail-closed (zero-guard verify).',
                timestamp: new Date().toISOString(),
                binding: safeBinding(parsedResponse, []),
            };
        }

        const guardResults: GuardResult[] = [];
        let guardsPassed = 0;
        let guardsFailed = 0;
        let blocked = false;
        let blockReason: string | undefined;

        for (const guard of guardsToUse) {
            try {
                const result = guard.check(parsedResponse, context);
                guardResults.push(result);

                // #31 semantics: a warning PASSES the guard but stays
                // visible via severity. It only fails/blocks verification
                // when warnings are not allowed (allowWarnings=false).
                const failed = !result.passed
                    || (result.severity === 'warning' && !this.allowWarnings);

                if (failed) {
                    guardsFailed++;
                    if (
                        this.strictMode
                        && (result.severity === 'error'
                            || (result.severity === 'warning' && !this.allowWarnings))
                    ) {
                        blocked = true;
                        blockReason = result.message;
                    }
                } else {
                    guardsPassed++;
                }
            } catch (error) {
                guardResults.push({
                    guardName: guard.name,
                    passed: false,
                    message: `Guard error: ${error instanceof Error ? error.message : String(error)}`,
                    severity: 'error',
                });
                guardsFailed++;
            }
        }

        const guardNames = guardsToUse.map((g) => g.name);
        const binding = safeBinding(parsedResponse, guardNames);
        if (!binding) {
            // #31 review (Greptile P1): a cyclic / non-serializable response
            // must yield a failed VerificationResult, never an exception.
            guardResults.push({
                guardName: 'ResponseVerifier',
                passed: false,
                message:
                    'Response could not be bound — cyclic or non-serializable '
                    + 'structure. Failing closed.',
                severity: 'error',
            });
            return {
                verified: false,
                response: parsedResponse,
                guardsPassed,
                guardsFailed: guardsFailed + 1,
                guardResults,
                blocked: this.strictMode,
                blockReason: this.strictMode
                    ? 'Response could not be bound — cyclic or non-serializable structure.'
                    : undefined,
                timestamp: new Date().toISOString(),
            };
        }

        return {
            verified: guardsFailed === 0,
            response: parsedResponse,
            guardsPassed,
            guardsFailed,
            guardResults,
            blocked,
            blockReason,
            timestamp: new Date().toISOString(),
            // #31: tamper-evidence binding — the digest covers the response
            // AND the guard list. Not a signature; see types.ts.
            binding,
        };
    }

    /**
     * Verify a tool call.
     */
    verifyToolCall(
        toolName: string,
        args: Record<string, any>,
        guards?: BaseGuard[]
    ): VerificationResult {
        const toolCall = {
            type: 'tool_call',
            toolName,
            arguments: args,
        };
        return this.verify(toolCall, guards);
    }

    private parseResponse(response: any): ParsedResponse {
        // Parse strictness mirrors Python _parse_response (#30): Python
        // raises ValueError for non-dict/scalar inputs — npm must reject
        // them too, not wrap them as {type:'unknown'} and verify them.
        if (response !== null && typeof response === 'object' && !Array.isArray(response)) {
            return response;
        }

        if (typeof response === 'string') {
            let parsed: any;
            try {
                parsed = JSON.parse(response);
            } catch {
                return { type: 'text', content: response };
            }
            // JSON arrays are rejected like direct array inputs (Sentry HIGH,
            // PR #34): an array payload bypasses per-item inspection, so its
            // content would verify without ever being checked.
            if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
                const typeName = Array.isArray(parsed)
                    ? 'list'
                    : parsed === null ? 'null' : typeof parsed;
                throw new Error(
                    `Cannot parse JSON response of type ${typeName}. Expected object.`
                );
            }
            return parsed;
        }

        const typeName = response === null ? 'null' : Array.isArray(response) ? 'list' : typeof response;
        throw new Error(
            `Cannot parse response of type ${typeName}. Expected object, string, or JSON.`
        );
    }
}
