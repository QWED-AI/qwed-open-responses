/**
 * QWED Open Responses - Response Verifier
 */

import { BaseGuard } from './guards';
import { VerificationResult, GuardResult, ParsedResponse } from './types';

// Re-export types
export { VerificationResult, GuardResult };

/**
 * Main verifier for AI responses.
 */
export class ResponseVerifier {
    private defaultGuards: BaseGuard[];
    private strictMode: boolean;

    constructor(guards: BaseGuard[] = [], options: { strictMode?: boolean } = {}) {
        this.defaultGuards = guards;
        this.strictMode = options.strictMode ?? true;
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

                if (result.passed) {
                    guardsPassed++;
                } else {
                    guardsFailed++;
                    if (result.severity === 'error' && this.strictMode) {
                        blocked = true;
                        blockReason = result.message;
                    }
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

        return {
            verified: guardsFailed === 0,
            response: parsedResponse,
            guardsPassed,
            guardsFailed,
            guardResults,
            blocked,
            blockReason,
            timestamp: new Date().toISOString(),
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
            try {
                return JSON.parse(response);
            } catch {
                return { type: 'text', content: response };
            }
        }

        const typeName = response === null ? 'null' : Array.isArray(response) ? 'list' : typeof response;
        throw new Error(
            `Cannot parse response of type ${typeName}. Expected object, string, or JSON.`
        );
    }
}
