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
        if (typeof response === 'object' && response !== null) {
            return response;
        }

        if (typeof response === 'string') {
            try {
                return JSON.parse(response);
            } catch {
                return { type: 'text', content: response };
            }
        }

        return { type: 'unknown', raw: String(response) };
    }
}
