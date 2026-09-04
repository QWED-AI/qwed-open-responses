/**
 * QWED Open Responses - Types
 */

export interface GuardResult {
    guardName: string;
    passed: boolean;
    message?: string;
    details?: Record<string, any>;
    severity: 'error' | 'warning' | 'info';
}

/**
 * Tamper-evidence binding set by ResponseVerifier.verify (#31): SHA-256 of
 * the canonical verified response plus the guard names. Results without a
 * binding are untrusted (hand-constructed / replayed).
 */
export interface ResultBinding {
    responseSha256: string;
    guards: string[];
}

export interface VerificationResult {
    verified: boolean;
    response: any;
    guardsPassed: number;
    guardsFailed: number;
    guardResults: GuardResult[];
    blocked: boolean;
    blockReason?: string;
    timestamp: string;
    binding?: ResultBinding;
}

export interface ToolCall {
    type?: string;
    toolName?: string;
    tool_name?: string;
    name?: string;
    arguments?: Record<string, any>;
}

export interface ParsedResponse {
    type?: string;
    content?: string;
    output?: any;
    toolCalls?: ToolCall[];
    tool_calls?: ToolCall[];
    [key: string]: any;
}
