/**
 * QWED Open Responses - Guards
 */

import { GuardResult, ParsedResponse } from './types';

/**
 * Base class for all guards.
 */
export abstract class BaseGuard {
    abstract name: string;
    abstract description: string;

    abstract check(response: ParsedResponse, context?: Record<string, any>): GuardResult;

    protected passResult(message?: string, details?: Record<string, any>): GuardResult {
        return {
            guardName: this.name,
            passed: true,
            message: message || `${this.name} passed`,
            details,
            severity: 'info',
        };
    }

    protected failResult(message: string, details?: Record<string, any>, severity: 'error' | 'warning' = 'error'): GuardResult {
        return {
            guardName: this.name,
            passed: false,
            message,
            details,
            severity,
        };
    }
}

/**
 * Tool Guard - Blocks dangerous tool calls.
 */
export class ToolGuard extends BaseGuard {
    name = 'ToolGuard';
    description = 'Validates tool calls for safety';

    private blockedTools: Set<string>;
    private allowedTools: Set<string> | null;
    private dangerousPatterns: RegExp[];

    private static DEFAULT_BLOCKED_TOOLS = new Set([
        'execute_shell', 'shell', 'bash', 'cmd', 'exec', 'eval',
        'delete_file', 'remove_file', 'write_file', 'modify_file',
        'send_email', 'transfer_money', 'make_payment',
    ]);

    private static DEFAULT_DANGEROUS_PATTERNS = [
        /DROP\s+TABLE/i,
        /DELETE\s+FROM/i,
        /TRUNCATE\s+TABLE/i,
        /rm\s+-rf/i,
        /rmdir\s+\/s/i,
        /eval\s*\(/i,
        /exec\s*\(/i,
        /__import__/i,
    ];

    constructor(options: {
        blockedTools?: string[];
        allowedTools?: string[];
        useDefaultBlocklist?: boolean;
        dangerousPatterns?: RegExp[];
    } = {}) {
        super();

        const {
            blockedTools = [],
            allowedTools,
            useDefaultBlocklist = true,
            dangerousPatterns = [],
        } = options;

        this.blockedTools = new Set(blockedTools);
        if (useDefaultBlocklist) {
            ToolGuard.DEFAULT_BLOCKED_TOOLS.forEach(t => this.blockedTools.add(t));
        }

        this.allowedTools = allowedTools ? new Set(allowedTools) : null;
        this.dangerousPatterns = [
            ...ToolGuard.DEFAULT_DANGEROUS_PATTERNS,
            ...dangerousPatterns,
        ];
    }

    check(response: ParsedResponse, context?: Record<string, any>): GuardResult {
        const toolCalls = this.extractToolCalls(response);

        if (toolCalls.length === 0) {
            return this.passResult('No tool calls to verify');
        }

        for (const call of toolCalls) {
            const toolName = call.toolName || call.tool_name || call.name || 'unknown';
            const args = call.arguments || {};

            // Check blocked list
            if (this.blockedTools.has(toolName)) {
                return this.failResult(`BLOCKED: Tool '${toolName}' is not allowed`, { blockedTool: toolName });
            }

            // Check allowed list (whitelist mode)
            if (this.allowedTools && !this.allowedTools.has(toolName)) {
                return this.failResult(`BLOCKED: Tool '${toolName}' is not in allowed list`, {
                    tool: toolName,
                    allowed: Array.from(this.allowedTools),
                });
            }

            // Check dangerous patterns
            const argsStr = JSON.stringify(args);
            for (const pattern of this.dangerousPatterns) {
                if (pattern.test(argsStr)) {
                    return this.failResult('BLOCKED: Dangerous pattern detected in tool arguments', {
                        tool: toolName,
                        pattern: pattern.source,
                    });
                }
            }
        }

        return this.passResult(`All ${toolCalls.length} tool call(s) verified`);
    }

    private extractToolCalls(response: ParsedResponse): any[] {
        const calls: any[] = [];

        if (response.type === 'tool_call') {
            calls.push(response);
        }

        if (response.toolCalls || response.tool_calls) {
            calls.push(...(response.toolCalls || response.tool_calls || []));
        }

        return calls;
    }
}

/**
 * Schema Guard - Validates JSON schema.
 */
export class SchemaGuard extends BaseGuard {
    name = 'SchemaGuard';
    description = 'Validates response against JSON Schema';

    private schema: Record<string, any>;

    constructor(schema: Record<string, any>) {
        super();
        this.schema = schema;
    }

    check(response: ParsedResponse, context?: Record<string, any>): GuardResult {
        const data = response.output || response;

        // Basic type checking (full JSON Schema validation would need ajv)
        if (this.schema.type === 'object' && typeof data !== 'object') {
            return this.failResult('Expected object type');
        }

        if (this.schema.required) {
            const missing = this.schema.required.filter((field: string) => !(field in data));
            if (missing.length > 0) {
                return this.failResult(`Missing required fields: ${missing.join(', ')}`, { missing });
            }
        }

        return this.passResult('Schema validation passed');
    }
}

/**
 * Safety Guard - Comprehensive safety checks.
 */
export class SafetyGuard extends BaseGuard {
    name = 'SafetyGuard';
    description = 'Comprehensive safety checks';

    private checkPii: boolean;
    private checkInjection: boolean;

    private static PII_PATTERNS = {
        email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
        phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
        ssn: /\b\d{3}-\d{2}-\d{4}\b/,
        creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
    };

    private static INJECTION_PATTERNS = [
        /ignore\s+(previous|all|above)\s+(instructions?|prompts?)/i,
        /disregard\s+(previous|all|above)/i,
        /forget\s+(everything|all|your\s+instructions)/i,
        /you\s+are\s+now\s+/i,
        /pretend\s+(you|to\s+be)/i,
    ];

    constructor(options: { checkPii?: boolean; checkInjection?: boolean } = {}) {
        super();
        this.checkPii = options.checkPii ?? true;
        this.checkInjection = options.checkInjection ?? true;
    }

    check(response: ParsedResponse, context?: Record<string, any>): GuardResult {
        const content = this.extractContent(response);
        const issues: string[] = [];

        if (this.checkPii) {
            for (const [type, pattern] of Object.entries(SafetyGuard.PII_PATTERNS)) {
                if (pattern.test(content)) {
                    issues.push(`PII detected: ${type}`);
                }
            }
        }

        if (this.checkInjection) {
            for (const pattern of SafetyGuard.INJECTION_PATTERNS) {
                if (pattern.test(content)) {
                    return this.failResult('BLOCKED: Prompt injection detected', { pattern: pattern.source });
                }
            }
        }

        if (issues.length > 0) {
            return this.failResult(`Safety issues detected: ${issues.join(', ')}`, { issues }, 'warning');
        }

        return this.passResult('All safety checks passed');
    }

    private extractContent(response: ParsedResponse): string {
        const parts: string[] = [];

        if (typeof response.content === 'string') parts.push(response.content);
        if (typeof response.output === 'string') parts.push(response.output);
        if (typeof response.text === 'string') parts.push(response.text);

        if (typeof response.output === 'object') parts.push(JSON.stringify(response.output));
        if (response.arguments) parts.push(JSON.stringify(response.arguments));

        return parts.join(' ');
    }
}

/**
 * Math Guard - Verifies calculations.
 */
export class MathGuard extends BaseGuard {
    name = 'MathGuard';
    description = 'Verifies mathematical calculations';

    private tolerance: number;

    constructor(options: { tolerance?: number } = {}) {
        super();
        this.tolerance = options.tolerance ?? 0.01;
    }

    check(response: ParsedResponse, context?: Record<string, any>): GuardResult {
        const data = response.output || response;

        if (typeof data !== 'object') {
            return this.passResult('No calculations to verify');
        }

        // Check common total patterns
        if ('total' in data && 'subtotal' in data) {
            const subtotal = Number(data.subtotal) || 0;
            const tax = Number(data.tax) || 0;
            const shipping = Number(data.shipping) || 0;
            const discount = Number(data.discount) || 0;
            const total = Number(data.total);

            const expected = subtotal + tax + shipping - discount;

            if (Math.abs(expected - total) > this.tolerance) {
                return this.failResult(
                    `Total mismatch: expected ${expected}, got ${total}`,
                    { expected, actual: total }
                );
            }
        }

        return this.passResult('Math verification passed');
    }
}
