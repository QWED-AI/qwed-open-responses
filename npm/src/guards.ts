/**
 * QWED Open Responses - Guards
 */

import Ajv, { ValidateFunction, ErrorObject } from 'ajv';
import addFormats from 'ajv-formats';
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

            // Unrecognized envelope (#28): fail closed, never pass silently.
            if (call.type === '__unrecognized__') {
                return this.failResult(
                    'BLOCKED: Response contains tool-like content in an unrecognized format. '
                    + 'Supported shapes: type=tool_call, tool_calls[], choices[].message.tool_calls[], '
                    + 'content[].type=tool_use.',
                    { responseKeys: Object.keys(response) },
                );
            }

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

        const respType = String(response.type || '').toLowerCase();

        if (respType === 'tool_call') {
            calls.push(response);
        }

        if (response.toolCalls || response.tool_calls) {
            calls.push(...(response.toolCalls || response.tool_calls || []));
        }

        // OpenAI format
        if (response.choices) {
            for (const choice of (response.choices as any[])) {
                const msg = choice.message || {};
                if (msg.tool_calls) calls.push(...msg.tool_calls);
            }
        }

        // Anthropic format: content blocks with type == "tool_use"
        if (Array.isArray(response.content)) {
            for (const block of (response.content as any[])) {
                if (block !== null && typeof block === 'object' && block.type === 'tool_use') {
                    calls.push({
                        type: 'tool_call',
                        tool_name: block.name || '',
                        arguments: block.input || {},
                    });
                }
            }
        }

        // Responses API direct function_call items (#33 review)
        if (respType === 'function_call') {
            calls.push(response);
        }

        // Normalize (#33 review): flatten function-wrapped calls and decode
        // JSON-encoded argument strings so blocklist/dangerous-argument
        // policies always operate on tool_name/arguments. Unparseable calls
        // become fail-closed sentinels.
        const normalized = this.normalizeCalls(calls);
        if (normalized.length === 0) {
            const isToolShaped = (v: any): boolean =>
                v !== null && typeof v === 'object' &&
                ('name' in v || 'arguments' in v);

            let toolShaped = false;
            for (const key of ['tool_use', 'function_call', 'function']) {
                if (isToolShaped((response as any)[key])) {
                    toolShaped = true;
                    break;
                }
            }

            const hasToolNameWithArgs =
                (response as any).tool_name !== undefined &&
                'arguments' in response;

            let hasNestedToolType = false;
            if (Array.isArray(response.content)) {
                for (const block of (response.content as any[])) {
                    if (block !== null && typeof block === 'object' &&
                        ['tool_use', 'function_call'].includes(String(block.type || '').toLowerCase())) {
                        hasNestedToolType = true;
                        break;
                    }
                }
            }

            if (
                toolShaped ||
                hasToolNameWithArgs ||
                hasNestedToolType ||
                (respType !== 'text' && respType !== '' && respType !== 'message' &&
                 respType !== 'structured_output' && respType.includes('tool'))
            ) {
                normalized.push({ type: '__unrecognized__', tool_name: undefined, arguments: {} });
            }
        }

        return normalized;
    }

    private parseToolArguments(raw: any): { ok: boolean; value?: any } {
        if (raw !== null && typeof raw === 'object' && !Array.isArray(raw)) {
            return { ok: true, value: raw };
        }
        if (typeof raw === 'string') {
            try {
                const parsed = JSON.parse(raw);
                if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
                    return { ok: true, value: parsed };
                }
            } catch {
                // fall through to fail-closed
            }
        }
        return { ok: false };
    }

    private normalizeCalls(calls: any[]): any[] {
        const sentinel = (name?: string): any => ({
            type: '__unrecognized__',
            tool_name: undefined,
            arguments: {},
            attempted_name: name ?? undefined,
        });

        const out: any[] = [];
        for (const call of calls) {
            if (call.type === '__unrecognized__') {
                out.push(call);
                continue;
            }

            // OpenAI function wrapper: {type?, function: {name, arguments}}
            const fn = call.function;
            if (fn !== null && typeof fn === 'object' && fn.name !== undefined) {
                const parsed = this.parseToolArguments(fn.arguments ?? {});
                if (!parsed.ok) {
                    out.push(sentinel(fn.name));
                    continue;
                }
                out.push({ type: 'tool_call', tool_name: fn.name, arguments: parsed.value });
                continue;
            }

            // Responses API direct item: {type: 'function_call', name, arguments}
            if (String(call.type || '').toLowerCase() === 'function_call' && call.name !== undefined) {
                const parsed = this.parseToolArguments(call.arguments ?? {});
                if (!parsed.ok) {
                    out.push(sentinel(call.name));
                    continue;
                }
                out.push({ type: 'tool_call', tool_name: call.name, arguments: parsed.value });
                continue;
            }

            // JSON-encoded argument strings on otherwise-recognized calls
            if (typeof call.arguments === 'string') {
                const parsed = this.parseToolArguments(call.arguments);
                if (!parsed.ok) {
                    out.push(sentinel(call.toolName || call.tool_name || call.name));
                    continue;
                }
                out.push({ ...call, arguments: parsed.value });
                continue;
            }

            out.push(call);
        }
        return out;
    }
}

/**
 * Schema Guard - Validates JSON schema.
 */
export class SchemaGuard extends BaseGuard {
    name = 'SchemaGuard';
    description = 'Validates response against JSON Schema';

    private validate: ValidateFunction;

    constructor(schema: Record<string, any>) {
        super();
        try {
            const ajv = new Ajv({ allErrors: true });
            addFormats(ajv as any);
            this.validate = ajv.compile(schema);
        } catch (error) {
            throw new Error(
                `Invalid JSON Schema: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    check(response: ParsedResponse, context?: Record<string, any>): GuardResult {
        const data = 'output' in response ? response.output : response;

        let valid: boolean;
        try {
            valid = this.validate(data) as boolean;
        } catch {
            return this.failResult('Schema validation error during evaluation');
        }

        if (!valid) {
            const errors = this.validate.errors || [];
            const messages = errors.map((e: ErrorObject) =>
                `${e.instancePath || '/'}: ${e.message}`
            );
            return this.failResult(
                `Schema validation failed: ${errors.length} error(s)`,
                {
                    errors: messages.slice(0, 10),
                    totalErrors: errors.length,
                }
            );
        }

        return this.passResult('Schema validation passed', { schemaValid: true });
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

    private extractContent(response: ParsedResponse, depth: number = 0): string {
        const MAX_DEPTH = 12;
        const parts: string[] = [];

        if (typeof response.content === 'string') parts.push(response.content);
        if (typeof response.output === 'string') parts.push(response.output);
        if (typeof response.text === 'string') parts.push(response.text);

        if (typeof response.output === 'object' && response.output !== null) parts.push(JSON.stringify(response.output));
        if (response.arguments) parts.push(JSON.stringify(response.arguments));

        // Recursive walk for unrecognized shapes (#29). Known keys are
        // traversed too when they hold CONTAINERS (e.g. an Anthropic-style
        // content list of text blocks) — only string/stringified forms were
        // collected above, so nothing hides in a familiar-named key.
        if (depth < MAX_DEPTH) {
            for (const [key, value] of Object.entries(response)) {
                if (value === null || typeof value !== 'object') continue; // strings/scalars collected above where meaningful
                if (key === 'arguments') continue; // already stringified above
                if (key === 'output' && !Array.isArray(value)) continue; // already stringified above
                parts.push(this.extractContent(value as ParsedResponse, depth + 1));
            }
        }

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
