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
            // Sentinel checks FIRST (mirror Python order): __unrecognized__ /
            // __malformed__ sentinels carry no usable name, so they must be
            // reported with their specific messages before the name check.

            // Unrecognized envelope (#28): fail closed, never pass silently.
            if (call.type === '__unrecognized__') {
                return this.failResult(
                    'BLOCKED: Response contains tool-like content in an unrecognized format. '
                    + 'Supported shapes: type=tool_call, tool_calls[], choices[].message.tool_calls[], '
                    + 'content[].type=tool_use.',
                    { responseKeys: Object.keys(response) },
                );
            }

            // Malformed entry (#33): non-object toolCalls/choices member —
            // fail closed, never forward unvalidated content. An ambiguous
            // hybrid envelope (direct call + sibling collection) is also
            // rejected (Greptile P1).
            if (call.type === '__malformed__') {
                const message = call.reason === 'ambiguous_hybrid_envelope'
                    ? 'BLOCKED: Ambiguous hybrid tool-call envelope - response mixes a direct '
                      + 'tool call (type=tool_call/function_call) with a sibling '
                      + 'toolCalls/tool_calls/choices/content collection.'
                    : 'BLOCKED: Response contains a malformed tool-call entry '
                      + '(non-object item in toolCalls/tool_calls or choices[].message.tool_calls). '
                      + 'Each entry must be an object with a tool name.';
                return this.failResult(
                    message,
                    { responseKeys: Object.keys(response) },
                );
            }

            // A tool call must carry a real name — blank/non-string names can
            // never match blocklist/allowed/dangerous checks, so fail closed
            // rather than reporting an anonymous call verified (#33). NOTE:
            // no 'unknown' fallback — a nameless call (e.g. Anthropic
            // tool_use with missing name) must be BLOCKED, not coerced to a
            // name that passes validation (Sentry MEDIUM).
            const toolName = call.toolName || call.tool_name || call.name;
            if (!ToolGuard.validToolName(toolName)) {
                return this.failResult(
                    'BLOCKED: Tool call has no valid (non-blank string) name.',
                    { responseKeys: Object.keys(response) },
                );
            }
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

    private static validToolName(name: any): boolean {
        // A tool-call name must be a non-empty string to be verifiable (#33).
        return typeof name === 'string' && name.trim().length > 0;
    }

    private static malformedEntry(reason?: string): Record<string, any> {
        const entry: Record<string, any> = { type: '__malformed__', tool_name: undefined, arguments: {} };
        if (reason) entry.reason = reason;
        return entry;
    }

    private extractToolCalls(response: ParsedResponse): any[] {
        const calls: any[] = [];

        const respType = String(response.type || '').toLowerCase();

        // Ambiguous hybrid envelope: a direct tool-call object that ALSO
        // carries a sibling collection. Reject instead of choosing one side,
        // which would let the other escape validation (Greptile P1).
        const isDirect = respType === 'tool_call' || respType === 'function_call';
        const hasSibling = response.toolCalls !== undefined
            || response.tool_calls !== undefined
            || response.choices !== undefined
            || response.content !== undefined;
        if (isDirect && hasSibling) {
            return [ToolGuard.malformedEntry('ambiguous_hybrid_envelope')];
        }

        if (respType === 'tool_call') {
            calls.push(response);
        } else {
            // List of tool calls. When the object is itself a tool_call we
            // already returned above, so this else avoids double-counting a
            // sibling toolCalls array (Sentry MEDIUM). A non-array container
            // (scalar/dict) is malformed, not a for...of TypeError (#33).
            const tc = response.toolCalls ?? response.tool_calls ?? [];
            if (Array.isArray(tc)) {
                for (const item of tc) {
                    if (item !== null && typeof item === 'object') {
                        calls.push(item);
                    } else {
                        calls.push(ToolGuard.malformedEntry());
                    }
                }
            } else if (tc !== null) {
                calls.push(ToolGuard.malformedEntry());
            }
        }

        // OpenAI format — validate each choice and its tool_calls members.
        const choices = response.choices;
        if (Array.isArray(choices)) {
            for (const choice of choices) {
                if (choice === null || typeof choice !== 'object') {
                    calls.push(ToolGuard.malformedEntry());
                    continue;
                }
                const msg = choice.message;
                if (msg === null || typeof msg !== 'object') continue;
                const mt = msg.tool_calls;
                if (Array.isArray(mt)) {
                    for (const item of mt) {
                        if (item !== null && typeof item === 'object') {
                            calls.push(item);
                        } else {
                            calls.push(ToolGuard.malformedEntry());
                        }
                    }
                } else if (mt !== null && mt !== undefined) {
                    calls.push(ToolGuard.malformedEntry());
                }
            }
        } else if (choices !== null && choices !== undefined) {
            calls.push(ToolGuard.malformedEntry());
        }

        // Anthropic format: content blocks with type == "tool_use"
        const content: any = response.content;
        if (Array.isArray(content)) {
            for (const block of content) {
                if (block !== null && typeof block === 'object' && block.type === 'tool_use') {
                    calls.push({
                        type: 'tool_call',
                        tool_name: block.name || '',
                        arguments: block.input || {},
                    });
                }
            }
        } else if (typeof content === 'string') {
            // Plain-text content (e.g. type=text) is not a tool-block
            // collection — it carries no tool calls (Greptile P1).
        } else if (content !== null && content !== undefined) {
            calls.push(ToolGuard.malformedEntry());
        }

        // Responses API direct function_call items (#33 review). Only when
        // the known shapes yielded nothing — a hybrid envelope carrying both
        // must not double-count.
        if (!calls.length && respType === 'function_call') {
            calls.push(response);
        }

        // Normalize (#33 review): flatten function-wrapped calls and decode
        // JSON-encoded argument strings so blocklist/dangerous-argument
        // policies always operate on tool_name/arguments. Unparseable calls
        // become fail-closed sentinels.
        const normalized = this.normalizeCalls(calls);
        if (normalized.length === 0) {
            // Bounded recursive scan (#33 review): tool-shaped objects nested
            // inside wrappers/arrays must not slip through as "no tool calls".
            if (this.containsNestedToolShape(response, 0)) {
                normalized.push({
                    type: '__unrecognized__',
                    tool_name: undefined,
                    arguments: {},
                });
                return normalized;
            }

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
                return normalized;
            }

            // Declared-benign envelopes are validated structurally above; the
            // bounded deep-scan applies only to undeclared/unmodeled types.
            if (respType !== 'text' && respType !== '' &&
                respType !== 'message' && respType !== 'structured_output') {
                if (this.containsNestedToolShape(response, 0)) {
                    normalized.push({
                        type: '__unrecognized__',
                        tool_name: undefined,
                        arguments: {},
                    });
                }
            }
        }

        return normalized;
    }

    private static MAX_ARGS_JSON_CHARS = 10_000;

    private parseToolArguments(raw: any): { ok: boolean; value?: any } {
        // None / blank payloads are legitimate zero-argument calls.
        if (
            raw === null ||
            raw === undefined ||
            (typeof raw === 'string' && raw.trim() === '')
        ) {
            return { ok: true, value: {} };
        }
        if (raw !== null && typeof raw === 'object' && !Array.isArray(raw)) {
            return { ok: true, value: raw };
        }
        if (typeof raw === 'string') {
            // Fail closed on oversized payloads before parsing (DoS bound).
            if (raw.length > ToolGuard.MAX_ARGS_JSON_CHARS) {
                return { ok: false };
            }
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

    containsNestedToolShape(value: any, depth: number): boolean {
        /** Bounded recursive scan for tool-shaped objects (#33 review). */
        if (depth > 12) return false;
        if (value === null || typeof value !== 'object') return false;
        if (this.isToolShapedDict(value)) return true;
        for (const v of Object.values(value)) {
            if (this.containsNestedToolShape(v, depth + 1)) return true;
        }
        return false;
    }

    private isToolShapedDict(value: any): boolean {
        if (value === null || typeof value !== 'object') return false;
        const t = String(value.type || '').toLowerCase();
        if (t === 'tool_use' || t === 'function_call' || t === 'tool_call') return true;
        return 'tool_name' in value || ('name' in value && 'arguments' in value);
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
            if (call.type === '__unrecognized__' || call.type === '__malformed__') {
                out.push(call);
                continue;
            }

            // OpenAI function wrapper: {type?, function: {name, arguments}}.
            // A present-but-malformed/nameless function must fail closed
            // rather than fall through with dangerous arguments uninspected.
            if ('function' in call) {
                const fn = call.function;
                if (fn !== null && typeof fn === 'object') {
                    const n = fn.name;
                    if (!ToolGuard.validToolName(n)) {
                        out.push(sentinel(call.toolName || call.name || n));
                        continue;
                    }
                    const parsed = this.parseToolArguments(fn.arguments ?? {});
                    if (!parsed.ok) {
                        out.push(sentinel(n));
                        continue;
                    }
                    out.push({ type: 'tool_call', tool_name: n, arguments: parsed.value });
                    continue;
                }
                // function present but null / non-object — malformed wrapper.
                out.push(sentinel(call.toolName || call.name));
                continue;
            }

            // Responses API direct item: {type: 'function_call', name, arguments}
            if (String(call.type || '').toLowerCase() === 'function_call') {
                const n = call.name;
                if (!ToolGuard.validToolName(n)) {
                    out.push(sentinel(undefined));
                    continue;
                }
                const parsed = this.parseToolArguments(call.arguments ?? {});
                if (!parsed.ok) {
                    out.push(sentinel(n));
                    continue;
                }
                out.push({ type: 'tool_call', tool_name: n, arguments: parsed.value });
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
        const KNOWN: Record<string, boolean> = { content: true, output: true, text: true, arguments: true };
        const parts: string[] = [];

        if (typeof response.content === 'string') parts.push(response.content);
        if (typeof response.output === 'string') parts.push(response.output);
        if (typeof response.text === 'string') parts.push(response.text);

        if (typeof response.output === 'object' && response.output !== null) parts.push(JSON.stringify(response.output));
        if (response.arguments) parts.push(JSON.stringify(response.arguments));

        // Recursive walk for unrecognized shapes (#29). Known keys are
        // traversed too when they hold CONTAINERS — and string leaves under
        // unknown keys are COLLECTED so injection/PII text cannot hide in a
        // familiar or arbitrary nested key.
        if (depth < MAX_DEPTH) {
            for (const [key, value] of Object.entries(response)) {
                if (typeof value === 'string') {
                    if (!(key in KNOWN)) parts.push(value);
                    continue; // known-key strings were collected above
                }
                if (value === null || typeof value !== 'object') continue;
                if (key === 'arguments' && !Array.isArray(value)) continue; // already stringified above
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
