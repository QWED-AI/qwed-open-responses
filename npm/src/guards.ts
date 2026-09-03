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

    // Unified cross-language superset — every pattern case-insensitive.
    // Mirrors Python DEFAULT_DANGEROUS_PATTERNS exactly; the previously
    // missing del/format/sudo/chmod/subprocess/os.system entries are the
    // #30 divergences (Python blocked them, npm passed them).
    private static DEFAULT_DANGEROUS_PATTERNS = [
        /DROP\s+TABLE/i,
        /DELETE\s+FROM/i,
        /TRUNCATE\s+TABLE/i,
        /rm\s+-rf/i,
        /rmdir\s+\/s/i,
        /del\s+\/f/i,
        /format\s+c:/i,
        /sudo\s+/i,
        /chmod\s+777/i,
        /eval\s*\(/i,
        /exec\s*\(/i,
        /__import__/i,
        /subprocess/i,
        /os\.system/i,
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

            // Check dangerous patterns — serialization itself can throw
            // (circular refs / extreme depth), so fail closed on it.
            let argsStr: string;
            try {
                argsStr = JSON.stringify(args);
            } catch {
                return this.failResult('BLOCKED: Tool arguments could not be serialized');
            }
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

        // Multiple independent top-level collections at once is ambiguous and
        // would double-count under max_calls_per_response - reject (Sentry LOW).
        const presentCollections = [
            'toolCalls', 'tool_calls', 'choices', 'content',
        ].filter((k) => (response as any)[k] !== undefined);
        if (presentCollections.length > 1) {
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
                // Case-insensitive to match the dict-content path below — a
                // mixed-case "Tool_Use" block is a tool call (Sentry HIGH).
                if (
                    block !== null && typeof block === 'object' &&
                    String(block.type || '').toLowerCase() === 'tool_use'
                ) {
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
        } else if (content !== null && content !== undefined && typeof content === 'object') {
            // Dict-valued content is a valid format for some APIs. Only a
            // direct tool_use block is a tool call; a tool-shaped object
            // nested inside is ambiguous and malformed; benign dicts carry
            // no tools (Sentry HIGH).
            if (String(content.type || '').toLowerCase() === 'tool_use') {
                calls.push({
                    type: 'tool_call',
                    tool_name: content.name || '',
                    arguments: content.input || {},
                });
            } else if (this.containsNestedToolShape(content, 0)) {
                calls.push(ToolGuard.malformedEntry());
            }
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
        }

        return normalized;
    }

    private static MAX_ARGS_JSON_CHARS = 10_000;

    private static MAX_ARGS_JSON_DEPTH = 128;

    /**
     * Non-recursive max container nesting depth of a value.
     * Returns -1 when an ancestor back-reference (true cycle) is detected.
     * Containers shared by siblings (acyclic DAG references) are allowed —
     * enter/exit bookkeeping keeps the visited set to the active path only.
     */
    private static argumentsDepth(obj: any): number {
        if (obj === null || typeof obj !== 'object') return 0;
        let max = 0;
        type Frame = [any, number, boolean];
        const stack: Frame[] = [[obj, 1, true]];
        const onPath = new Set<any>();
        while (stack.length > 0) {
            const frame = stack.pop()!;
            const node = frame[0];
            const depth = frame[1];
            const entering = frame[2];
            if (!entering) {
                onPath.delete(node);
                continue;
            }
            if (onPath.has(node)) return -1;
            onPath.add(node);
            if (depth > max) max = depth;
            stack.push([node, depth, false]);
            const children: any[] = Array.isArray(node)
                ? node
                : Object.values(node);
            for (const child of children) {
                if (child !== null && typeof child === 'object') {
                    stack.push([child, depth + 1, true]);
                }
            }
        }
        return max;
    }

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
            // Bound structural depth before JSON.stringify can overflow the
            // stack on deeply nested objects (Greptile P1, mirror of Python).
            // A negative depth means a cycle — fail closed on that too.
            const argsDepth = ToolGuard.argumentsDepth(raw);
            if (argsDepth < 0 || argsDepth > ToolGuard.MAX_ARGS_JSON_DEPTH) {
                return { ok: false };
            }
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
                if (fn !== null && typeof fn === 'object' && !Array.isArray(fn)) {
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
                // Non-object `function` value is an incidental key (e.g. string
                // metadata), not a wrapper — fall through; the call is still
                // policy-checked by name in check(), and a nameless call is
                // rejected there (Sentry: valid tool_call must not be blocked).
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

    private static PII_PATTERNS = {
        email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
        phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
        ssn: /\b\d{3}-\d{2}-\d{4}\b/,
        creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
        // #30 parity: Python detects IPs, npm silently passed them.
        ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
    };

    // #30 parity: mirrors Python INJECTION_PATTERNS — the missing five
    // patterns let injection payloads pass on npm while Python blocked them.
    private static INJECTION_PATTERNS = [
        /ignore\s+(previous|all|above)\s+(instructions?|prompts?)/i,
        /disregard\s+(previous|all|above)/i,
        /forget\s+(everything|all|your\s+instructions)/i,
        /you\s+are\s+now\s+/i,
        /act\s+as\s+if\s+you\s+are/i,
        /pretend\s+(you|to\s+be)/i,
        /new\s+instructions?\s*:/i,
        // Requires instruction-override context after the role prefix — a
        // bare "system:" label matches ordinary config text ("system:
        // healthy", "Operating system: Linux") and blocked legitimate
        // responses (Sentry/Greptile P1, PR #34). Filler between the marker
        // and the override term is unbounded but cannot cross another
        // "system:" marker (linear on adversarial input) and cannot cross
        // sentence boundaries (periods excluded, so benign multi-sentence
        // text stays passing). Directives include disclose/leak/expose
        // alongside reveal (Greptile P1, PR #34). Mirrors safety_guard.py.
        /system\s*:\s*(?:(?!\bsystem\s*:)[A-Za-z]+[,:;!?]?\s+)*(?:ignore|disregard|forget|override|you\s+are|act\s+as|pretend|new\s+instructions?|bypass|reveal|disclose|leak|expose)\b/i,
        /<\|.*?\|>/,
        /\[\[.*?\]\]/,
    ];

    // #30 parity: Python's harmful-content check had no npm counterpart at
    // all — "api_key=sk-12345" was BLOCKED on Python and passed on npm.
    // The value part excludes benign placeholder labels ("password:
    // required", "api_key: not set") while still matching real credentials
    // (Sentry/Greptile P1, PR #34). Mirrors safety_guard.py HARMFUL_PATTERNS.
    // Each exemption alternative must match the ENTIRE value — the old \b
    // let "password=required-secret" bypass, and (?=\s|$) let
    // "password=required actual-secret" bypass (credential hidden after
    // whitespace, which \S+ cannot reach). Alternatives now assert only
    // whitespace/punctuation until end-of-string (Greptile P1, PR #34).
    private static CREDENTIAL_PATTERNS = [
        /password\s*[=:]\s*(?!(?:required|optional|none|null|redacted|omitted|placeholder|invalid|expired|not[_\s]?(?:set|provided)|n\/?a)(?=[\s.,;:!?)\]]*$)|\*{3,}(?=[\s.,;:!?)\]]*$)|x{3,}(?=[\s.,;:!?)\]]*$))\S+/i,
        /api[_-]?key\s*[=:]\s*(?!(?:required|optional|none|null|redacted|omitted|placeholder|invalid|expired|not[_\s]?(?:set|provided)|n\/?a)(?=[\s.,;:!?)\]]*$)|\*{3,}(?=[\s.,;:!?)\]]*$)|x{3,}(?=[\s.,;:!?)\]]*$))\S+/i,
        /secret\s*[=:]\s*(?!(?:required|optional|none|null|redacted|omitted|placeholder|invalid|expired|not[_\s]?(?:set|provided)|n\/?a)(?=[\s.,;:!?)\]]*$)|\*{3,}(?=[\s.,;:!?)\]]*$)|x{3,}(?=[\s.,;:!?)\]]*$))\S+/i,
        // Value-aware label form (same placeholder exemption as above) —
        // "private[_-]?key" bare-matching blocked benign labels such as
        // "private_key: not set" (Greptile P1, PR #34). [\s_-]? also catches
        // the spaced "private key: <value>" form. Mirrors safety_guard.py.
        /private[\s_-]?key\s*[=:]\s*(?!(?:required|optional|none|null|redacted|omitted|placeholder|invalid|expired|not[_\s]?(?:set|provided)|n\/?a)(?=[\s.,;:!?)\]]*$)|\*{3,}(?=[\s.,;:!?)\]]*$)|x{3,}(?=[\s.,;:!?)\]]*$))\S+/i,
    ];

    private static HARMFUL_PATTERNS = [
        ...SafetyGuard.CREDENTIAL_PATTERNS,
        // Dashed PEM header only: without the leading dashes the
        // case-insensitive pattern matches ordinary prose like "begin
        // private key rotation" (CodeRabbit, PR #34). Real PEM data
        // always carries the delimiter. Python applies re.I to all
        // HARMFUL_PATTERNS — case-insensitive here too (CodeAnt, PR #34).
        /-{3,}\s*BEGIN\s+(?:[A-Z0-9]+\s+)*PRIVATE\s+KEY/i,
    ];

    // Credential-shaped tail tokens for guidance-prose detection below.
    // The prefix alternation is literal-only (linear, no nesting).
    private static CRED_PREFIX_RE = /sk-|ghp_|glpat-|xox[baprs]?-|eyJ|akia|-----BEGIN/i;
    private static PROSE_MIN_TOKENS = 5;
    private static LABEL_VALUE_RE =
        /\b(password|api[_-]?key|secret|private[\s_-]?key)\s*[=:]\s*(\S+)([\s\S]*)/i;

    private static isCredentialShapedToken(token: string): boolean {
        if (SafetyGuard.CRED_PREFIX_RE.test(token)) return true;
        if (token.length >= 16 && !token.includes('=') && !token.includes(':')) return true;
        if ((token.includes('-') || token.includes('_')) && (/\d/.test(token) || token.length >= 12)) return true;
        let run = 0;
        let hasDigit = false;
        const flush = () => {
            const hit = run >= 6 && hasDigit;
            run = 0;
            hasDigit = false;
            return hit;
        };
        for (const c of token) {
            if (/[A-Za-z0-9_]/.test(c)) {
                run++;
                if (/\d/.test(c)) hasDigit = true;
            } else if (flush()) {
                return true;
            }
        }
        return flush();
    }

    private static isGuidanceProse(text: string): boolean {
        const tokens = text.split(/\s+/).filter(Boolean);
        if (tokens.length < SafetyGuard.PROSE_MIN_TOKENS) return false;
        return !tokens.some((t) => SafetyGuard.isCredentialShapedToken(t));
    }

    private static placeholderTailAllows(leaf: string): boolean {
        const m = SafetyGuard.LABEL_VALUE_RE.exec(leaf);
        if (!m) return false;
        const probe = `${m[1]}=${m[2]}`;
        if (SafetyGuard.CREDENTIAL_PATTERNS.some((p) => p.test(probe))) return false;
        const tail = m[3].split(/\s+/).filter(Boolean);
        if (tail.length === 0) return true;
        if (tail.some((t) => SafetyGuard.isCredentialShapedToken(t))) return false;
        return tail.length >= 2;
    }

    private checkPii: boolean;
    private checkInjection: boolean;
    private checkHarmful: boolean;

    constructor(options: {
        checkPii?: boolean;
        checkInjection?: boolean;
        checkHarmful?: boolean;
    } = {}) {
        super();
        this.checkPii = options.checkPii ?? true;
        this.checkInjection = options.checkInjection ?? true;
        this.checkHarmful = options.checkHarmful ?? true;
    }

    check(response: ParsedResponse, context?: Record<string, any>): GuardResult {
        let content: string;
        try {
            content = this.extractContent(response);
        } catch (err) {
            // Cyclic / unserializable structures cannot be inspected —
            // fail closed instead of crashing the caller (Greptile P1).
            return this.failResult(
                'BLOCKED: Response content could not be safely inspected '
                + '(cyclic or unserializable structure).',
                { error: String(err) },
            );
        }
        // Python parity: issues is a uniform array of
        // {type, severity, details} objects for BOTH paths — the error path
        // (all issues, errors AND warnings) and the warning-only path
        // (Sentry, PR #34: PII used to be plain strings here and verbose
        // {type: 'PII detected: email', details: []} objects there).
        const issues: Array<{ type: string; severity: string; details: string[] }> = [];
        // Error-severity issues are COLLECTED across checks — matching
        // Python, which appends injection and harmful findings together and
        // reports the total (CodeAnt nitpick, PR #34: returning on the first
        // harmful pattern discarded PII and other diagnostics).
        const errorIssues: Array<{ type: string; severity: string; details: string[] }> = [];

        if (this.checkPii) {
            // Python parity: one {type:'pii', severity:'warning'} entry whose
            // details carry the matched PII types (email, phone, ...).
            const piiTypes: string[] = [];
            for (const [type, pattern] of Object.entries(SafetyGuard.PII_PATTERNS)) {
                if (pattern.test(content)) {
                    piiTypes.push(type);
                }
            }
            if (piiTypes.length > 0) {
                issues.push({ type: 'pii', severity: 'warning', details: piiTypes });
            }
        }

        if (this.checkInjection) {
            const injections: string[] = [];
            for (const pattern of SafetyGuard.INJECTION_PATTERNS) {
                if (pattern.test(content)) {
                    injections.push(pattern.source);
                }
            }
            if (injections.length > 0) {
                const entry = { type: 'injection', severity: 'error', details: injections };
                issues.push(entry);
                errorIssues.push(entry);
            }
        }

        if (this.checkHarmful) {
            // Mirrors Python: harmful content is an ERROR-severity issue
            // (fails the guard), unlike PII which is only a warning (#30).
            // Evaluated per collected string, not on the joined content —
            // placeholder exemptions must occupy the complete field value
            // (Greptile P1, PR #34); joined extraction artifacts would
            // defeat the end-of-string anchor. Guidance prose skips only
            // the credential patterns, never PEM (Sentry/Greptile P1).
            const harmful: string[] = [];
            for (const leaf of this.extractLeafStrings(response)) {
                if (SafetyGuard.isGuidanceProse(leaf)) continue;
                if (SafetyGuard.placeholderTailAllows(leaf)) continue;
                for (const pattern of SafetyGuard.HARMFUL_PATTERNS) {
                    if (pattern.test(leaf) && !harmful.includes(pattern.source)) {
                        harmful.push(pattern.source);
                    }
                }
            }
            if (harmful.length > 0) {
                const entry = { type: 'harmful', severity: 'error', details: harmful };
                issues.push(entry);
                errorIssues.push(entry);
            }
        }

        if (errorIssues.length > 0) {
            return this.failResult(
                `Safety check failed: ${errorIssues.length} critical issue(s)`,
                // All detected issues — errors AND warnings — match Python,
                // which returns details={'issues': issues} with everything
                // (Sentry, PR #34: PII warnings were discarded when a
                // critical issue co-existed).
                { issues },
            );
        }

        if (issues.length > 0) {
            return this.failResult(
                `Safety warnings: ${issues.length} warning(s)`,
                { issues },
                'warning',
            );
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

    private extractLeafStrings(response: ParsedResponse, depth: number = 0): string[] {
        // Every string leaf for per-field harmful evaluation (mirrors
        // Python _collect_leaf_strings). Dict entries contribute both the
        // bare value and the `key=value` form: the bare value alone drops
        // the field context credential patterns match on, so
        // `{"password": "hunter2"}` would otherwise verify uninspected
        // (Greptile P1, PR #34). The strict placeholder exemption still
        // judges the `key=value` form. Bounded like extractContent so
        // deeply nested payloads terminate.
        const MAX_DEPTH = 12;
        if (depth > MAX_DEPTH) return [];
        if (typeof response === 'string') return [response];
        if (response === null || typeof response !== 'object') return [];
        const leaves: string[] = [];
        for (const [key, value] of Object.entries(response)) {
            if (typeof value === 'string') {
                leaves.push(value);
                leaves.push(`${key}=${value}`);
            } else if (value !== null && typeof value === 'object') {
                leaves.push(...this.extractLeafStrings(value as ParsedResponse, depth + 1));
            }
        }
        return leaves;
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
