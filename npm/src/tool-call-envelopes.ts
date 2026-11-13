/**
 * Envelope rules shared by ToolGuard. They live outside guards.ts, which is
 * close to the 100,000-character limit of the QWED Security scanner.
 * Mirrors the matching ToolGuard class attributes in the Python package.
 */

/** Keys under which one call can wrap another. */
export const NESTED_CALL_KEYS = ['tool_call', 'toolCall', 'function_call', 'functionCall'];

/** Root fields that name a call or carry its arguments. */
export const ROOT_CALL_FIELDS = ['toolName', 'tool_name', 'name', 'arguments'];

/** Fields a consumer may dispatch on. All that are present must agree (#64). */
export const IDENTITY_KEYS = ['name', 'tool_name', 'toolName'];

/**
 * Keys that carry another call envelope or call collection. A Responses
 * output[] call item, or the response object around it, carrying one of them
 * is ambiguous: verifying one side would let the other escape.
 */
export const OTHER_CALL_ENVELOPE_KEYS = [
    ...NESTED_CALL_KEYS,
    'function', 'tool_use', 'tool_calls', 'toolCalls', 'choices', 'content',
];

/**
 * Responses API items that ask the CLIENT to execute an action without a
 * function name/arguments envelope: type -> [canonical tool name, payload
 * key] (GHSA-xhq6-w3f2-m5w6). Mirrors Python _CLIENT_ACTION_ITEMS.
 */
export const CLIENT_ACTION_ITEMS: Record<string, [string, string]> = {
    local_shell_call: ['local_shell', 'action'],
    shell_call: ['shell', 'action'],
    apply_patch_call: ['apply_patch', 'operation'],
    computer_call: ['computer_use', 'action'],
};
/** Client-executed items that carry their own tool name. */
export const NAMED_CLIENT_ITEMS = new Set(['custom_tool_call', 'mcp_approval_request']);
/**
 * Provider-hosted tool items report server-side results; they are exempt
 * only from the "*_call" suffix rule, not from name/arguments inspection.
 */
export const HOSTED_TOOL_ITEMS = new Set([
    'web_search_call', 'file_search_call', 'code_interpreter_call',
    'image_generation_call', 'mcp_call',
]);

/** Depth bound shared with the nested tool-shape scan (Python _MAX_NESTED_SCAN_DEPTH). */
export const MAX_NESTED_SCAN_DEPTH = 12;

/** check() messages for each __malformed__ sentinel reason. */
export const MALFORMED_MESSAGES: Record<string, string> = {
    ambiguous_hybrid_envelope: 'BLOCKED: Ambiguous hybrid tool-call envelope - response mixes a direct '
        + 'tool call (type=tool_call/function_call) with a sibling '
        + 'toolCalls/tool_calls/choices/content collection.',
    conflicting_tool_names: 'BLOCKED: Tool call name fields disagree - name, tool_name and '
        + 'toolName must all name the same tool.',
    malformed_output: "BLOCKED: A response object's output must be a list of objects.",
    malformed_entry: 'BLOCKED: Response contains a malformed tool-call entry '
        + '(non-object item in toolCalls/tool_calls or choices[].message.tool_calls). '
        + 'Each entry must be an object with a tool name.',
};

// Characters Python's str.strip() removes. JavaScript's trim() also removes
// U+FEFF but keeps U+001C-U+001F and U+0085, so type and name fields would
// otherwise normalise differently in the two packages.
const PY_WHITESPACE = new Set([
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009,
    0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

/** Python str.strip(), in linear time (a trailing-whitespace regex is quadratic). */
export function pyStrip(value: string): string {
    let start = 0;
    let end = value.length;
    while (start < end && PY_WHITESPACE.has(value.charCodeAt(start))) start++;
    while (end > start && PY_WHITESPACE.has(value.charCodeAt(end - 1))) end--;
    return value.slice(start, end);
}

/** Python str.casefold() for the characters tool names and types use. */
export function casefold(name: string): string {
    // ASCII folds the same as toLowerCase(); skip the per-character walk.
    if (/^[\x00-\x7f]*$/.test(name)) return name.toLowerCase();
    return Array.from(name, (character) => {
        const codePoint = character.codePointAt(0);
        if (codePoint === undefined) return character;

        // Python casefold preserves dotless i and folds Cherokee to uppercase.
        if (codePoint === 0x0131 || (codePoint >= 0x13a0 && codePoint <= 0x13f5)) {
            return character;
        }
        if (codePoint === 0x1e9e) return 'ss';
        if (codePoint >= 0x13f8 && codePoint <= 0x13fd) {
            return String.fromCodePoint(codePoint - 0x8);
        }
        if (codePoint >= 0xab70 && codePoint <= 0xabbf) {
            return String.fromCodePoint(codePoint - 0x97d0);
        }

        // Per-code-point upper/lower casing supplies full-fold expansions
        // without locale-sensitive or context-sensitive sigma behaviour.
        return Array.from(character.toUpperCase(), (upperCharacter) =>
            upperCharacter.toLowerCase(),
        ).join('');
    }).join('');
}

/** Fold case and surrounding whitespace without merging separators. */
export function normalizeToolIdentity(name: string): string {
    return casefold(pyStrip(name));
}

/**
 * A protocol type marker (type / object) as Python's _normalized_type reads
 * it: strings only, stripped and case-folded; anything else is ''.
 */
export function normalizedType(value: unknown): string {
    return typeof value === 'string' ? normalizeToolIdentity(value) : '';
}

/**
 * Remove whitespace around each '.' in linear time. Same result as replacing
 * every match of the regex \s*\.\s* with '.' (trimStart / trimEnd remove
 * exactly what \s matches), but that regex backtracks quadratically over a
 * long whitespace run with no dot.
 */
export function collapseDotSpacing(value: string): string {
    if (!value.includes('.')) return value;
    const parts = value.split('.');
    const last = parts.length - 1;
    return parts.map((part, index) => {
        const piece = index > 0 ? part.trimStart() : part;
        return index < last ? piece.trimEnd() : piece;
    }).join('.');
}

function hasOwn(value: object, key: string): boolean {
    return Object.prototype.hasOwnProperty.call(value, key);
}

function isPlainObject(value: unknown): value is Record<string, any> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Fail-closed sentinel for a malformed or ambiguous envelope. */
export function malformedEntry(reason?: string): Record<string, any> {
    const entry: Record<string, any> = { type: '__malformed__', tool_name: undefined, arguments: {} };
    if (reason) entry.reason = reason;
    return entry;
}

/** Fail-closed sentinel for a call that cannot be read. */
export function unrecognizedEntry(reason: string, name?: unknown): Record<string, any> {
    return {
        type: '__unrecognized__',
        tool_name: undefined,
        arguments: {},
        reason,
        attempted_name: name ?? undefined,
    };
}

/**
 * Whether an item type requests client-side execution. Known client action
 * items always match. With `includeUnknown`, any other `*_call` /
 * `*_request` type (except provider-hosted items) matches too, so new or
 * unmodelled executable items fail closed. The suffix rule is applied only
 * to known protocol item positions, because ordinary data uses such type
 * labels (pull_request, refund_request, phone_call). Mirrors Python.
 */
export function isActionItemType(type: string, includeUnknown = false): boolean {
    const itemType = normalizedType(type);
    if (hasOwn(CLIENT_ACTION_ITEMS, itemType) || NAMED_CLIENT_ITEMS.has(itemType)) {
        return true;
    }
    if (!includeUnknown || HOSTED_TOOL_ITEMS.has(itemType)) return false;
    return itemType.endsWith('_call') || itemType.endsWith('_request');
}

/** Whether a value also carries another call envelope or collection. */
export function carriesOtherCallEnvelope(value: object): boolean {
    return OTHER_CALL_ENVELOPE_KEYS.some((key) => hasOwn(value, key));
}

/**
 * Whether the fields that name a call disagree (#64). A consumer may
 * dispatch on name, tool_name or toolName, so every one that is present must
 * name the same tool. Blank strings count as absent; a non-string value
 * beside another name always conflicts.
 */
export function hasConflictingIdentity(call: Record<string, unknown>): boolean {
    const present = IDENTITY_KEYS
        .map((key) => call[key])
        .filter((value) => value !== undefined && value !== null
            && !(typeof value === 'string' && pyStrip(value) === ''));
    if (present.length < 2) return false;
    if (present.some((value) => typeof value !== 'string')) return true;
    return new Set(present.map((value) => normalizeToolIdentity(value as string))).size > 1;
}

/** Whether a value is a Responses call item, known or unknown. */
function isResponseCallItem(item: unknown): boolean {
    if (!isPlainObject(item)) return false;
    const itemType = normalizedType(item.type);
    return itemType === 'function_call' || isActionItemType(itemType, true);
}

/**
 * Whether a value presents Responses call items, whatever its object says:
 * output[] members, a stream event's item, and the same positions inside a
 * response wrapper. Used where another call source was already extracted,
 * so an unknown *_call item there fails closed too. A chain of wrappers
 * deeper than the scan bound fails closed. Mirrors Python
 * _holds_response_call_items.
 */
export function holdsResponseCallItems(value: Record<string, any>): boolean {
    let current = value;
    for (let depth = 0; depth < MAX_NESTED_SCAN_DEPTH; depth++) {
        const output = hasOwn(current, 'output') ? current.output : undefined;
        if (Array.isArray(output) && output.some(isResponseCallItem)) return true;
        if (hasOwn(current, 'item') && isResponseCallItem(current.item)) return true;
        const inner = hasOwn(current, 'response') ? current.response : undefined;
        if (!isPlainObject(inner)) return false;
        current = inner;
    }
    return true;
}

/**
 * A custom_tool_call's input: the string, or '' when it is absent. Any other
 * value, null included, is unusable (undefined) and fails closed, as in
 * Python.
 */
export function customToolInput(call: Record<string, any>): string | undefined {
    if (call.input === undefined) return '';
    return typeof call.input === 'string' ? call.input : undefined;
}

/** Whether a content block is an Anthropic tool_use call. */
export function isToolUseBlock(block: unknown): boolean {
    return isPlainObject(block) && normalizedType(block.type) === 'tool_use';
}

/** Fields a direct call of this root type is read from. */
function directCallFields(rootType: string): string[] {
    const fields = ['type', 'arguments', 'function', ...IDENTITY_KEYS, ...NESTED_CALL_KEYS];
    if (hasOwn(CLIENT_ACTION_ITEMS, rootType)) {
        fields.push(CLIENT_ACTION_ITEMS[rootType][1]);
    } else if (rootType === 'custom_tool_call') {
        fields.push('input');
    }
    return fields;
}

/** A choices[] member without the message.tool_calls it gave. */
function withoutMessageToolCalls(choice: unknown): unknown {
    if (!isPlainObject(choice) || !isPlainObject(choice.message)) return choice;
    const message = { ...choice.message };
    delete message.tool_calls;
    return { ...choice, message };
}

/**
 * The parts of a response that known-shape extraction did not read: drops
 * the direct call's own fields, the toolCalls / tool_calls collection,
 * choices[].message.tool_calls and tool_use content blocks, and keeps
 * everything else for the scan for other calls. Mirrors Python
 * _unextracted_parts.
 */
export function unextractedParts(response: Record<string, any>, rootType: string): Record<string, any> {
    const residual: Record<string, any> = { ...response };
    if (rootType === 'tool_call' || rootType === 'function_call' || isActionItemType(rootType)) {
        for (const key of directCallFields(rootType)) delete residual[key];
    }
    delete residual.tool_calls;
    delete residual.toolCalls;
    if (Array.isArray(residual.choices)) {
        residual.choices = residual.choices.map(withoutMessageToolCalls);
    }
    const content = residual.content;
    if (Array.isArray(content)) {
        residual.content = content.filter((block) => !isToolUseBlock(block));
    } else if (isToolUseBlock(content)) {
        delete residual.content;
    }
    return residual;
}

/**
 * Separate the call items in a response object's output[]. `calls` holds
 * every function_call and client action item, as-is, plus an
 * __unrecognized__ sentinel for each other executable item, so an unknown
 * item still fails closed when a known call sits beside it. `residual` is
 * the response with only the remaining members left in output, for the scan
 * for unrecognised tool content. A response object's output must be a list
 * of objects: any other value, and any member that is not an object, becomes
 * a malformed sentinel. A value that is not a response object, or holds no
 * such item, returns no calls. Mirrors Python _split_response_output.
 */
export function splitResponseOutput(response: any): { calls: any[]; residual: any } {
    if (normalizedType(response.object) !== 'response') {
        return { calls: [], residual: response };
    }
    const output = response.output;
    if (output === undefined || output === null) return { calls: [], residual: response };
    if (!Array.isArray(output)) {
        return { calls: [malformedEntry('malformed_output')], residual: { ...response, output: [] } };
    }
    const calls: any[] = [];
    const remaining: any[] = [];
    for (const item of output) {
        if (!isPlainObject(item)) {
            calls.push(malformedEntry('malformed_output'));
            continue;
        }
        const itemType = normalizedType(item.type);
        if (itemType === 'function_call' || isActionItemType(itemType)) {
            calls.push(item);
        } else if (isActionItemType(itemType, true)) {
            calls.push(unrecognizedEntry('unknown_output_item'));
        } else {
            remaining.push(item);
        }
    }
    if (calls.length === 0) return { calls: [], residual: response };
    return { calls, residual: { ...response, output: remaining } };
}
