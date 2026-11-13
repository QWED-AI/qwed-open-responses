const { ToolGuard } = require('../dist/guards');
const { collapseDotSpacing, normalizedType, pyStrip } = require('../dist/tool-call-envelopes');

// One call source per response, and nothing hidden beside it. A harmless
// call in one envelope must not let a call in another go unchecked, whatever
// `object` says. A response object's output must be a list of objects.
// Argument normalisation stays linear on long inputs. Mirrors
// tests/test_tool_call_sources.py; shared cases are in
// tests/fixtures/tool_guard_envelope_parity.json.

const RM_RF = {
    type: 'local_shell_call',
    call_id: 'call_9',
    action: { type: 'exec', command: ['rm', '-rf', '/'], env: {} },
};
const BASH_CALL = { type: 'function_call', call_id: 'call_1', name: 'bash', arguments: '{"cmd": "ls"}' };
const SEARCH_CALL = { type: 'function_call', call_id: 'call_2', name: 'search', arguments: '{}' };
const SEARCH_TOOL_CALLS = [{ type: 'function', function: { name: 'search', arguments: '{}' } }];
const SEARCH_TOOL_USE = { type: 'tool_use', id: 'toolu_1', name: 'search', input: {} };

function check(response) {
    return new ToolGuard({ allowedTools: ['search'] }).check(response);
}

const HIDDEN_BESIDE_A_SAFE_CALL = {
    'output list with no object': { output: [RM_RF], tool_calls: SEARCH_TOOL_CALLS },
    'output list beside toolCalls': { output: [RM_RF], toolCalls: [{ name: 'search', arguments: {} }] },
    'realtime.response object': { object: 'realtime.response', output: [BASH_CALL], tool_calls: SEARCH_TOOL_CALLS },
    'stream item': { type: 'response.output_item.done', item: RM_RF, tool_calls: SEARCH_TOOL_CALLS },
    'response wrapper': {
        type: 'response.completed',
        response: { object: 'response', output: [RM_RF] },
        tool_calls: SEARCH_TOOL_CALLS,
    },
    'output list beside a tool_use block': { output: [RM_RF], content: [SEARCH_TOOL_USE] },
    'unknown item in an output list': { output: [{ type: 'exec_call', command: 'rm -rf /' }], tool_calls: SEARCH_TOOL_CALLS },
    'unknown stream item beside a response object call': { object: 'response', output: [SEARCH_CALL], item: { type: 'exec_call' } },
    'legacy function_call beside message tool_calls': {
        choices: [{ message: { tool_calls: SEARCH_TOOL_CALLS, function_call: { name: 'bash', arguments: '{}' } } }],
    },
    'function_call block beside a tool_use block': { content: [SEARCH_TOOL_USE, BASH_CALL] },
    'root tool_name and arguments beside tool_calls': { tool_name: 'bash', arguments: { cmd: 'ls' }, tool_calls: SEARCH_TOOL_CALLS },
    'output list on a direct tool_call': { type: 'tool_call', tool_name: 'search', arguments: {}, output: [RM_RF] },
    'stream item on a direct function_call': { ...SEARCH_CALL, item: RM_RF },
};

describe('one call source per response', () => {
    test.each(Object.entries(HIDDEN_BESIDE_A_SAFE_CALL))('%s fails closed', (_name, response) => {
        const result = check(response);
        expect(result.passed).toBe(false);
        expect(result.message).toContain('unrecognized format');
    });

    test('a response wrapper chain is followed to the scan bound', () => {
        const wrapped = (depth, inner) => {
            let value = inner;
            for (let level = 0; level < depth; level++) value = { type: 'response.completed', response: value };
            return value;
        };
        const hidden = { object: 'response', output: [{ type: 'exec_call' }] };
        for (const depth of [1, 11]) {
            expect(check({ ...wrapped(depth, hidden), tool_calls: SEARCH_TOOL_CALLS }).passed).toBe(false);
        }
        // Past the bound the chain cannot be read to the end, so it fails
        // closed even with nothing executable inside.
        expect(check({ ...wrapped(13, { output: [] }), tool_calls: SEARCH_TOOL_CALLS }).passed).toBe(false);
        expect(check({ ...wrapped(2, { output: [] }), tool_calls: SEARCH_TOOL_CALLS }).passed).toBe(true);
    });

    test.each([
        ['chat completion', {
            object: 'chat.completion',
            choices: [{
                index: 0,
                message: { role: 'assistant', content: null, refusal: null, annotations: [], function_call: null, tool_calls: SEARCH_TOOL_CALLS },
                finish_reason: 'tool_calls',
            }],
            usage: { prompt_tokens: 9, completion_tokens: 3 },
        }],
        ['anthropic message', {
            type: 'message',
            role: 'assistant',
            content: [
                { type: 'text', text: 'Searching.' },
                { type: 'server_tool_use', id: 'srvtoolu_1', name: 'web_search', input: { query: 'q' } },
                SEARCH_TOOL_USE,
            ],
            stop_reason: 'tool_use',
            usage: { input_tokens: 9, output_tokens: 3 },
        }],
        ['tool_call', { type: 'tool_call', tool_name: 'search', arguments: { q: 'x' } }],
        ['function_call', { ...SEARCH_CALL, status: 'completed', id: 'fc_1' }],
        ['response', { object: 'response', output: [SEARCH_CALL] }],
    ])('%s with ordinary fields still verifies', (_name, response) => {
        expect(check(response).passed).toBe(true);
    });

    test.each(['functionCall', 'tool_use', 'toolCalls'])('root action item carrying %s is ambiguous', (key) => {
        const result = check({ type: 'custom_tool_call', name: 'search', input: 'x', [key]: { name: 'bash', arguments: '{}' } });
        expect(result.passed).toBe(false);
        expect(result.message).toContain('Ambiguous hybrid');
    });
});

describe('response object output', () => {
    test.each([
        ['string member', ['text']],
        ['null member', [null, SEARCH_CALL]],
        ['array member', [[BASH_CALL]]],
        ['string', 'hello'],
        ['object', { type: 'message' }],
    ])('%s fails closed', (_name, output) => {
        const result = check({ object: 'response', output });
        expect(result.passed).toBe(false);
        expect(result.message).toContain('output must be a list of objects');
    });

    test('no output means no calls', () => {
        expect(check({ object: 'response', output: null }).passed).toBe(true);
    });

    test('custom_tool_call with a null input fails closed, as in Python', () => {
        const response = { object: 'response', output: [{ type: 'custom_tool_call', call_id: 'c', name: 'search', input: null }] };
        expect(check(response).passed).toBe(false);
    });
});

describe('name and type fields', () => {
    test.each([
        ['direct call', { type: 'tool_call', name: 'search', tool_name: 'bash' }],
        ['nested call', { tool_calls: [{ tool_call: { name: 'search', tool_name: 'bash' } }] }],
        ['custom_tool_call with a blank tool_name', {
            object: 'response',
            output: [{ type: 'custom_tool_call', call_id: 'call_1', name: 'search', tool_name: '  ', input: 'x' }],
        }],
    ])('conflicting name fields say so (#64): %s', (_name, response) => {
        const result = check(response);
        expect(result.passed).toBe(false);
        expect(result.message).toContain('name fields disagree');
    });

    test('strip the same characters as Python str.strip()', () => {
        expect(pyStrip('\u0085\u001c search 　')).toBe('search');
        expect(pyStrip('﻿search')).toBe('﻿search');
        expect(normalizedType(' Function_Call\u0085')).toBe('function_call');
        expect(normalizedType(['response'])).toBe('');
        expect(normalizedType(5)).toBe('');
    });

    test('a padded tool_use type is still a tool call', () => {
        const result = check({ content: [{ type: ' Tool_Use ', name: 'bash', input: {} }] });
        expect(result.passed).toBe(false);
        expect(result.message).toContain("Tool 'bash'");
    });
});

describe('linear argument normalisation', () => {
    test('dot spacing matches the regex it replaces', () => {
        const old = /\s*\.\s*/g;
        const alphabet = [' ', '\t', '\n', '　', '﻿', '.', 'a', 'b'];
        let seed = 64;
        const next = (limit) => {
            seed = (seed * 1103515245 + 12345) % 2147483648;
            return seed % limit;
        };
        for (let run = 0; run < 3000; run++) {
            let value = '';
            const length = next(25);
            for (let index = 0; index < length; index++) value += alphabet[next(alphabet.length)];
            expect(collapseDotSpacing(value)).toBe(value.replace(old, '.'));
        }
    });

    test.each([
        ['spaces', ' '.repeat(99000)],
        ['spaces then text', ' '.repeat(99000) + 'x'],
        ['mixed whitespace', 'a' + ' \t'.repeat(49000) + 'b'],
        ['dots and spaces', '. '.repeat(49000)],
    ])('long %s in output calls are checked quickly', (_name, text) => {
        const output = Array.from({ length: 10 }, (_unused, index) => ({
            type: 'custom_tool_call', call_id: `call_${index}`, name: 'search', input: text,
        }));
        const started = Date.now();
        const result = check({ object: 'response', output });
        const elapsed = Date.now() - started;
        expect(result.passed).toBe(true);
        // The regex took seconds per 99,000-space item; this takes
        // milliseconds. The bound leaves room for slow CI runners.
        expect(elapsed).toBeLessThan(5000);
    });

    test('spaced dangerous calls are still folded', () => {
        const result = check({ type: 'tool_call', tool_name: 'search', arguments: { q: "os 　.\n system('id')" } });
        expect(result.passed).toBe(false);
    });
});
