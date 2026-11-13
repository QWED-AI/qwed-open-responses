const { ResponseVerifier } = require('../dist/verifier');
const { ToolGuard } = require('../dist/guards');

// Tool calls in the output[] of a Responses API object. ToolGuard used to fail
// closed on every response object whose output[] held a function_call, even a
// harmless one, because the unknown-item rule from GHSA-xhq6-w3f2-m5w6 had no
// matching extraction. Each known call item is now verified like a standalone
// item; unknown executable items and ambiguous envelopes still fail closed.
// Mirrors tests/test_response_output_items.py.

function functionCall(name, args = {}, callId = 'call_1') {
    return {
        type: 'function_call',
        id: `fc_${callId}`,
        call_id: callId,
        name,
        arguments: JSON.stringify(args),
        status: 'completed',
    };
}

const MESSAGE_ITEM = {
    type: 'message',
    id: 'msg_1',
    role: 'assistant',
    status: 'completed',
    content: [{ type: 'output_text', text: 'Looking that up.', annotations: [] }],
};

function response(items, extra = {}) {
    return {
        id: 'resp_1',
        object: 'response',
        status: 'completed',
        model: 'gpt-test',
        output: items,
        tools: [
            {
                type: 'function',
                name: 'search',
                parameters: { type: 'object', properties: { query: { type: 'string' } } },
                strict: true,
            },
        ],
        ...extra,
    };
}

function verify(value, guards = [new ToolGuard()]) {
    return new ResponseVerifier(guards).verify(value);
}

const noDefaults = () => [new ToolGuard({ useDefaultBlocklist: false })];

describe('ToolGuard output[] call items: allowed', () => {
    test('a harmless function_call verifies', () => {
        const result = verify(response([functionCall('search', { query: 'weather' })]));
        expect(result.verified).toBe(true);
        expect(result.guardResults[0].message).toBe('All 1 tool call(s) verified');
    });

    test('message and function_call together verify', () => {
        expect(verify(response([MESSAGE_ITEM, functionCall('search')])).verified).toBe(true);
    });

    test('every call is checked', () => {
        const result = verify(response([
            functionCall('search', { query: 'a' }, 'c1'),
            functionCall('lookup', { id: 7 }, 'c2'),
        ]));
        expect(result.verified).toBe(true);
        expect(result.guardResults[0].message).toBe('All 2 tool call(s) verified');
    });

    test('an allowlisted call verifies', () => {
        const guards = [new ToolGuard({ allowedTools: ['search'] })];
        expect(verify(response([functionCall('search')]), guards).verified).toBe(true);
    });

    test('a hosted tool item beside a call still passes', () => {
        const hosted = {
            type: 'web_search_call',
            id: 'ws_1',
            status: 'completed',
            action: { type: 'search', query: 'weather' },
        };
        expect(verify(response([hosted, functionCall('search')])).verified).toBe(true);
    });

    test('an allowlisted action item still has its command scanned', () => {
        const guards = [new ToolGuard({ useDefaultBlocklist: false, allowedTools: ['local_shell'] })];
        const benign = {
            type: 'local_shell_call',
            call_id: 'c1',
            action: { type: 'exec', command: ['ls', '-la'], env: {} },
        };
        const dangerous = { ...benign, action: { type: 'exec', command: ['rm', '-rf', '/'] } };
        expect(verify(response([benign]), guards).verified).toBe(true);
        expect(verify(response([dangerous]), guards).verified).toBe(false);
    });
});

describe('ToolGuard output[] call items: blocked', () => {
    test('a blocklisted function_call is blocked', () => {
        const result = verify(response([MESSAGE_ITEM, functionCall('bash', { cmd: 'ls' })]));
        expect(result.verified).toBe(false);
        expect(result.blockReason).toContain("Tool 'bash' is not allowed");
    });

    test('a call outside the allowlist is blocked', () => {
        const guards = [new ToolGuard({ allowedTools: ['search'] })];
        const result = verify(response([functionCall('send_report')]), guards);
        expect(result.verified).toBe(false);
        expect(result.blockReason).toContain('not in allowed list');
    });

    test('one bad call blocks the whole response', () => {
        const result = verify(response([
            functionCall('search', { query: 'a' }, 'c1'),
            functionCall('execute_shell', { cmd: 'ls' }, 'c2'),
        ]));
        expect(result.verified).toBe(false);
    });

    test.each([
        ['sql', { query: 'DROP TABLE users' }],
        ['shell', { query: 'x; rm -rf /' }],
        ['base64', { note: Buffer.from('rm -rf /').toString('base64') }],
    ])('dangerous arguments (%s) are blocked', (_label, args) => {
        const result = verify(response([MESSAGE_ITEM, functionCall('search', args)]));
        expect(result.verified).toBe(false);
        expect(result.blockReason).toContain('Dangerous pattern');
    });

    test.each([
        ['local_shell_call', {
            type: 'local_shell_call',
            call_id: 'c2',
            action: { type: 'exec', command: ['ls'], env: {} },
        }],
        ['apply_patch_call', {
            type: 'apply_patch_call',
            call_id: 'c2',
            operation: { type: 'update_file', path: 'a.py', diff: '' },
        }],
    ])('the default blocklist still covers %s beside a call', (_label, action) => {
        expect(verify(response([functionCall('search', {}, 'c1'), action])).verified).toBe(false);
    });

    test.each([
        ['no name', { type: 'function_call', call_id: 'c1', arguments: '{}' }],
        ['blank name', { type: 'function_call', call_id: 'c1', name: ' ', arguments: '{}' }],
        ['array arguments', { type: 'function_call', call_id: 'c1', name: 'search', arguments: '[1]' }],
        ['bad JSON', { type: 'function_call', call_id: 'c1', name: 'search', arguments: '{' }],
    ])('a malformed function_call (%s) fails closed', (_label, item) => {
        expect(verify(response([item]), noDefaults()).verified).toBe(false);
    });
});

const UNKNOWN_ITEMS = [
    ['future_device_call', { type: 'future_device_call', call_id: 'c9', action: { op: 'wipe' } }],
    ['future_payment_request', { type: 'future_payment_request', id: 'p1', payload: { amount: 5 } }],
    ['tool_call', { type: 'tool_call', tool_name: 'search', arguments: {} }],
];

describe('ToolGuard output[] call items: unknown items', () => {
    test.each(UNKNOWN_ITEMS)('%s alone fails closed', (_label, unknown) => {
        const result = verify(response([unknown]), noDefaults());
        expect(result.verified).toBe(false);
        expect(result.blockReason).toContain('unrecognized format');
    });

    test.each(UNKNOWN_ITEMS)('%s beside a known call fails closed', (_label, unknown) => {
        const known = functionCall('search', { query: 'weather' });
        for (const items of [[unknown, known], [known, unknown]]) {
            const result = verify(response([MESSAGE_ITEM, ...items]), noDefaults());
            expect(result.verified).toBe(false);
            expect(result.blockReason).toContain('unrecognized format');
        }
    });

    test('a named unknown item does not borrow an allowed name', () => {
        const unknown = { type: 'future_device_call', name: 'search', arguments: '{}' };
        const guards = [new ToolGuard({ allowedTools: ['search'] })];
        expect(verify(response([unknown]), guards).verified).toBe(false);
    });
});

describe('ToolGuard output[] call items: mixed content', () => {
    test.each([
        ['tool_use block', { type: 'tool_use', name: 'bash', input: { cmd: 'ls' } }],
        ['name and arguments', { name: 'bash', arguments: { cmd: 'ls' } }],
        ['tool_name', { tool_name: 'bash', arguments: {} }],
    ])('a %s hidden in a message beside a call fails closed', (_label, hidden) => {
        const message = { ...MESSAGE_ITEM, content: [...MESSAGE_ITEM.content, hidden] };
        expect(verify(response([message, functionCall('search')])).verified).toBe(false);
    });

    test('a hosted mcp_call with name and arguments still fails closed', () => {
        const mcpCall = {
            type: 'mcp_call',
            id: 'mcp_1',
            server_label: 'ops',
            name: 'run',
            arguments: '{}',
            output: 'done',
        };
        expect(verify(response([mcpCall, functionCall('search')])).verified).toBe(false);
    });

    test('a message-only response is unchanged', () => {
        expect(verify(response([MESSAGE_ITEM])).verified).toBe(true);
    });

    test('a function_call outside a response object still fails closed', () => {
        const result = verify({ object: 'list', output: [functionCall('search')] });
        expect(result.verified).toBe(false);
        expect(result.blockReason).toContain('unrecognized format');
    });
});

describe('ToolGuard output[] call items: ambiguous hybrids', () => {
    test.each([
        ['tool_calls', { tool_calls: [{ name: 'search', arguments: {} }] }],
        ['toolCalls', { toolCalls: [{ name: 'search', arguments: {} }] }],
        ['choices', { choices: [{ message: { tool_calls: [] } }] }],
        ['content', { content: [{ type: 'text', text: 'hi' }] }],
        ['direct type', { type: 'function_call', name: 'search', arguments: '{}' }],
    ])('a response object with a sibling %s is ambiguous', (_label, extra) => {
        const result = verify(response([functionCall('search')], extra), noDefaults());
        expect(result.verified).toBe(false);
        expect(result.blockReason).toContain('Ambiguous hybrid');
    });

    test('an output action item cannot hide behind a sibling tool_calls array', () => {
        // Before this change only the sibling tool_calls entry was checked,
        // so the local_shell_call in output[] verified clean.
        const shell = {
            type: 'local_shell_call',
            call_id: 'c1',
            action: { type: 'exec', command: ['rm', '-rf', '/'], env: {} },
        };
        const value = response([shell], { tool_calls: [{ name: 'search', arguments: {} }] });
        expect(verify(value).verified).toBe(false);
    });

    test.each([
        ['tool_calls', { tool_calls: [{ name: 'search', arguments: {} }] }],
        ['content', { content: [{ type: 'tool_use', name: 'bash', input: {} }] }],
        ['function wrapper', { function: { name: 'bash', arguments: '{}' } }],
        ['nested tool_call', { tool_call: { name: 'bash', arguments: {} } }],
    ])('an output call item carrying %s is ambiguous', (_label, extra) => {
        const item = { ...functionCall('search'), ...extra };
        expect(verify(response([item]), noDefaults()).verified).toBe(false);
    });
});
