const { ResponseVerifier } = require('../dist/verifier');
const { ToolGuard } = require('../dist/guards');

// Client-executed Responses API action items (GHSA-xhq6-w3f2-m5w6) must be
// policy-checked like function calls, never read as tool-free content.
const ACTION_ITEMS = {
    local_shell_call: {
        type: 'local_shell_call',
        call_id: 'c1',
        status: 'completed',
        action: { type: 'exec', command: ['rm', '-rf', '/'], env: {} },
    },
    shell_call: { type: 'shell_call', call_id: 'c2', action: { commands: ['rm -rf /'] } },
    apply_patch_call: {
        type: 'apply_patch_call',
        call_id: 'c3',
        operation: { type: 'delete_file', path: '/etc/passwd' },
    },
    computer_call: {
        type: 'computer_call',
        call_id: 'c4',
        action: { type: 'type', text: 'rm -rf /' },
    },
    custom_tool_call: { type: 'custom_tool_call', call_id: 'c5', name: 'bash', input: 'rm -rf /' },
    mcp_approval_request: {
        type: 'mcp_approval_request',
        id: 'a1',
        server_label: 'ops',
        name: 'execute_shell',
        arguments: '{}',
    },
};

function verify(response, guards = [new ToolGuard()]) {
    return new ResponseVerifier(guards).verify(response);
}

function allowOnly(...names) {
    return [new ToolGuard({ useDefaultBlocklist: false, allowedTools: names })];
}

describe('ToolGuard client action items (GHSA-xhq6-w3f2-m5w6)', () => {
    test.each(Object.keys(ACTION_ITEMS))('%s is blocked standalone', (itemType) => {
        const result = verify(ACTION_ITEMS[itemType]);
        expect(result.verified).toBe(false);
        expect(result.blocked).toBe(true);
    });

    test.each(Object.keys(ACTION_ITEMS))('%s is blocked inside response output[]', (itemType) => {
        const result = verify({ id: 'resp_1', object: 'response', output: [ACTION_ITEMS[itemType]] });
        expect(result.verified).toBe(false);
    });

    test.each([
        ['local_shell_call', 'local_shell'],
        ['shell_call', 'shell'],
        ['apply_patch_call', 'apply_patch'],
        ['computer_call', 'computer_use'],
    ])('%s is reported under the canonical name %s', (itemType, canonical) => {
        const result = new ToolGuard().check(ACTION_ITEMS[itemType]);
        expect(result.passed).toBe(false);
        expect(result.message).toContain(`'${canonical}'`);
    });

    test('allowlisted local_shell still scans the joined argv', () => {
        const benign = {
            type: 'local_shell_call',
            call_id: 'c6',
            action: { type: 'exec', command: ['ls', '-la'], env: {} },
        };
        expect(verify(ACTION_ITEMS.local_shell_call, allowOnly('local_shell')).verified).toBe(false);
        expect(verify(benign, allowOnly('local_shell')).verified).toBe(true);
    });

    test('custom tool input is pattern scanned', () => {
        const item = { type: 'custom_tool_call', call_id: 'c8', name: 'run_sql', input: 'DROP TABLE users' };
        expect(verify(item).verified).toBe(false);
        expect(verify({ ...item, input: 'select 1' }).verified).toBe(true);
    });

    test.each(['tool_name', 'toolName'])('conflicting %s on a named item fails closed', (key) => {
        const item = { type: 'custom_tool_call', call_id: 'c9', name: 'bash', [key]: 'search', input: 'ls' };
        expect(verify(item, [new ToolGuard({ useDefaultBlocklist: false })]).verified).toBe(false);
    });

    test.each([
        [{ type: 'custom_tool_call', call_id: 'c10', input: 'ls' }],
        [{ type: 'custom_tool_call', call_id: 'c11', name: 'x', input: { a: 1 } }],
        [{ type: 'local_shell_call', call_id: 'c12', action: 'rm -rf /' }],
        [{ type: 'apply_patch_call', call_id: 'c13' }],
        [{ type: 'mcp_approval_request', id: 'a2', name: 'x', arguments: '[1]' }],
    ])('malformed action item fails closed: %j', (item) => {
        expect(verify(item, [new ToolGuard({ useDefaultBlocklist: false })]).verified).toBe(false);
    });

    test.each([
        [{ tool_call: { name: 'search', arguments: {} } }],
        [{ function_call: { name: 'search', arguments: '{}' } }],
        [{ function: { name: 'search', arguments: '{}' } }],
        [{ tool_calls: [{ name: 'search', arguments: {} }] }],
    ])('action item carrying another call envelope is ambiguous: %j', (extra) => {
        const item = { ...ACTION_ITEMS.local_shell_call, ...extra };
        expect(verify(item, [new ToolGuard({ useDefaultBlocklist: false })]).verified).toBe(false);
    });

    test.each([
        [{ type: 'future_device_call', call_id: 'c14', action: { op: 'wipe' } }],
        [{ type: 'future_payment_request', id: 'p1', payload: { amount: 5 } }],
    ])('unknown executable item fails closed in response output[]: %j', (unknown) => {
        const guards = [new ToolGuard({ useDefaultBlocklist: false })];
        expect(verify({ object: 'response', output: [unknown] }, guards).verified).toBe(false);
    });

    test.each([
        [{ type: 'refund_request', amount: 5 }],
        [{ type: 'structured_output', output: { pr: { type: 'pull_request' } } }],
        [{ type: 'message', content: [{ type: 'phone_call', minutes: 3 }] }],
        [{ object: 'list', output: [{ type: 'merge_request', iid: 1 }] }],
    ])('ordinary data type labels are not action items: %j', (response) => {
        expect(verify(response).verified).toBe(true);
    });

    test('type labels are matched after trimming', () => {
        const item = { ...ACTION_ITEMS.local_shell_call, type: 'local_shell_call ' };
        expect(verify(item).verified).toBe(false);
    });

    test.each([
        [{ type: 'web_search_call', id: 'ws1', status: 'completed', action: { type: 'search', query: 'weather' } }],
        [{ type: 'file_search_call', id: 'fs1', status: 'completed', queries: ['q'] }],
        [{ type: 'function_call_output', call_id: 'c1', output: 'done' }],
    ])('hosted tool items and tool outputs keep passing: %j', (item) => {
        expect(verify(item).verified).toBe(true);
    });
});
