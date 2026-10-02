const { ResponseVerifier } = require('../dist/verifier');
const { ToolGuard } = require('../dist/guards');

function nestedResponse(value, depth = 13) {
    for (let index = 0; index < depth; index += 1) {
        value = { wrapper: value };
    }
    return value;
}

describe('ToolGuard issue #41 envelope fail-closed parity', () => {
    test('rejects a dual-identity function wrapper', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            function: { name: 'execute_shell', arguments: { cmd: 'id' } },
            arguments: { query: 'safe' },
        });

        expect(result.passed).toBe(false);
        expect(result.message.toLowerCase()).toContain('ambiguous');
    });

    test('rejects all non-null nested identities instead of selecting one', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_call: { tool_name: 'search', arguments: {} },
            function_call: { tool_name: 'execute_shell', arguments: {} },
        });

        expect(result.passed).toBe(false);
        expect(result.message.toLowerCase()).toContain('ambiguous');
    });

    test('rejects a nested identity that conflicts with a root function wrapper', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_call: { tool_name: 'search', arguments: {} },
            function: { name: 'execute_shell', arguments: { cmd: 'id' } },
        });

        expect(result.passed).toBe(false);
        expect(result.message.toLowerCase()).toContain('ambiguous');
    });

    test('ignores null nested aliases on a valid function wrapper', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_call: null,
            function: { name: 'search', arguments: {} },
        });

        expect(result.passed).toBe(true);
        expect(result.message).toContain('1 tool call');
    });

    test('runs ToolGuard for structured output instead of skipping it', () => {
        const result = new ResponseVerifier([new ToolGuard()]).verify({
            type: 'structured_output',
            output: { name: 'execute_shell', arguments: { cmd: 'id' } },
        });

        expect(result.verified).toBe(false);
        expect(result.guardResults[0].message).not.toBe('No tool calls to verify');
    });

    test('checks JSON-encoded function-call arguments', () => {
        const result = new ResponseVerifier([new ToolGuard()]).verify(JSON.stringify({
            type: 'function_call',
            name: 'execute_shell',
            arguments: JSON.stringify({ cmd: 'id' }),
        }));

        expect(result.verified).toBe(false);
        expect(result.guardResults[0].message).toContain('execute_shell');
    });

    test('fails closed when nested tool scanning reaches its bound', () => {
        const result = new ToolGuard().check(nestedResponse({
            type: 'tool_call',
            tool_name: 'execute_shell',
            arguments: {},
        }));

        expect(result.passed).toBe(false);
    });

    test('never reports clean when nested scanning is truncated', () => {
        const result = new ToolGuard().check(nestedResponse({ value: 'safe' }));

        expect(result.passed).toBe(false);
    });
});
