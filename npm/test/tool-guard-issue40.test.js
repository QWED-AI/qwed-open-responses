const { ToolGuard } = require('../dist/guards');

describe('ToolGuard issue #40 normalized separators and aliases', () => {
    test.each([
        'rm -fr /',
        'DROP/*x*/TABLE users',
        'os . system(1)',
    ])('blocks equivalent dangerous command spelling: %s', (payload) => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { command: payload },
        });

        expect(result.passed).toBe(false);
        expect(result.message.toLowerCase()).toContain('dangerous pattern');
    });

    test('blocks normalized spellings in JSON-encoded arguments', () => {
        const result = new ToolGuard().check({
            type: 'function_call',
            name: 'search',
            arguments: JSON.stringify({ command: 'DROP/*x*/TABLE users' }),
        });

        expect(result.passed).toBe(false);
    });

    test.each([
        'executeShell',
        'transferMoney',
        'runCommand',
        'terminal',
        ' execute-shell ',
    ])('blocks common tool-name alias: %s', (toolName) => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: toolName,
            arguments: {},
        });

        expect(result.passed).toBe(false);
        expect(result.message).toContain('not allowed');
    });

    test('uses separator normalization for allowed tool names', () => {
        const result = new ToolGuard({
            useDefaultBlocklist: false,
            allowedTools: ['safe-tool'],
        }).check({
            type: 'tool_call',
            tool_name: 'safeTool',
            arguments: {},
        });

        expect(result.passed).toBe(true);
    });
});
