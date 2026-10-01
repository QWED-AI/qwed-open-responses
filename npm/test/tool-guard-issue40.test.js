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

    test('keeps allowlist checks tied to the configured tool name', () => {
        const guard = new ToolGuard({
            useDefaultBlocklist: false,
            allowedTools: ['safe-tool'],
        });

        const exactName = guard.check({
            type: 'tool_call',
            tool_name: 'safe-tool',
            arguments: {},
        });
        const aliasName = guard.check({
            type: 'tool_call',
            tool_name: 'safeTool',
            arguments: {},
        });

        expect(exactName.passed).toBe(true);
        expect(aliasName.passed).toBe(false);
    });

    test.each([
        'rm -r -f /',
        'rm -f -r /',
        'rm --force --recursive /',
    ])('blocks separate destructive rm flags: %s', (command) => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { command },
        });

        expect(result.passed).toBe(false);
        expect(result.message.toLowerCase()).toContain('dangerous pattern');
    });

    test('does not rewrite ordinary words as rm flags', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { query: 'rm -refactor documentation' },
        });

        expect(result.passed).toBe(true);
    });

    test.each([
        'rm -fr /',
        'DROP/*comment*/TABLE users',
    ])('normalizes base64 decoded dangerous text: %s', (command) => {
        const encoded = Buffer.from(command, 'utf8').toString('base64');
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { query: encoded },
        });

        expect(result.passed).toBe(false);
        expect(result.details.encoding).toBe('base64');
    });

    test.each([
        ['bash', 'ba\u017fh', false],
        ['\u13a0', '\uab70', false],
        ['ss', '\u1e9e', false],
        ['i', '\u0131', true],
    ])('matches Python casefold for %s and %s', (blockedTool, toolName, passed) => {
        const result = new ToolGuard({
            blockedTools: [blockedTool],
            useDefaultBlocklist: false,
        }).check({
            type: 'tool_call',
            tool_name: toolName,
            arguments: {},
        });

        expect(result.passed).toBe(passed);
    });

    test.each([
        ['bash', 'ba\u017fh', true],
        ['i', '\u0131', false],
    ])('applies Python casefold to allowed tools %s and %s', (allowedTool, toolName, passed) => {
        const result = new ToolGuard({
            allowedTools: [allowedTool],
            useDefaultBlocklist: false,
        }).check({
            type: 'tool_call',
            tool_name: toolName,
            arguments: {},
        });

        expect(result.passed).toBe(passed);
    });
});
