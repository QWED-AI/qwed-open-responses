const { ToolGuard } = require('../dist/guards');

describe('ToolGuard issue #39 raw argument scanning', () => {
    test.each([
        'DROP\tTABLE users;',
        'DROP\nTABLE users;',
        'DROP TABLE users;',
        'rm\t-rf /',
        'rm -rf /',
        'eval\n(1 + 1)',
    ])('blocks default pattern in parsed arguments: %s', (payload) => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { command: payload },
        });

        expect(result.passed).toBe(false);
        expect(result.message.toLowerCase()).toContain('dangerous pattern');
    });

    test('blocks control characters in JSON-encoded and nested arguments', () => {
        const result = new ToolGuard().check({
            type: 'function_call',
            name: 'search',
            arguments: JSON.stringify({
                filters: [{ query: 'DROP\tTABLE users;' }],
            }),
        });

        expect(result.passed).toBe(false);
    });

    test('applies custom patterns to raw nested string leaves', () => {
        const guard = new ToolGuard({ dangerousPatterns: [/BLOCK\s+ME/i] });
        const result = guard.check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { nested: ['block\nme'] },
        });

        expect(result.passed).toBe(false);
    });

    test('allows benign string values containing whitespace', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { query: 'weather\tforecast\nfor tomorrow' },
        });

        expect(result.passed).toBe(true);
    });

    test('checks base64 tokens in nested string leaves', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { nested: [{ payload: 'cm0gLXJmIC8=' }] },
        });

        expect(result.passed).toBe(false);
        expect(result.details.encoding).toBe('base64');
    });

    test('fails closed for argument depth beyond the configured bound', () => {
        let argumentsValue = {};
        for (let depth = 0; depth < 128; depth++) {
            argumentsValue = { nested: argumentsValue };
        }

        const result = new ToolGuard().check({
            type: 'function_call',
            name: 'search',
            arguments: argumentsValue,
        });

        expect(result.passed).toBe(false);
    });

    test('fails closed for cyclic arguments', () => {
        const argumentsValue = { command: 'benign' };
        argumentsValue.self = argumentsValue;

        const result = new ToolGuard().check({
            type: 'function_call',
            name: 'search',
            arguments: argumentsValue,
        });

        expect(result.passed).toBe(false);
    });

    test('allows shared acyclic argument objects', () => {
        const shared = { query: 'weather' };
        const result = new ToolGuard().check({
            type: 'function_call',
            name: 'search',
            arguments: { left: shared, right: shared },
        });

        expect(result.passed).toBe(true);
    });

    test('scans nested argument keys as well as values', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { nested: { 'rm -rf /': 'benign' } },
        });

        expect(result.passed).toBe(false);
        expect(result.message.toLowerCase()).toContain('dangerous pattern');
    });

    test('fails closed for a cyclic direct tool call', () => {
        const argumentsValue = { command: 'benign' };
        argumentsValue.self = argumentsValue;

        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: argumentsValue,
        });

        expect(result.passed).toBe(false);
    });

    test('fails closed when a direct tool call exceeds the nesting limit', () => {
        let argumentsValue = {};
        for (let depth = 0; depth < 128; depth++) {
            argumentsValue = { nested: argumentsValue };
        }

        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: argumentsValue,
        });

        expect(result.passed).toBe(false);
    });

    test('fails closed when reading an argument getter throws', () => {
        const argumentsValue = {};
        Object.defineProperty(argumentsValue, 'command', {
            enumerable: true,
            get() {
                throw new Error('unavailable');
            },
        });

        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: argumentsValue,
        });

        expect(result.passed).toBe(false);
        expect(result.message).toContain('could not be inspected safely');
    });

    test('fails closed when argument scanning exceeds its node limit', () => {
        const argumentsValue = Object.fromEntries(
            Array.from({ length: 10_001 }, (_, index) => [`query${index}`, 'value'])
        );
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: argumentsValue,
        });

        expect(result.passed).toBe(false);
    });

    test('fails closed when argument scanning exceeds its character limit', () => {
        const result = new ToolGuard().check({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { query: 'a'.repeat(100_001) },
        });

        expect(result.passed).toBe(false);
    });
});
