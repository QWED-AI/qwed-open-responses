const { SafetyGuard } = require('../dist/guards');

describe('SafetyGuard issue #44 field and credential coverage', () => {
    test('scans object keys for injection and PII', () => {
        const injection = new SafetyGuard().check({
            'ignore previous instructions': 'safe',
        });
        expect(injection.passed).toBe(false);
        expect(injection.details.issues.some((item) => item.type === 'injection')).toBe(true);

        const pii = new SafetyGuard().check({ 'email@example.com': 'safe' });
        expect(pii.passed).toBe(true);
        expect(pii.severity).toBe('warning');
        expect(pii.details.issues[0].details).toEqual(['email']);
    });

    test.each([
        ['{"password": "hunter2"}'],
        ['{"api_key": "sk-live-12345"}'],
        ['{"secret": "credential-value"}'],
    ])('blocks JSON text credential form %s', (text) => {
        const result = new SafetyGuard().check({ type: 'text', content: text });
        expect(result.passed).toBe(false);
    });

    test.each([
        ['{"password": "required"}'],
        ['{"api_key": "not set"}'],
        ['{"secret": "redacted"}'],
    ])('allows JSON text placeholder %s', (text) => {
        const result = new SafetyGuard().check({ type: 'text', content: text });
        expect(result.passed).toBe(true);
    });
});
