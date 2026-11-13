const { ResponseVerifier } = require('../dist/verifier');
const { ToolGuard } = require('../dist/guards');
const { cases } = require('../../tests/fixtures/tool_guard_envelope_parity.json');

// ToolGuard envelope rules shared with the Python package. Both run every
// case with allowedTools ['search'], so a passing case means the only call
// screened was `search`. Python twin: tests/test_tool_guard_envelope_parity.py.
describe('ToolGuard shared envelope cases', () => {
    test.each(cases.map((testCase) => [testCase.name, testCase]))('%s', (_name, testCase) => {
        const result = new ResponseVerifier([new ToolGuard({ allowedTools: ['search'] })])
            .verify(testCase.response);
        expect(result.verified).toBe(testCase.expect === 'pass');
    });
});
