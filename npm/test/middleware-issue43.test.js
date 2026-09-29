const express = require('express');
const { verifyRequestBody, verifyToolCalls } = require('../dist');

function makeRequest(body, headers = {}, method = 'POST') {
    return {
        body,
        method,
        path: '/execute',
        get(name) {
            return headers[name.toLowerCase()];
        },
    };
}

function makeResponse() {
    return {
        statusCode: 200,
        payload: undefined,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(payload) {
            this.payload = payload;
            return this;
        },
    };
}

describe('request verification middleware (Issue #43)', () => {
    test('blocks unparsed tool-call bodies before an Express route can execute them', async () => {
        const app = express();
        let routeExecuted = false;
        app.use(express.json());
        app.use(verifyToolCalls());
        app.post('/execute', (_req, res) => {
            routeExecuted = true;
            res.sendStatus(204);
        });

        const server = app.listen(0);
        try {
            const address = server.address();
            const response = await fetch(`http://127.0.0.1:${address.port}/execute`, {
                method: 'POST',
                headers: { 'content-type': 'text/plain' },
                body: JSON.stringify({
                    tool_calls: [{ name: 'exec', arguments: { command: 'rm -rf /' } }],
                }),
            });

            expect(response.status).toBe(422);
            expect(await response.json()).toMatchObject({
                code: 'QWED_REQUEST_BLOCKED',
            });
            expect(routeExecuted).toBe(false);
        } finally {
            await new Promise((resolve, reject) => {
                server.close((error) => error ? reject(error) : resolve());
            });
        }
    });

    test('fails closed when body verification is unavailable, even in non-blocking mode', () => {
        const req = makeRequest(undefined, { 'content-length': '12' });
        const res = makeResponse();
        const next = jest.fn();

        verifyRequestBody({ blockOnFailure: false })(req, res, next);

        expect(res.statusCode).toBe(422);
        expect(res.payload.code).toBe('QWED_REQUEST_BLOCKED');
        expect(next).not.toHaveBeenCalled();
        expect(req._qwedVerification).toMatchObject({
            verified: false,
            blocked: true,
            guardsFailed: 1,
        });
    });

    test('continues when no request body was sent', () => {
        const req = makeRequest(undefined, { 'content-length': '0' }, 'GET');
        const res = makeResponse();
        const next = jest.fn();

        verifyRequestBody()(req, res, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect(res.statusCode).toBe(200);
        expect(req._qwedVerification).toBeUndefined();
    });

    test('allows a parsed benign tool call through the default blocking middleware', () => {
        const req = makeRequest({
            type: 'tool_call',
            tool_name: 'search',
            arguments: { query: 'weather' },
        });
        const res = makeResponse();
        const next = jest.fn();

        verifyToolCalls()(req, res, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect(req._qwedVerification.verified).toBe(true);
        expect(res.statusCode).toBe(200);
    });

    test('verifies a parsed tool-call body and preserves the non-blocking option', () => {
        const req = makeRequest({
            tool_calls: [{ name: 'exec', arguments: { command: 'whoami' } }],
        });
        const res = makeResponse();
        const next = jest.fn();

        verifyToolCalls({ blockOnFailure: false })(req, res, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect(req._qwedVerification.verified).toBe(false);
        expect(res.statusCode).toBe(200);
    });

    test('rejects parsed non-object bodies instead of treating them as absent', () => {
        const req = makeRequest(null, {
            'content-type': 'application/json',
            'content-length': '4',
        });
        const res = makeResponse();
        const next = jest.fn();

        verifyToolCalls()(req, res, next);

        expect(res.statusCode).toBe(422);
        expect(res.payload.code).toBe('QWED_REQUEST_BLOCKED');
        expect(next).not.toHaveBeenCalled();
        expect(req._qwedVerification.verified).toBe(false);
    });
});
