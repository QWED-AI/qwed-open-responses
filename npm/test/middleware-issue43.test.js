const http = require('node:http');
const expressVersions = [
    { label: 'Express 4', express: require('express4') },
    { label: 'Express 5', express: require('express') },
];
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
    test.each(expressVersions)(
        'blocks unparsed tool-call bodies before an Express route can execute them on $label, even in non-blocking mode',
        async ({ express: expressVersion }) => {
            const app = expressVersion();
            let routeExecuted = false;
            app.use(expressVersion.json());
            app.use(verifyToolCalls({ blockOnFailure: false }));
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
        }
    );

    test.each(expressVersions)(
        'allows a parsed empty JSON object through on $label',
        async ({ express: expressVersion }) => {
            const app = expressVersion();
            let routeExecuted = false;
            let routeBody;
            app.use(expressVersion.json());
            app.use(verifyRequestBody({ blockOnFailure: false }));
            app.post('/execute', (req, res) => {
                routeExecuted = true;
                routeBody = req.body;
                res.sendStatus(204);
            });

            const server = app.listen(0);
            try {
                const address = server.address();
                const response = await fetch(`http://127.0.0.1:${address.port}/execute`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: '{}',
                });

                expect(response.status).toBe(204);
                expect(routeExecuted).toBe(true);
                expect(routeBody).toEqual({});
            } finally {
                await new Promise((resolve, reject) => {
                    server.close((error) => error ? reject(error) : resolve());
                });
            }
        }
    );

    test.each(expressVersions)(
        'allows a parsed empty object from a custom text/plain JSON parser on $label',
        async ({ express: expressVersion }) => {
            const app = expressVersion();
            let routeExecuted = false;
            let routeBody;
            app.use(expressVersion.json({ type: 'text/plain' }));
            app.use(verifyRequestBody({ blockOnFailure: false }));
            app.post('/execute', (req, res) => {
                routeExecuted = true;
                routeBody = req.body;
                res.sendStatus(204);
            });

            const server = app.listen(0);
            try {
                const address = server.address();
                const response = await fetch(`http://127.0.0.1:${address.port}/execute`, {
                    method: 'POST',
                    headers: { 'content-type': 'text/plain' },
                    body: '{}',
                });

                expect(response.status).toBe(204);
                expect(routeExecuted).toBe(true);
                expect(routeBody).toEqual({});
            } finally {
                await new Promise((resolve, reject) => {
                    server.close((error) => error ? reject(error) : resolve());
                });
            }
        }
    );

    test.each(expressVersions)(
        'blocks an empty chunked request even when a custom JSON parser is configured on $label',
        async ({ express: expressVersion }) => {
            const app = expressVersion();
            let routeExecuted = false;
            app.use(expressVersion.json({ type: 'text/plain' }));
            app.use(verifyRequestBody({ blockOnFailure: false }));
            app.post('/execute', (_req, res) => {
                routeExecuted = true;
                res.sendStatus(204);
            });

            const server = app.listen(0);
            try {
                const address = server.address();
                const response = await new Promise((resolve, reject) => {
                    const request = http.request({
                        hostname: '127.0.0.1',
                        port: address.port,
                        path: '/execute',
                        method: 'POST',
                        headers: {
                            'content-type': 'text/plain',
                            'transfer-encoding': 'chunked',
                        },
                    }, (res) => {
                        let payload = '';
                        res.setEncoding('utf8');
                        res.on('data', (chunk) => { payload += chunk; });
                        res.on('end', () => resolve({ status: res.statusCode, payload }));
                    });
                    request.on('error', reject);
                    request.end();
                });

                expect(response.status).toBe(422);
                expect(JSON.parse(response.payload)).toMatchObject({
                    code: 'QWED_REQUEST_BLOCKED',
                });
                expect(routeExecuted).toBe(false);
            } finally {
                await new Promise((resolve, reject) => {
                    server.close((error) => error ? reject(error) : resolve());
                });
            }
        }
    );

    test.each(expressVersions)(
        'allows a parsed empty vendor JSON object through on $label',
        async ({ express: expressVersion }) => {
            const app = expressVersion();
            let routeBody;
            app.use(expressVersion.json({ type: 'application/*+json' }));
            app.use(verifyRequestBody({ blockOnFailure: false }));
            app.post('/execute', (req, res) => {
                routeBody = req.body;
                res.sendStatus(204);
            });

            const server = app.listen(0);
            try {
                const address = server.address();
                const response = await fetch(`http://127.0.0.1:${address.port}/execute`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/merge-patch+json' },
                    body: '{}',
                });

                expect(response.status).toBe(204);
                expect(routeBody).toEqual({});
            } finally {
                await new Promise((resolve, reject) => {
                    server.close((error) => error ? reject(error) : resolve());
                });
            }
        }
    );

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

    test('continues when Express 4 leaves an empty object for a bodyless non-JSON request', () => {
        const req = makeRequest({}, {
            'content-type': 'text/plain',
            'content-length': '0',
        }, 'GET');
        const res = makeResponse();
        const next = jest.fn();

        verifyRequestBody()(req, res, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect(res.statusCode).toBe(200);
        expect(req._qwedVerification).toBeUndefined();
    });

    test('fails closed for an empty chunked request left as an empty object', () => {
        const req = makeRequest({}, {
            'content-type': 'text/plain',
            'transfer-encoding': 'chunked',
        });
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
