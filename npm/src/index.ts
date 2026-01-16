/**
 * QWED Open Responses - Express Middleware
 * 
 * Verification guards for AI agent outputs in Express.js applications.
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';

// Re-export all guards and types
export * from './guards';
export * from './types';
export * from './verifier';

import { ResponseVerifier, VerificationResult } from './verifier';
import { BaseGuard, ToolGuard, SchemaGuard, SafetyGuard } from './guards';

export interface QWEDMiddlewareOptions {
    /** Guards to apply to all requests */
    guards?: BaseGuard[];
    /** Block requests that fail verification */
    blockOnFailure?: boolean;
    /** Custom error handler */
    onError?: (error: VerificationResult, req: Request, res: Response) => void;
    /** Log verification results */
    verbose?: boolean;
    /** Paths to skip verification */
    skipPaths?: string[];
}

/**
 * Create QWED verification middleware for Express.
 * 
 * @example
 * ```typescript
 * import express from 'express';
 * import { createQWEDMiddleware, ToolGuard, SafetyGuard } from 'qwed-open-responses';
 * 
 * const app = express();
 * 
 * app.use(createQWEDMiddleware({
 *   guards: [new ToolGuard(), new SafetyGuard()],
 *   blockOnFailure: true,
 * }));
 * ```
 */
export function createQWEDMiddleware(options: QWEDMiddlewareOptions = {}): RequestHandler {
    const {
        guards = [],
        blockOnFailure = true,
        onError,
        verbose = false,
        skipPaths = [],
    } = options;

    const verifier = new ResponseVerifier(guards);

    return (req: Request, res: Response, next: NextFunction) => {
        // Skip certain paths
        if (skipPaths.some(path => req.path.startsWith(path))) {
            return next();
        }

        // Store original json method
        const originalJson = res.json.bind(res);

        // Override json to verify before sending
        res.json = (body: any) => {
            const result = verifier.verify(body);

            if (verbose) {
                console.log(`[QWED] ${req.method} ${req.path} -> ${result.verified ? 'PASS' : 'FAIL'}`);
            }

            // Attach verification result to response
            (res as any)._qwedVerification = result;

            if (!result.verified && blockOnFailure) {
                if (onError) {
                    onError(result, req, res);
                    return res;
                }

                return originalJson({
                    error: 'Response verification failed',
                    code: 'QWED_VERIFICATION_FAILED',
                    details: result.guardResults.filter(g => !g.passed).map(g => ({
                        guard: g.guardName,
                        message: g.message,
                    })),
                });
            }

            return originalJson(body);
        };

        next();
    };
}

/**
 * Middleware to verify incoming request bodies.
 */
export function verifyRequestBody(options: QWEDMiddlewareOptions = {}): RequestHandler {
    const {
        guards = [],
        blockOnFailure = true,
        verbose = false,
    } = options;

    const verifier = new ResponseVerifier(guards);

    return (req: Request, res: Response, next: NextFunction) => {
        if (!req.body) {
            return next();
        }

        const result = verifier.verify(req.body);

        if (verbose) {
            console.log(`[QWED] Request body ${req.method} ${req.path} -> ${result.verified ? 'PASS' : 'FAIL'}`);
        }

        (req as any)._qwedVerification = result;

        if (!result.verified && blockOnFailure) {
            return res.status(422).json({
                error: 'Request verification failed',
                code: 'QWED_REQUEST_BLOCKED',
                details: result.guardResults.filter(g => !g.passed).map(g => ({
                    guard: g.guardName,
                    message: g.message,
                })),
            });
        }

        next();
    };
}

/**
 * Middleware to verify tool calls in AI agent requests.
 */
export function verifyToolCalls(options: QWEDMiddlewareOptions = {}): RequestHandler {
    const toolGuard = new ToolGuard();
    const guards = [toolGuard, ...(options.guards || [])];

    return verifyRequestBody({ ...options, guards });
}

// Default export
export default {
    createQWEDMiddleware,
    verifyRequestBody,
    verifyToolCalls,
    ResponseVerifier,
    ToolGuard,
    SchemaGuard,
    SafetyGuard,
};
