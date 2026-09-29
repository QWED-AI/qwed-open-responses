const { ResponseVerifier } = require("../dist/verifier");
const { SafetyGuard, SchemaGuard } = require("../dist/guards");

const passGuard = {
    name: "PassGuard",
    check: () => ({ guardName: "PassGuard", passed: true, severity: "info" }),
};

describe("bounded verification resources", () => {
    test("fails closed when scanned content exceeds the character limit", () => {
        const result = new SafetyGuard().check({
            content: "x".repeat(100_001),
        });

        expect(result.passed).toBe(false);
        expect(result.details.resourceLimit).toContain("character limit");
    });

    test("counts astral Unicode characters consistently with Python", () => {
        const result = new SafetyGuard().check({
            content: "😀".repeat(50_001),
        });

        expect(result.passed).toBe(true);
    });

    test("accepts content at the character limit", () => {
        const result = new SafetyGuard().check({
            content: "x".repeat(100_000),
        });

        expect(result.passed).toBe(true);
    });

    test("fails closed when the response graph exceeds the node limit", () => {
        const result = new SafetyGuard().check({
            content: Array(10_001).fill(""),
        });

        expect(result.passed).toBe(false);
        expect(result.details.resourceLimit).toContain("node count");
    });

    test("fails closed when nested content exceeds the depth limit", () => {
        let response = { content: "safe" };
        for (let index = 0; index < 13; index++) {
            response = { nested: response };
        }

        const result = new SafetyGuard().check(response);

        expect(result.passed).toBe(false);
        expect(result.details.resourceLimit).toContain("nesting");
    });

    test("does not scan output arrays twice", () => {
        const result = new SafetyGuard().check({
            output: Array(20).fill("x".repeat(4_000)),
        });

        expect(result.passed).toBe(true);
    });

    test("finds emails and handles malformed long address candidates", () => {
        const valid = new SafetyGuard().check({
            content: "Contact user.name+tag@example.com",
        });
        const adversarial = new SafetyGuard().check({
            content: "a.".repeat(1_000) + "@" + "b.".repeat(1_000) + "!",
        });
        const malformed = new SafetyGuard().check({
            content: "user@foo..com",
        });

        expect(valid.passed).toBe(true);
        expect(valid.severity).toBe("warning");
        expect(valid.details.issues[0].details).toEqual(["email"]);
        expect(adversarial.passed).toBe(true);
        expect(malformed.passed).toBe(true);
    });

    test("rechecks shared objects in each inspection context", () => {
        const shared = { phone: 1234567890 };
        const result = new SafetyGuard().check({
            ordinary: shared,
            arguments: shared,
        });

        expect(result.passed).toBe(true);
        expect(result.severity).toBe("warning");
        expect(result.details.issues[0].details).toEqual(["phone"]);
    });

    test("charges field names and join separators", () => {
        const wideKey = new SafetyGuard().check({
            ["x".repeat(20_000)]: 0,
        });
        expect(wideKey.passed).toBe(false);
        expect(wideKey.details.resourceLimit).toContain("field labels");

        const fields = new SafetyGuard().check({
            items: Array(9_997).fill("x".repeat(10)),
        });
        expect(fields.passed).toBe(false);
        expect(fields.details.resourceLimit).toContain("character limit");
    });

    test("fails closed for bigint values in ordinary fields", () => {
        const result = new SafetyGuard().check({ value: 1n });

        expect(result.passed).toBe(false);
        expect(result.details.resourceLimit).toContain("non-JSON");
    });

    test("reports only the first schema validation error", () => {
        const properties = {};
        const output = {};
        for (let index = 0; index < 50; index++) {
            properties["field_" + index] = { type: "string" };
            output["field_" + index] = index;
        }

        const result = new SchemaGuard({
            type: "object",
            properties,
        }).check({ output });

        expect(result.passed).toBe(false);
        expect(result.details.errors).toHaveLength(1);
        expect(result.details.totalErrors).toBeNull();
        expect(result.details.errorsTruncated).toBe(true);
    });

    test("returns a failed verdict for oversized JSON input", () => {
        const payload = '{"content":"' + "x".repeat(100_000) + '"}';
        const result = new ResponseVerifier([new SafetyGuard()]).verify(payload);

        expect(result.verified).toBe(false);
        expect(result.guardResults[0].guardName).toBe("ResponseVerifier");
        expect(result.guardResults[0].details.resourceLimit).toContain("limit");
    });

    test("accepts JSON input at the character limit", () => {
        const payload = '{"content":"' + "x".repeat(99_986) + '"}';
        const result = new ResponseVerifier([passGuard]).verify(payload);

        expect(payload.length).toBe(100_000);
        expect(result.verified).toBe(true);
        expect(result.response.content).toHaveLength(99_986);
    });

    test("accepts JSON at the nesting depth limit", () => {
        const depth = 100;
        const payload = '{"nested":'.repeat(depth) + "null" + "}".repeat(depth);
        const result = new ResponseVerifier([passGuard]).verify(payload);
        let nested = result.response;
        for (let index = 0; index < depth; index++) nested = nested.nested;

        expect(result.verified).toBe(true);
        expect(nested).toBeNull();
    });

    test("returns a failed verdict for deeply nested JSON", () => {
        const depth = 101;
        const payload = '{"nested":'.repeat(depth) + "null" + "}".repeat(depth);
        const result = new ResponseVerifier([new SafetyGuard()]).verify(payload);

        expect(result.verified).toBe(false);
        expect(result.guardResults[0].details.resourceLimit).toContain("nesting");
    });

    test("does not throw when parsing oversized integer tokens", () => {
        const payload = '{"value":' + "9".repeat(5_000) + "}";
        const result = new ResponseVerifier([new SafetyGuard()]).verify(payload);

        expect(result.verified).toBe(false);
    });

    test("keeps plain text fallback behavior", () => {
        const result = new ResponseVerifier([new SafetyGuard()]).verify("not JSON");

        expect(result.verified).toBe(true);
        expect(result.response).toEqual({ type: "text", content: "not JSON" });
    });

    test("keeps plain text fallback with many brackets", () => {
        const text = "[".repeat(101) + " code sample";
        const result = new ResponseVerifier([new SafetyGuard()]).verify(text);

        expect(result.verified).toBe(true);
        expect(result.response).toEqual({ type: "text", content: text });
    });
});
