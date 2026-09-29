const { SchemaGuard } = require("../dist/guards");
const parityCases = require("../../tests/fixtures/schema_guard_parity.json");

describe("SchemaGuard shared validation cases", () => {
    test.each(parityCases)(
        "$name",
        ({ schema, data, expected, allowAdditionalProperties }) => {
            const result = new SchemaGuard(schema, {
                allowAdditionalProperties,
            }).check({ output: data });

            expect(result.passed).toBe(expected);
        }
    );
});
