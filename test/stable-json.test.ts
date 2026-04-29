import { describe, expect, it } from "vitest";

import { stableStringify } from "../src/stable-json.js";

describe("stableStringify", () => {
  it("orders object keys recursively and omits undefined values", () => {
    expect(stableStringify({ z: 1, a: { y: 2, x: undefined, b: 3 } })).toBe('{"a":{"b":3,"y":2},"z":1}');
  });

  it("rejects circular data", () => {
    const value: Record<string, unknown> = {};
    value.self = value;

    expect(() => stableStringify(value)).toThrow("Cannot stableStringify circular data.");
  });
});

