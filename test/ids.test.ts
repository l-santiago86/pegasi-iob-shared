import { describe, expect, it } from "vitest";

import { assertPrefixedId, randomPrefixedId } from "../src/ids.js";

describe("id helpers", () => {
  it("generates and validates PEGASI IOB prefixed ids", () => {
    const id = randomPrefixedId("activation_record");

    expect(id).toMatch(/^activation_record_[a-f0-9]{32}$/);
    expect(assertPrefixedId(id, "activation_record")).toBe(id);
    expect(() => assertPrefixedId(id, "publication")).toThrow("Expected publication id");
  });

  it("rejects invalid prefixes", () => {
    expect(() => randomPrefixedId("ActivationRecord")).toThrow("Invalid PEGASI IOB id prefix");
  });
});

