import { describe, expect, it } from "vitest";

import { optionalEnv, parseBooleanEnv, parsePositiveIntegerEnv, requiredEnv } from "../src/config.js";

describe("config helpers", () => {
  it("reads required and optional env values without trimming returned secrets", () => {
    const env = {
      REQUIRED_VALUE: "  keep-spaces  ",
      EMPTY_VALUE: "   "
    };

    expect(requiredEnv("REQUIRED_VALUE", env)).toBe("  keep-spaces  ");
    expect(optionalEnv("EMPTY_VALUE", env)).toBeUndefined();
    expect(() => requiredEnv("MISSING_VALUE", env)).toThrow("MISSING_VALUE is required.");
  });

  it("parses positive integers and booleans strictly", () => {
    expect(parsePositiveIntegerEnv(undefined, 10)).toBe(10);
    expect(parsePositiveIntegerEnv("25", 10)).toBe(25);
    expect(() => parsePositiveIntegerEnv("0", 10)).toThrow("Expected positive integer");
    expect(parseBooleanEnv(undefined, true)).toBe(true);
    expect(parseBooleanEnv("true")).toBe(true);
    expect(parseBooleanEnv("false", true)).toBe(false);
    expect(() => parseBooleanEnv("yes")).toThrow("Expected boolean");
  });
});

