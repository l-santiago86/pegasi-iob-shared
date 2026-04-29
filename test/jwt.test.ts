import { createHmac } from "node:crypto";

import { describe, expect, it } from "vitest";

import { parseBearerAuthorization, verifyHs256Jwt } from "../src/jwt.js";

describe("jwt helpers", () => {
  const secret = "0123456789abcdef0123456789abcdef";

  it("parses bearer auth and verifies HS256 JWT claims", () => {
    const token = signJwt({ sub: "actor_123", exp: 4_102_444_800 }, secret);

    expect(parseBearerAuthorization(`Bearer ${token}`)).toBe(token);
    expect(verifyHs256Jwt(token, { secret, nowSeconds: 1_700_000_000 })).toMatchObject({
      sub: "actor_123",
      exp: 4_102_444_800
    });
  });

  it("rejects weak secrets, invalid signatures, and expired tokens", () => {
    const token = signJwt({ sub: "actor_123", exp: 100 }, secret);

    expect(() => verifyHs256Jwt(token, { secret: "too-short", nowSeconds: 1 })).toThrow("at least 32 bytes");
    expect(() => verifyHs256Jwt(`${token.slice(0, -1)}x`, { secret, nowSeconds: 1 })).toThrow("signature is invalid");
    expect(() => verifyHs256Jwt(token, { secret, nowSeconds: 101 })).toThrow("JWT is expired");
  });

  it("rejects malformed bearer headers", () => {
    expect(() => parseBearerAuthorization(undefined)).toThrow("Authorization header is required.");
    expect(() => parseBearerAuthorization("Basic abc")).toThrow("Bearer token format");
  });
});

function signJwt(payload: Record<string, unknown>, secret: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${signature}`;
}

