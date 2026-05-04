import { createHmac } from "node:crypto";

import { describe, expect, it } from "vitest";

import { parseBearerAuthorization, verifyHs256Jwt, verifyHs256JwtWithRotation } from "../src/jwt.js";

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

  describe("verifyHs256JwtWithRotation (grace period dual-validation)", () => {
    const currentSecret = "current-secret-32-bytes-long-aaaaaa";
    const previousSecret = "previous-secret-32-bytes-long-bbbbb";
    const nowSeconds = 1_700_000_000;

    it("validates a token signed with currentSecret", () => {
      const token = signJwt({ sub: "actor_1", exp: 4_102_444_800 }, currentSecret);
      const claims = verifyHs256JwtWithRotation(token, {
        currentSecret,
        previousSecret,
        nowSeconds
      });
      expect(claims.sub).toBe("actor_1");
    });

    it("falls back to previousSecret when current fails (during grace period)", () => {
      const token = signJwt({ sub: "actor_2", exp: 4_102_444_800 }, previousSecret);
      const claims = verifyHs256JwtWithRotation(token, {
        currentSecret,
        previousSecret,
        nowSeconds
      });
      expect(claims.sub).toBe("actor_2");
    });

    it("rejects when neither current nor previous matches (post grace period)", () => {
      const token = signJwt({ sub: "actor_3", exp: 4_102_444_800 }, "other-secret-32-bytes-long-zzzzzzz");
      expect(() =>
        verifyHs256JwtWithRotation(token, { currentSecret, previousSecret, nowSeconds })
      ).toThrow("signature is invalid");
    });

    it("rejects when previousSecret is undefined and current fails (no grace period in effect)", () => {
      const token = signJwt({ sub: "actor_4", exp: 4_102_444_800 }, previousSecret);
      expect(() =>
        verifyHs256JwtWithRotation(token, { currentSecret, nowSeconds })
      ).toThrow("signature is invalid");
    });

    it("never falls back to previous on non-signature failures (expiry)", () => {
      const token = signJwt({ sub: "actor_5", exp: 100 }, currentSecret);
      // Current secret matches, but token is expired. Must NOT swallow that
      // by also trying previous (which would also be expired but might mask
      // the real diagnosis).
      expect(() =>
        verifyHs256JwtWithRotation(token, { currentSecret, previousSecret, nowSeconds: 200 })
      ).toThrow("JWT is expired");
    });
  });
});

function signJwt(payload: Record<string, unknown>, secret: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${signature}`;
}

