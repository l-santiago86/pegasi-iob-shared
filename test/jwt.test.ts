import { createHmac, createSign, generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  extractJwtRoles,
  parseBearerAuthorization,
  verifyBearerAuthorization,
  verifyBearerJwt,
  verifyHs256Jwt,
  verifyHs256JwtWithRotation,
  verifyOidcJwt
} from "../src/jwt.js";

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

  describe("OIDC/JWKS verification", () => {
    const issuer = "https://identity.dev.pegasiiob.com/realms/pegasi-iob";
    const audience = "pegasi-iob-admin-console";
    const nowSeconds = 1_800_000_000;

    it("verifies an RS256 OIDC token against JWKS", async () => {
      const fixture = createRs256Fixture({
        iss: issuer,
        aud: [audience, "account"],
        sub: "user_platform_admin",
        exp: nowSeconds + 300,
        tenant_scope_id: "tenant_torax_dev",
        realm_access: { roles: ["platform_admin", "operator"] }
      });

      const claims = await verifyOidcJwt(fixture.token, {
        issuer,
        audience,
        nowSeconds,
        fetchImpl: fixture.fetchImpl
      });

      expect(claims.sub).toBe("user_platform_admin");
      expect(claims.tenant_scope_id).toBe("tenant_torax_dev");
      expect(extractJwtRoles(claims)).toEqual(["platform_admin", "operator"]);
    });

    it("rejects invalid OIDC audience and expired tokens", async () => {
      const fixture = createRs256Fixture({
        iss: issuer,
        aud: "other-client",
        sub: "user_platform_admin",
        exp: nowSeconds + 300
      });

      await expect(
        verifyOidcJwt(fixture.token, { issuer, audience, nowSeconds, fetchImpl: fixture.fetchImpl })
      ).rejects.toThrow("aud claim");

      const expired = createRs256Fixture({
        iss: issuer,
        aud: audience,
        sub: "user_platform_admin",
        exp: nowSeconds - 1
      });
      await expect(
        verifyOidcJwt(expired.token, { issuer, audience, nowSeconds, fetchImpl: expired.fetchImpl })
      ).rejects.toThrow("expired");
    });

    it("routes hybrid bearer verification by JWT alg", async () => {
      const hs256Token = signJwt({ sub: "svc", exp: nowSeconds + 300 }, secret);
      await expect(
        verifyBearerJwt(hs256Token, {
          mode: "hybrid",
          hs256: { currentSecret: secret, nowSeconds }
        })
      ).resolves.toMatchObject({ sub: "svc" });

      const rs256 = createRs256Fixture({
        iss: issuer,
        aud: audience,
        sub: "user_operator",
        exp: nowSeconds + 300
      });
      await expect(
        verifyBearerAuthorization(`Bearer ${rs256.token}`, {
          mode: "hybrid",
          oidc: { issuer, audience, nowSeconds, fetchImpl: rs256.fetchImpl }
        })
      ).resolves.toMatchObject({ sub: "user_operator" });
    });
  });
});

function signJwt(payload: Record<string, unknown>, secret: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${signature}`;
}

function createRs256Fixture(payload: Record<string, unknown>): {
  readonly token: string;
  readonly fetchImpl: typeof fetch;
} {
  const keyId = "pegasi-test-key";
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: keyId })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${body}`);
  signer.end();
  const signature = signer.sign(privateKey).toString("base64url");
  const token = `${header}.${body}.${signature}`;
  return {
    token,
    fetchImpl: (async () => ({
      ok: true,
      status: 200,
      json: async () => ({ keys: [{ ...jwk, kid: keyId, alg: "RS256", use: "sig" }] })
    })) as typeof fetch
  };
}

