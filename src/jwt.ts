import { createHmac, timingSafeEqual } from "node:crypto";

export interface JwtClaims {
  readonly sub: string;
  readonly exp?: number;
  readonly iat?: number;
  readonly [claim: string]: unknown;
}

export interface VerifyHs256JwtOptions {
  readonly secret: string;
  readonly nowSeconds?: number;
  readonly minSecretBytes?: number;
}

export interface VerifyHs256JwtWithRotationOptions {
  /**
   * Current signing key. Tokens issued from now on are signed with this.
   * Validation tries this first.
   */
  readonly currentSecret: string;
  /**
   * Previous signing key. Set during the grace period after a rotation so
   * tokens issued before the rotation still validate. Leave undefined when
   * no rotation is in progress.
   */
  readonly previousSecret?: string;
  readonly nowSeconds?: number;
  readonly minSecretBytes?: number;
}

export function parseBearerAuthorization(authorization: string | undefined): string {
  if (!authorization) {
    throw new Error("Authorization header is required.");
  }
  const [scheme, token, extra] = authorization.split(/\s+/);
  if (scheme !== "Bearer" || !token || extra) {
    throw new Error("Authorization header must use Bearer token format.");
  }
  return token;
}

export function verifyHs256Jwt(token: string, options: VerifyHs256JwtOptions): JwtClaims {
  const minSecretBytes = options.minSecretBytes ?? 32;
  if (Buffer.byteLength(options.secret, "utf8") < minSecretBytes) {
    throw new Error(`HS256 secret must be at least ${minSecretBytes} bytes.`);
  }
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new Error("JWT must have three parts.");
  }
  const header = parseJwtPart(encodedHeader);
  if (header.alg !== "HS256") {
    throw new Error("JWT alg must be HS256.");
  }
  if (header.typ !== undefined && header.typ !== "JWT") {
    throw new Error("JWT typ must be JWT when present.");
  }
  const expectedSignature = hmacSha256Base64Url(`${encodedHeader}.${encodedPayload}`, options.secret);
  if (!constantTimeEqual(encodedSignature, expectedSignature)) {
    throw new Error("JWT signature is invalid.");
  }
  const claims = parseJwtPart(encodedPayload);
  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    throw new Error("JWT sub claim is required.");
  }
  if (claims.exp !== undefined) {
    if (typeof claims.exp !== "number") {
      throw new Error("JWT exp claim must be numeric.");
    }
    const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
    if (claims.exp <= nowSeconds) {
      throw new Error("JWT is expired.");
    }
  }
  return claims as JwtClaims;
}

/**
 * Validates an HS256 JWT against {@link VerifyHs256JwtWithRotationOptions.currentSecret}
 * first; if signature verification fails AND a `previousSecret` is provided,
 * retries with that one. Use this in services during the rotation grace
 * period so tokens minted with the old key keep validating until the
 * rotator Lambda flips the previous slot off.
 *
 * Other validation steps (alg, typ, sub, exp) are unchanged. Only the
 * signature verification is dual-key.
 */
export function verifyHs256JwtWithRotation(
  token: string,
  options: VerifyHs256JwtWithRotationOptions
): JwtClaims {
  try {
    return verifyHs256Jwt(token, {
      secret: options.currentSecret,
      ...(options.nowSeconds !== undefined ? { nowSeconds: options.nowSeconds } : {}),
      ...(options.minSecretBytes !== undefined ? { minSecretBytes: options.minSecretBytes } : {})
    });
  } catch (err) {
    // Only fall back to previous on signature failures, never on alg/typ/sub/exp.
    // That keeps the validation surface identical between the two keys.
    if (
      !options.previousSecret ||
      !(err instanceof Error) ||
      !err.message.includes("signature is invalid")
    ) {
      throw err;
    }
    return verifyHs256Jwt(token, {
      secret: options.previousSecret,
      ...(options.nowSeconds !== undefined ? { nowSeconds: options.nowSeconds } : {}),
      ...(options.minSecretBytes !== undefined ? { minSecretBytes: options.minSecretBytes } : {})
    });
  }
}

function parseJwtPart(encoded: string): Record<string, unknown> {
  try {
    const decoded = Buffer.from(encoded, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(decoded);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("JWT part must decode to an object.");
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error("JWT part is not valid base64url JSON.");
  }
}

function hmacSha256Base64Url(input: string, secret: string): string {
  return createHmac("sha256", secret).update(input).digest("base64url");
}

function constantTimeEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer);
}

