import { createHmac, createPublicKey, createVerify, timingSafeEqual } from "node:crypto";
import type { JsonWebKey } from "node:crypto";

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

export interface VerifyOidcJwtOptions {
  readonly issuer: string;
  readonly audience: string | readonly string[];
  readonly jwksUri?: string;
  readonly nowSeconds?: number;
  readonly allowedAlgorithms?: readonly string[];
  readonly fetchImpl?: typeof fetch;
}

export interface VerifyBearerJwtOptions {
  readonly mode?: "hs256" | "oidc" | "hybrid";
  readonly hs256?: VerifyHs256JwtWithRotationOptions;
  readonly oidc?: VerifyOidcJwtOptions;
}

interface JwksDocument {
  readonly keys?: readonly JsonWebKey[];
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

export async function verifyBearerJwt(token: string, options: VerifyBearerJwtOptions): Promise<JwtClaims> {
  const mode = options.mode ?? "hs256";
  const alg = readJwtAlgorithm(token);

  if (alg === "HS256") {
    if (mode === "oidc" || !options.hs256) {
      throw new Error("HS256 JWT verification is not enabled.");
    }
    return verifyHs256JwtWithRotation(token, options.hs256);
  }

  if (mode === "hs256" || !options.oidc) {
    throw new Error(`${alg} JWT verification is not enabled.`);
  }
  return verifyOidcJwt(token, options.oidc);
}

export async function verifyBearerAuthorization(
  authorization: string | undefined,
  options: VerifyBearerJwtOptions
): Promise<JwtClaims> {
  return verifyBearerJwt(parseBearerAuthorization(authorization), options);
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

export async function verifyOidcJwt(token: string, options: VerifyOidcJwtOptions): Promise<JwtClaims> {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new Error("JWT must have three parts.");
  }
  const header = parseJwtPart(encodedHeader);
  const alg = expectString(header.alg, "JWT alg is required.");
  const allowedAlgorithms = options.allowedAlgorithms ?? ["RS256"];
  if (!allowedAlgorithms.includes(alg)) {
    throw new Error(`JWT alg must be one of ${allowedAlgorithms.join(", ")}.`);
  }
  const kid = expectString(header.kid, "OIDC JWT kid is required.");
  const claims = parseJwtPart(encodedPayload);
  validateRegisteredClaims(claims, options);

  const jwk = await findJwk(kid, options);
  if (!jwk) {
    throw new Error("OIDC signing key was not found in JWKS.");
  }
  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${encodedHeader}.${encodedPayload}`);
  verifier.end();
  const key = createPublicKey({ key: jwk, format: "jwk" });
  if (!verifier.verify(key, Buffer.from(encodedSignature, "base64url"))) {
    throw new Error("JWT signature is invalid.");
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    throw new Error("JWT sub claim is required.");
  }
  return claims as JwtClaims;
}

export function extractJwtRoles(
  claims: JwtClaims,
  roleClaim = "roles",
  clientId?: string
): readonly string[] {
  const direct = stringArrayClaim(claims[roleClaim]);
  if (direct.length > 0) return direct;

  const realmAccess = recordClaim(claims.realm_access);
  const realmRoles = realmAccess ? stringArrayClaim(realmAccess.roles) : [];
  if (realmRoles.length > 0) return realmRoles;

  const resourceAccess = recordClaim(claims.resource_access);
  const clientAccess =
    resourceAccess && clientId ? recordClaim(resourceAccess[clientId]) : null;
  return clientAccess ? stringArrayClaim(clientAccess.roles) : [];
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

function readJwtAlgorithm(token: string): string {
  const encodedHeader = token.split(".")[0];
  if (!encodedHeader) {
    throw new Error("JWT must have three parts.");
  }
  return expectString(parseJwtPart(encodedHeader).alg, "JWT alg is required.");
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

async function findJwk(kid: string, options: VerifyOidcJwtOptions): Promise<JsonWebKey | undefined> {
  const jwksUri = options.jwksUri ?? `${options.issuer.replace(/\/+$/, "")}/protocol/openid-connect/certs`;
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(jwksUri);
  if (!response.ok) {
    throw new Error(`JWKS fetch failed with HTTP ${response.status}.`);
  }
  const document = (await response.json()) as JwksDocument;
  return document.keys?.find((key) => key.kid === kid);
}

function validateRegisteredClaims(claims: Record<string, unknown>, options: VerifyOidcJwtOptions): void {
  const issuer = options.issuer.replace(/\/+$/, "");
  if (claims.iss !== issuer) {
    throw new Error("JWT iss claim is invalid.");
  }
  if (!audienceMatches(claims.aud, options.audience)) {
    throw new Error("JWT aud claim is invalid.");
  }

  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp <= nowSeconds) {
    throw new Error("JWT is expired.");
  }
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf > nowSeconds)) {
    throw new Error("JWT nbf claim is invalid.");
  }
}

function audienceMatches(value: unknown, expected: string | readonly string[]): boolean {
  const expectedSet = new Set(Array.isArray(expected) ? expected : [expected]);
  if (typeof value === "string") {
    return expectedSet.has(value);
  }
  if (!Array.isArray(value)) {
    return false;
  }
  return value.some((entry) => typeof entry === "string" && expectedSet.has(entry));
}

function expectString(value: unknown, message: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(message);
  }
  return value;
}

function stringArrayClaim(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
}

function recordClaim(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hmacSha256Base64Url(input: string, secret: string): string {
  return createHmac("sha256", secret).update(input).digest("base64url");
}

function constantTimeEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer);
}

