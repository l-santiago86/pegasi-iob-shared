/**
 * PHI / PII redaction baseline for IOB structured logs.
 *
 * This module exports the canonical list of JSON paths that should be
 * masked anywhere a payload might be serialized into a log line — the
 * Fastify logger config in each service should pass `PHI_LOG_REDACT_PATHS`
 * (and the matching `redact.censor`) into `pino`. We keep the list here
 * (in pegasi-iob-shared) so the 6 services do not drift.
 *
 * The list is intentionally narrow at first: it only covers the obvious
 * direct-identifier fields we ship across the network. The next pass adds
 * a runtime guard that recursively scans request/response payloads for
 * patterns (e.g. "rut", "ssn", "dni", "email", "phone") and warns when an
 * unredacted match shows up.
 */

/**
 * Fastify uses these as `redact.paths` for its pino logger. The shape is
 * pino's documented JSONpath-lite (no leading "$.", supports wildcards).
 *
 * @see https://getpino.io/#/docs/redaction
 */
export const PHI_LOG_REDACT_PATHS = Object.freeze([
  // Direct identifiers carried in admission requests + activation runs.
  "*.patient_identifier",
  "*.patient_id",
  "*.mrn",
  "*.medical_record_number",
  "*.rut",
  "*.dni",
  "*.ssn",
  "*.passport_number",
  "*.email",
  "*.phone",
  "*.phone_number",
  "*.date_of_birth",
  "*.dob",
  "*.address",
  "*.full_name",
  "*.given_name",
  "*.family_name",
  // Auth / secret material that must never land in logs.
  "*.password",
  "*.password_hash",
  "*.secret",
  "*.access_token",
  "*.refresh_token",
  "*.id_token",
  "*.jwt",
  "*.private_key",
  "*.api_key",
  "*.client_secret",
  "*.authorization",
  "req.headers.authorization",
  "headers.authorization",
  // Inline payload bodies sometimes contain PHI directly.
  "*.local_payload_inline_base64"
]);

/**
 * pino-style censor token. Use `[REDACTED]` so log scanners can grep for
 * accidental misses (an unredacted PHI field will not contain this token).
 */
export const PHI_LOG_REDACT_CENSOR = "[REDACTED]";

/**
 * Field-name patterns we treat as suspicious if they appear unredacted.
 * Used by the runtime guard helper below to surface drift between the
 * service's logger config and the canonical list.
 */
export const PHI_FIELD_NAME_PATTERNS = Object.freeze<readonly RegExp[]>([
  /^patient[_-]?(id|identifier)$/i,
  /^mrn$/i,
  /^medical[_-]?record[_-]?number$/i,
  /^rut$/i,
  /^dni$/i,
  /^ssn$/i,
  /^email$/i,
  /^phone(_number)?$/i,
  /^date[_-]?of[_-]?birth$/i,
  /^dob$/i,
  /^address$/i,
  /^(full|given|family)[_-]?name$/i,
  /^password(_hash)?$/i,
  /^(access|refresh|id)[_-]?token$/i,
  /^(api|client)[_-]?(key|secret)$/i,
  /^private[_-]?key$/i,
  /^jwt$/i,
  /^authorization$/i
]);

/**
 * Walks an arbitrary value and returns the dotted paths of any keys whose
 * names match {@link PHI_FIELD_NAME_PATTERNS}. Use this in unit tests to
 * fail the build if a service starts emitting PHI through a new field
 * the redact list does not yet cover.
 *
 * Caps recursion depth at 10 and array index inspection at 50 entries to
 * avoid blowing up on large payloads.
 */
export function findUnredactedPhiPaths(
  value: unknown,
  options: { readonly maxDepth?: number; readonly maxArray?: number } = {}
): readonly string[] {
  const maxDepth = options.maxDepth ?? 10;
  const maxArray = options.maxArray ?? 50;
  const matches: string[] = [];
  visit(value, "", 0);
  return matches;

  function visit(node: unknown, path: string, depth: number): void {
    if (depth > maxDepth || node === null || node === undefined) {
      return;
    }
    if (Array.isArray(node)) {
      const limit = Math.min(node.length, maxArray);
      for (let i = 0; i < limit; i += 1) {
        visit(node[i], `${path}[${i}]`, depth + 1);
      }
      return;
    }
    if (typeof node !== "object") {
      return;
    }
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const childPath = path ? `${path}.${key}` : key;
      if (PHI_FIELD_NAME_PATTERNS.some((rx) => rx.test(key))) {
        matches.push(childPath);
      }
      visit(child, childPath, depth + 1);
    }
  }
}
