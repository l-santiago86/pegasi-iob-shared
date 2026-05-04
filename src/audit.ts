/**
 * HTTP audit baseline for IOB services.
 *
 * Emits one structured "audit_event" log line per non-health request,
 * stamped with: actor (sub), tenant_scope_id, HTTP method + path,
 * status code, duration, correlation + request IDs. The output flows
 * through the existing pino logger so it lands in Loki + CloudWatch
 * Logs without any extra plumbing — query with
 * `{audit_event="true"}` in Loki.
 *
 * What this complements:
 *   - DB-level audit (pgaudit on Aurora) captures every SQL mutation
 *     with actor=db_user. That's the ground truth for what happened
 *     to data, but does NOT carry the JWT actor / tenant — only the
 *     shared service DB user.
 *   - This module captures the HTTP-level "who (JWT actor + tenant)
 *     called which API endpoint with what outcome" so the two layers
 *     join: pgaudit gives you "what changed", this gives you "who
 *     asked for that change to happen via the API".
 *
 * What this intentionally does NOT log:
 *   - Request bodies. Bodies are the most likely PHI/PII vector and
 *     redaction at this layer would be incomplete. The pgaudit stream
 *     already carries the SQL (with binds replaced by <not logged>).
 *   - Response bodies. Same reason.
 *   - Authorization header. Already redacted by the pino redact list
 *     in @pegasimed.com/pegasi-iob-shared/phi-redaction.
 */

import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  HookHandlerDoneFunction
} from "fastify";

/**
 * Minimal shape of the auth context attached to a request by the
 * service's BearerAuthVerifier. Kept as `unknown` here because each
 * service has its own AuthContext type with extra fields (roles,
 * tenant_scope_id pattern, etc.); the audit hook only reads the two
 * common fields by duck-type.
 */
export interface AuditAuthRef {
  readonly subject?: string;
  readonly tenant_scope_id?: string;
  readonly actor?: { readonly actor_type?: string; readonly subject?: string };
}

export interface AuditEvent {
  readonly audit_event: true;
  readonly service: string;
  readonly actor_subject: string | null;
  readonly tenant_scope_id: string | null;
  readonly actor_type: string | null;
  readonly method: string;
  readonly url: string;
  readonly status_code: number;
  readonly duration_ms: number;
  readonly correlation_id: string | null;
  readonly request_id: string | null;
  readonly remote_addr: string | null;
  readonly outcome: "success" | "client_error" | "server_error";
  readonly occurred_at: string;
}

export interface AuditLogger {
  record(event: AuditEvent): void;
}

/**
 * Default logger — writes through Fastify's `request.log`. The pino
 * logger sees the `audit_event: true` field and forwards the rest.
 * Loki/CloudWatch consumers query by that label.
 */
export class FastifyLogAuditLogger implements AuditLogger {
  constructor(private readonly request: FastifyRequest) {}

  record(event: AuditEvent): void {
    this.request.log.info(event, "audit");
  }
}

/** Test helper. */
export class InMemoryAuditLogger implements AuditLogger {
  readonly events: AuditEvent[] = [];

  record(event: AuditEvent): void {
    this.events.push(event);
  }
}

export interface AuditHookOptions {
  /** Service name (e.g. "commercial-core-api") — included on every event. */
  readonly serviceName: string;
  /**
   * Path globs to skip. Defaults skip /health/*, the typical noise.
   * Match is exact-or-startsWith on the URL path before the query string.
   */
  readonly skipPathPrefixes?: readonly string[];
  /**
   * Inject a non-default logger (typically only used in tests). When
   * unset, each request gets a {@link FastifyLogAuditLogger} bound to
   * the request's pino child logger.
   */
  readonly loggerFactory?: (request: FastifyRequest) => AuditLogger;
}

const DEFAULT_SKIP_PREFIXES: readonly string[] = ["/health/"];

/**
 * Registers the audit hook on a Fastify instance. Call once at app
 * boot, after auth handlers are registered (so request.authContext is
 * populated before onResponse fires).
 */
export function registerAuditHook(app: FastifyInstance, options: AuditHookOptions): void {
  const skip = options.skipPathPrefixes ?? DEFAULT_SKIP_PREFIXES;
  const loggerFactory = options.loggerFactory ?? ((req) => new FastifyLogAuditLogger(req));

  app.addHook("onRequest", (request: FastifyRequest, _reply: FastifyReply, done: HookHandlerDoneFunction) => {
    (request as { __auditStart?: bigint }).__auditStart = process.hrtime.bigint();
    done();
  });

  app.addHook("onResponse", (request: FastifyRequest, reply: FastifyReply, done: HookHandlerDoneFunction) => {
    try {
      const path = (request.url ?? "").split("?", 1)[0] ?? "";
      if (skip.some((prefix) => path === prefix || path.startsWith(prefix))) {
        done();
        return;
      }
      const start = (request as { __auditStart?: bigint }).__auditStart;
      const durationNs = start !== undefined ? Number(process.hrtime.bigint() - start) : 0;
      const auth = (request as { authContext?: AuditAuthRef }).authContext;
      const headers = request.headers as Record<string, string | string[] | undefined>;
      const correlationId = pickHeader(headers, "x-correlation-id");
      const requestId = pickHeader(headers, "x-request-id");
      const remoteAddr =
        pickHeader(headers, "x-forwarded-for")?.split(",")[0]?.trim() ?? request.ip ?? null;
      const status = reply.statusCode;
      const outcome: AuditEvent["outcome"] =
        status >= 500 ? "server_error" : status >= 400 ? "client_error" : "success";
      const event: AuditEvent = {
        audit_event: true,
        service: options.serviceName,
        actor_subject: auth?.actor?.subject ?? auth?.subject ?? null,
        tenant_scope_id: auth?.tenant_scope_id ?? null,
        actor_type: auth?.actor?.actor_type ?? null,
        method: request.method,
        url: path,
        status_code: status,
        duration_ms: Math.round(durationNs / 1_000_000),
        correlation_id: correlationId ?? null,
        request_id: requestId ?? null,
        remote_addr: remoteAddr,
        outcome,
        occurred_at: new Date().toISOString()
      };
      loggerFactory(request).record(event);
    } catch (err) {
      // Audit must never break a request. Log + swallow.
      request.log.warn({ err: err instanceof Error ? err.message : String(err) }, "audit hook failed");
    }
    done();
  });
}

function pickHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const v = headers[name];
  if (typeof v === "string") return v;
  if (Array.isArray(v) && v.length > 0) return v[0];
  return undefined;
}
