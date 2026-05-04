import Fastify from "fastify";
import { describe, expect, it } from "vitest";

import { InMemoryAuditLogger, registerAuditHook } from "../src/audit.js";

describe("audit hook", () => {
  it("emits one event per non-health request with actor + outcome", async () => {
    const logger = new InMemoryAuditLogger();
    const app = Fastify({ logger: false });
    registerAuditHook(app, {
      serviceName: "test-svc",
      loggerFactory: () => logger
    });
    app.get("/health/live", async () => ({ status: "ok" }));
    app.get("/widgets", async (request) => {
      (request as { authContext?: unknown }).authContext = {
        subject: "actor_smoke_001",
        tenant_scope_id: "tenant_smoke_001",
        actor: { actor_type: "USER", subject: "actor_smoke_001" }
      };
      return { items: [] };
    });
    app.post("/widgets", async (request, reply) => {
      (request as { authContext?: unknown }).authContext = {
        subject: "actor_smoke_001",
        tenant_scope_id: "tenant_smoke_001",
        actor: { actor_type: "USER", subject: "actor_smoke_001" }
      };
      reply.code(201);
      return { id: "w_001" };
    });
    app.get("/explode", async () => {
      throw new Error("boom");
    });

    await app.inject({ method: "GET", url: "/health/live" });
    await app.inject({
      method: "GET",
      url: "/widgets?limit=10",
      headers: { "x-correlation-id": "corr-1", "x-request-id": "req-1" }
    });
    await app.inject({
      method: "POST",
      url: "/widgets",
      headers: { "x-correlation-id": "corr-2", "x-request-id": "req-2" }
    });
    await app.inject({ method: "GET", url: "/explode" });

    expect(logger.events.length).toBe(3); // health/live skipped
    expect(logger.events[0]).toMatchObject({
      audit_event: true,
      service: "test-svc",
      method: "GET",
      url: "/widgets",
      status_code: 200,
      outcome: "success",
      actor_subject: "actor_smoke_001",
      tenant_scope_id: "tenant_smoke_001",
      actor_type: "USER",
      correlation_id: "corr-1",
      request_id: "req-1"
    });
    expect(logger.events[1]).toMatchObject({
      method: "POST",
      url: "/widgets",
      status_code: 201,
      outcome: "success"
    });
    expect(logger.events[2]).toMatchObject({
      method: "GET",
      url: "/explode",
      status_code: 500,
      outcome: "server_error",
      actor_subject: null,
      tenant_scope_id: null
    });
  });

  it("strips query string from url and respects custom skip prefixes", async () => {
    const logger = new InMemoryAuditLogger();
    const app = Fastify({ logger: false });
    registerAuditHook(app, {
      serviceName: "test-svc",
      skipPathPrefixes: ["/internal/"],
      loggerFactory: () => logger
    });
    app.get("/widgets", async () => ({ ok: true }));
    app.get("/internal/debug", async () => ({ ok: true }));
    app.get("/health/live", async () => ({ ok: true }));

    await app.inject({ method: "GET", url: "/widgets?a=1&b=2" });
    await app.inject({ method: "GET", url: "/internal/debug" });
    await app.inject({ method: "GET", url: "/health/live" });

    expect(logger.events.length).toBe(2); // /internal/debug skipped, /health/live NOT skipped (custom prefixes override the default)
    expect(logger.events[0]?.url).toBe("/widgets");
    expect(logger.events[1]?.url).toBe("/health/live");
  });

  it("classifies 4xx as client_error", async () => {
    const logger = new InMemoryAuditLogger();
    const app = Fastify({ logger: false });
    registerAuditHook(app, { serviceName: "test-svc", loggerFactory: () => logger });
    app.post("/widgets", async (_request, reply) => {
      reply.code(400);
      return { error: "bad" };
    });
    await app.inject({ method: "POST", url: "/widgets" });
    expect(logger.events[0]?.status_code).toBe(400);
    expect(logger.events[0]?.outcome).toBe("client_error");
  });

  it("never throws when logger.record fails (audit must not break requests)", async () => {
    const logger = {
      record() {
        throw new Error("audit pipeline down");
      }
    };
    const app = Fastify({ logger: false });
    registerAuditHook(app, { serviceName: "test-svc", loggerFactory: () => logger });
    app.get("/widgets", async () => ({ ok: true }));
    const r = await app.inject({ method: "GET", url: "/widgets" });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toEqual({ ok: true });
  });
});
