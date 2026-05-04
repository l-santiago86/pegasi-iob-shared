import { describe, expect, it } from "vitest";

import {
  PHI_FIELD_NAME_PATTERNS,
  PHI_LOG_REDACT_CENSOR,
  PHI_LOG_REDACT_PATHS,
  findUnredactedPhiPaths
} from "../src/phi-redaction.js";

describe("phi-redaction", () => {
  it("exposes a frozen redact path list", () => {
    expect(Object.isFrozen(PHI_LOG_REDACT_PATHS)).toBe(true);
    expect(PHI_LOG_REDACT_PATHS).toContain("*.patient_identifier");
    expect(PHI_LOG_REDACT_PATHS).toContain("req.headers.authorization");
  });

  it("uses [REDACTED] as the censor token", () => {
    expect(PHI_LOG_REDACT_CENSOR).toBe("[REDACTED]");
  });

  it("flags PHI-shaped fields with findUnredactedPhiPaths", () => {
    const payload = {
      patient: { mrn: "ABC123", date_of_birth: "1990-01-01" },
      contact: { email: "p@example.com", phone_number: "+56912345678" },
      audit: { actor: "u1" }
    };
    const found = findUnredactedPhiPaths(payload);
    expect(found).toEqual(
      expect.arrayContaining([
        "patient.mrn",
        "patient.date_of_birth",
        "contact.email",
        "contact.phone_number"
      ])
    );
    expect(found).not.toContain("audit.actor");
  });

  it("walks arrays + nested objects", () => {
    const payload = {
      records: [
        { rut: "11.111.111-1" },
        { rut: "22.222.222-2", address: "Av Apoquindo 1234" }
      ]
    };
    const found = findUnredactedPhiPaths(payload);
    expect(found).toEqual(["records[0].rut", "records[1].rut", "records[1].address"]);
  });

  it("respects maxDepth", () => {
    const deep: Record<string, unknown> = {};
    let cursor: Record<string, unknown> = deep;
    for (let i = 0; i < 15; i += 1) {
      cursor.next = {};
      cursor = cursor.next as Record<string, unknown>;
    }
    cursor.email = "x@y.z";
    expect(findUnredactedPhiPaths(deep, { maxDepth: 5 })).toEqual([]);
    expect(findUnredactedPhiPaths(deep, { maxDepth: 20 })).toContain(
      "next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.email"
    );
  });

  it("PHI_FIELD_NAME_PATTERNS rejects boring identifiers", () => {
    const safe = ["actor", "tenant_scope_id", "node_task_id", "status"];
    for (const key of safe) {
      const matched = PHI_FIELD_NAME_PATTERNS.some((rx) => rx.test(key));
      expect(matched).toBe(false);
    }
  });
});
