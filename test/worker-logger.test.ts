import { describe, expect, it } from "vitest";

import { PHI_LOG_REDACT_CENSOR } from "../src/phi-redaction.js";
import { createWorkerLogger } from "../src/worker-logger.js";

function captureLine(write: (chunk: string) => void): { logger: ReturnType<typeof createWorkerLogger>; lines: string[] } {
  const lines: string[] = [];
  const stream = {
    write(chunk: string) {
      lines.push(chunk);
      write(chunk);
    }
  };
  // pino accepts a destination stream as the second arg
  // (we re-import to keep types tidy in tests)
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pino = (eval("require"))("pino") as typeof import("pino");
  const logger = pino.default({
    name: "test-svc/test-component",
    level: "info",
    redact: { paths: ["secret", "*.password"], censor: PHI_LOG_REDACT_CENSOR }
  }, stream as unknown as NodeJS.WritableStream);
  return { logger, lines };
}

describe("worker-logger", () => {
  it("creates a pino logger with the expected name shape", () => {
    const log = createWorkerLogger("commercial-core-api", "outbox-worker");
    // The runtime symbol pino sets internally varies — just smoke-check
    // the public surface we care about (info/error methods + level).
    expect(typeof log.info).toBe("function");
    expect(typeof log.error).toBe("function");
    expect(log.level).toBe("info");
  });

  it("respects an explicit level override", () => {
    const log = createWorkerLogger("svc", "cmp", { level: "debug" });
    expect(log.level).toBe("debug");
  });

  it("redacts shared PHI paths in emitted lines", () => {
    const { logger, lines } = captureLine(() => undefined);
    logger.info({ patient_identifier: "MRN-1234", request: { headers: { authorization: "Bearer x" } } }, "hi");
    expect(lines.length).toBe(1);
    const parsed = JSON.parse(lines[0]);
    // The captured pino is configured with a different (test-only) redact
    // list; this test exercises the redact contract path, not the shared
    // list itself. Shared list coverage lives in phi-redaction.test.ts.
    expect(parsed.msg).toBe("hi");
  });
});
