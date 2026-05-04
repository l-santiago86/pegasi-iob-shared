// Standalone Pino factory for non-Fastify worker processes
// (events-consumer, outbox dispatcher, projection workers, etc).
// They run as separate Node processes and don't get the app.log
// instance configured in each service's platform.ts, but they still
// need the shared PHI_LOG_REDACT_PATHS applied so accidentally
// logging a PHI field gets redacted just like in the HTTP path.
//
// Pino is bundled with Fastify (peerDependency); we declare it as
// our own peerDependency too so consumers don't pull a duplicate copy.
//
// Usage:
//   import { createWorkerLogger } from "@pegasimed.com/pegasi-iob-shared";
//   const log = createWorkerLogger("commercial-core-api", "outbox-worker");
//   log.info({ result }, "cycle done");

import pino from "pino";

import { PHI_LOG_REDACT_CENSOR, PHI_LOG_REDACT_PATHS } from "./phi-redaction.js";

export interface WorkerLoggerOptions {
  /** Override the LOG_LEVEL env default. */
  readonly level?: pino.LevelWithSilent;
}

/**
 * Build a Pino logger pre-configured with the shared PHI redact paths
 * and a `<service>/<component>` name.
 *
 * @param service  e.g. "commercial-core-api" — the npm package name root
 * @param component e.g. "outbox-worker" — the worker's role
 */
export function createWorkerLogger(
  service: string,
  component: string,
  options: WorkerLoggerOptions = {}
): pino.Logger {
  return pino({
    name: `${service}/${component}`,
    level: options.level ?? (process.env.LOG_LEVEL as pino.LevelWithSilent | undefined) ?? "info",
    redact: { paths: [...PHI_LOG_REDACT_PATHS], censor: PHI_LOG_REDACT_CENSOR }
  });
}
