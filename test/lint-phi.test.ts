// Smoke tests for the lint-phi CLI. We invoke the script as a subprocess
// against synthetic fixtures written to a tempdir, then assert on stdout/
// stderr + exit code. This keeps the test logic independent of the CLI's
// internal helpers (which are not exported on purpose — it's a binary).

import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve as resolvePath } from "node:path";
import { describe, expect, it, beforeEach, afterEach } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const lintPhi = resolvePath(here, "..", "scripts", "lint-phi.mjs");

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "lint-phi-test-"));
  mkdirSync(join(tmp, "src"), { recursive: true });
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function runLint(...args: string[]) {
  return spawnSync(process.execPath, [lintPhi, ...args], {
    encoding: "utf8",
    cwd: tmp
  });
}

describe("lint-phi", () => {
  it("passes when there are no violations", () => {
    writeFileSync(
      join(tmp, "src", "clean.ts"),
      `export function add(a: number, b: number) { return a + b; }\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("0 violations");
  });

  it("fails on console.log in non-test source", () => {
    writeFileSync(
      join(tmp, "src", "bad.ts"),
      `export function leak(x: { mrn: string }) {\n  console.log("payload", x);\n}\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("[no-console]");
    expect(r.stderr).toContain("ERROR");
  });

  it("warns but does not fail on console.log in test files", () => {
    mkdirSync(join(tmp, "test"), { recursive: true });
    writeFileSync(
      join(tmp, "test", "foo.test.ts"),
      `import { it } from "vitest";\nit("logs", () => { console.log("ok"); });\n`
    );
    const r = runLint("test");
    expect(r.status).toBe(0);
    expect(r.stderr).toContain("WARN ");
    expect(r.stderr).toContain("[no-console]");
  });

  it("fails on process.stdout.write", () => {
    writeFileSync(
      join(tmp, "src", "raw.ts"),
      `export function dump(x: string) {\n  process.stdout.write(x);\n}\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("[no-direct-write]");
  });

  it("fails on a redact: declaration without importing PHI_LOG_REDACT_PATHS", () => {
    writeFileSync(
      join(tmp, "src", "logger.ts"),
      `import Fastify from "fastify";\nexport const app = Fastify({ logger: { redact: { paths: ["password"] } } });\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("[use-shared-redact]");
  });

  it("accepts a redact: declaration when PHI_LOG_REDACT_PATHS is imported in the same file", () => {
    writeFileSync(
      join(tmp, "src", "logger.ts"),
      `import Fastify from "fastify";\nimport { PHI_LOG_REDACT_PATHS } from "@pegasimed.com/pegasi-iob-shared";\nexport const app = Fastify({ logger: { redact: { paths: [...PHI_LOG_REDACT_PATHS] } } });\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(0);
  });

  it("respects the // allow-phi-lint override on the same line", () => {
    writeFileSync(
      join(tmp, "src", "boot.ts"),
      `export function boot() {\n  console.log("starting"); // allow-phi-lint: bootstrap before logger init\n}\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(0);
  });

  it("respects the // allow-phi-lint override on the line above", () => {
    writeFileSync(
      join(tmp, "src", "boot.ts"),
      `export function boot() {\n  // allow-phi-lint: bootstrap before logger init\n  console.log("starting");\n}\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(0);
  });

  it("skips node_modules and dist", () => {
    mkdirSync(join(tmp, "src", "node_modules", "evil"), { recursive: true });
    writeFileSync(
      join(tmp, "src", "node_modules", "evil", "leak.ts"),
      `console.log("from node_modules");\n`
    );
    mkdirSync(join(tmp, "src", "dist"), { recursive: true });
    writeFileSync(
      join(tmp, "src", "dist", "leak.ts"),
      `console.log("from dist");\n`
    );
    const r = runLint("src");
    expect(r.status).toBe(0);
  });

  it("returns 1 when given a nonexistent path", () => {
    const r = runLint("does-not-exist");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("path not found");
  });

  it("prints help with --help and exits 0", () => {
    const r = runLint("--help");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Usage: lint-phi");
  });
});
