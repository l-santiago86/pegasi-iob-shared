#!/usr/bin/env node
// PEGASI IOB — anti-PHI lint check
//
// Runs as a CI gate to prevent accidental PHI/PII leakage into stdout.
//
// Detects three classes of violation:
//
//   1. Direct console.* calls (console.log/info/warn/error/debug). These
//      bypass Pino entirely, which means the PHI_LOG_REDACT_PATHS
//      configured on the Fastify logger doesn't apply. Forbidden in
//      service src/ — use `request.log` or `app.log` instead.
//
//   2. Direct process.stdout.write / process.stderr.write calls. Same
//      reason — these bypass Pino. Forbidden in service src/.
//
//   3. Pino logger configs (a `redact:` field on a logger options object)
//      that don't pull in PHI_LOG_REDACT_PATHS from the shared library.
//      A service authoring its own redact list is drift waiting to happen.
//
// Each violation reports file:line:column with the offending source line
// and a short remediation hint, then exits non-zero so CI fails the build.
//
// Override mechanism: a violation can be silenced by adding a comment
//   // allow-phi-lint: <human-readable reason>
// either on the same line or directly above. This keeps overrides
// auditable in code review (every exception has a written justification).
//
// Usage:
//   npx lint-phi src/                    # lint a directory
//   npx lint-phi src/ test/              # multiple roots
//   npx lint-phi --help

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { argv, exit, cwd } from "node:process";

const DEFAULT_EXTENSIONS = new Set([".ts", ".mjs", ".js", ".cjs"]);
const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".git",
  ".next",
  ".turbo"
]);

// Test files run as one-off processes and may legitimately need
// console.log for vitest debug output. We still scan them but treat
// console.* as warnings, not errors. The redact-config check still
// applies (test code shouldn't define a competing redact list).
const TEST_FILE_PATTERNS = [
  /\.test\.[mc]?[jt]s$/i,
  /\.spec\.[mc]?[jt]s$/i,
  /[\\/]test[\\/]/i,
  /[\\/]tests[\\/]/i,
  /[\\/]__tests__[\\/]/i
];

const FORBIDDEN_CONSOLE = /\bconsole\s*\.\s*(log|info|warn|error|debug)\s*\(/g;
const FORBIDDEN_PROCESS_WRITE = /\bprocess\s*\.\s*(stdout|stderr)\s*\.\s*write\s*\(/g;
const REDACT_FIELD_DECL = /\bredact\s*:\s*\{/g;
const PHI_PATHS_IMPORT = /PHI_LOG_REDACT_PATHS/;

const ALLOW_COMMENT = /\/\/\s*allow-phi-lint\s*:\s*(.+)$/i;

function isTestFile(file) {
  return TEST_FILE_PATTERNS.some((rx) => rx.test(file));
}

function* walk(root) {
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOENT") {
      return;
    }
    throw err;
  }
  for (const entry of entries) {
    const full = join(root, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) {
        continue;
      }
      yield* walk(full);
    } else if (entry.isFile()) {
      const ext = entry.name.slice(entry.name.lastIndexOf("."));
      if (DEFAULT_EXTENSIONS.has(ext)) {
        yield full;
      }
    }
  }
}

function lineColFromIndex(source, index) {
  let line = 1;
  let col = 1;
  for (let i = 0; i < index; i += 1) {
    if (source[i] === "\n") {
      line += 1;
      col = 1;
    } else {
      col += 1;
    }
  }
  return { line, col };
}

function getLineText(source, lineNumber) {
  const lines = source.split("\n");
  return lines[lineNumber - 1] ?? "";
}

function isAllowed(source, lineNumber) {
  const lines = source.split("\n");
  const same = lines[lineNumber - 1] ?? "";
  if (ALLOW_COMMENT.test(same)) {
    return true;
  }
  // Also accept the comment immediately above the offending line.
  const above = lines[lineNumber - 2] ?? "";
  return ALLOW_COMMENT.test(above.trimStart());
}

function lintFile(filePath, displayPath) {
  const source = readFileSync(filePath, "utf8");
  const violations = [];
  const isTest = isTestFile(filePath);

  // Rule 1: console.*
  for (const match of source.matchAll(FORBIDDEN_CONSOLE)) {
    const { line, col } = lineColFromIndex(source, match.index);
    if (isAllowed(source, line)) continue;
    violations.push({
      severity: isTest ? "warn" : "error",
      rule: "no-console",
      file: displayPath,
      line,
      col,
      text: getLineText(source, line).trim(),
      hint: "use request.log / app.log (Fastify Pino) so PHI_LOG_REDACT_PATHS applies"
    });
  }

  // Rule 2: process.stdout/stderr.write
  for (const match of source.matchAll(FORBIDDEN_PROCESS_WRITE)) {
    const { line, col } = lineColFromIndex(source, match.index);
    if (isAllowed(source, line)) continue;
    violations.push({
      severity: "error",
      rule: "no-direct-write",
      file: displayPath,
      line,
      col,
      text: getLineText(source, line).trim(),
      hint: "direct process.stdout/stderr.write bypasses Pino redact — use the Fastify logger"
    });
  }

  // Rule 3: redact: {...} declared but PHI_LOG_REDACT_PATHS not imported
  // anywhere in the file. We accept the broader file-level reference
  // because a service's logger config can be split across files (e.g.
  // logger-options.ts importing the constant, then platform.ts using it).
  // For service-internal split, run the lint against the whole src/.
  const hasRedactDecl = REDACT_FIELD_DECL.test(source);
  // reset lastIndex because the regex is global
  REDACT_FIELD_DECL.lastIndex = 0;
  if (hasRedactDecl && !PHI_PATHS_IMPORT.test(source)) {
    const match = source.match(REDACT_FIELD_DECL);
    const idx = source.indexOf(match[0]);
    const { line, col } = lineColFromIndex(source, idx);
    if (!isAllowed(source, line)) {
      violations.push({
        severity: "error",
        rule: "use-shared-redact",
        file: displayPath,
        line,
        col,
        text: getLineText(source, line).trim(),
        hint: "import PHI_LOG_REDACT_PATHS from @pegasimed.com/pegasi-iob-shared instead of authoring a local redact list"
      });
    }
  }

  return violations;
}

function printHelp() {
  // eslint-disable-next-line no-console -- CLI usage output
  console.log(`Usage: lint-phi <path> [<path>...]

Scans the given paths for forbidden logging patterns that could leak PHI:

  no-console        console.log/info/warn/error/debug calls bypass Pino redact
  no-direct-write   process.stdout/stderr.write bypasses Pino redact
  use-shared-redact a Pino redact: {...} declaration without importing
                    PHI_LOG_REDACT_PATHS from @pegasimed.com/pegasi-iob-shared

Override a single violation by writing a justification comment:

    foo();  // allow-phi-lint: bootstrap-only, runs before logger init

Test files (*.test.ts, *.spec.ts, **/test/**, **/__tests__/**) get a warning
for no-console rather than an error — the redact rules still error.

Exit code: 0 if no errors (warnings allowed), 1 if any error found.`);
}

function main() {
  const args = argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return 0;
  }
  if (args.length === 0) {
    printHelp();
    return 1;
  }

  const allViolations = [];
  for (const arg of args) {
    const root = resolve(cwd(), arg);
    let stat;
    try {
      stat = statSync(root);
    } catch (err) {
      if (err.code === "ENOENT") {
        // eslint-disable-next-line no-console -- CLI diagnostic
        console.error(`lint-phi: path not found: ${arg}`);
        return 1;
      }
      throw err;
    }
    const files = stat.isDirectory() ? Array.from(walk(root)) : [root];
    for (const file of files) {
      const display = relative(cwd(), file).split(sep).join("/");
      allViolations.push(...lintFile(file, display));
    }
  }

  if (allViolations.length === 0) {
    // eslint-disable-next-line no-console -- CLI summary
    console.log("lint-phi: 0 violations");
    return 0;
  }

  const errors = allViolations.filter((v) => v.severity === "error");
  const warnings = allViolations.filter((v) => v.severity === "warn");

  for (const v of allViolations) {
    const tag = v.severity === "error" ? "ERROR" : "WARN ";
    // eslint-disable-next-line no-console -- CLI report
    console.error(
      `${tag} ${v.file}:${v.line}:${v.col}  [${v.rule}]\n  ${v.text}\n  hint: ${v.hint}`
    );
  }
  // eslint-disable-next-line no-console -- CLI summary
  console.error(
    `\nlint-phi: ${errors.length} error(s), ${warnings.length} warning(s)`
  );
  return errors.length > 0 ? 1 : 0;
}

exit(main());
