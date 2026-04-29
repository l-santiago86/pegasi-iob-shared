export type EnvRecord = Readonly<Record<string, string | undefined>>;

export function requiredEnv(name: string, env: EnvRecord = process.env): string {
  const value = env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

export function optionalEnv(name: string, env: EnvRecord = process.env): string | undefined {
  const value = env[name];
  if (!value || value.trim().length === 0) {
    return undefined;
  }
  return value;
}

export function parsePositiveIntegerEnv(value: string | undefined, fallback: number): number {
  if (!Number.isInteger(fallback) || fallback <= 0) {
    throw new Error("Positive integer fallback is required.");
  }
  if (value === undefined || value.trim().length === 0) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Expected positive integer environment value, received '${value}'.`);
  }
  return parsed;
}

export function parseBooleanEnv(value: string | undefined, fallback = false): boolean {
  if (value === undefined || value.trim().length === 0) {
    return fallback;
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  throw new Error(`Expected boolean environment value, received '${value}'.`);
}

