import { randomUUID } from "node:crypto";

const ID_PREFIX_PATTERN = /^[a-z][a-z0-9_]*$/;

export function randomPrefixedId(prefix: string): string {
  if (!ID_PREFIX_PATTERN.test(prefix)) {
    throw new Error(`Invalid PEGASI IOB id prefix '${prefix}'.`);
  }
  return `${prefix}_${randomUUID().replaceAll("-", "")}`;
}

export function assertPrefixedId(value: string, prefix: string): string {
  if (!ID_PREFIX_PATTERN.test(prefix)) {
    throw new Error(`Invalid PEGASI IOB id prefix '${prefix}'.`);
  }
  const pattern = new RegExp(`^${escapeRegExp(prefix)}_[A-Za-z0-9_-]{6,}$`);
  if (!pattern.test(value)) {
    throw new Error(`Expected ${prefix} id, received '${value}'.`);
  }
  return value;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

