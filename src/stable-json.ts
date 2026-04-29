export function stableStringify(value: unknown): string {
  return JSON.stringify(toStableJsonValue(value, new WeakSet()));
}

function toStableJsonValue(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    throw new Error("Cannot stableStringify circular data.");
  }
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => toStableJsonValue(item, seen));
    seen.delete(value);
    return result;
  }
  const object = value as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(object).sort()) {
    const item = object[key];
    if (item !== undefined) {
      result[key] = toStableJsonValue(item, seen);
    }
  }
  seen.delete(value);
  return result;
}

