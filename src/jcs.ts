/**
 * JSON Canonicalization Scheme (JCS) — RFC 8785.
 *
 * Produces a deterministic JSON serialization:
 *  - Object keys sorted lexicographically (by Unicode code point)
 *  - No insignificant whitespace
 *  - Consistent number formatting (no NaN/Infinity; integers without decimals)
 *  - Strings escaped per RFC 8259 with supplementary-plane code points
 *    preserved as surrogate pairs (JCS requirement).
 */

/**
 * Canonicalize any JSON-compatible value to its JCS byte string.
 */
export function jcsCanonicalize(value: unknown): string {
  return serializeValue(value);
}

function serializeValue(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'number') {
    return serializeNumber(value);
  }
  if (typeof value === 'string') {
    return serializeString(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(serializeValue).join(',') + ']';
  }
  if (typeof value === 'object') {
    return serializeObject(value as Record<string, unknown>);
  }
  throw new Error(`JCS: unsupported value type: ${typeof value}`);
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error('JCS: NaN and Infinity are not permitted');
  }
  // RFC 8785 §4: use the shortest representation that round-trips.
  // JSON.stringify already does this for IEEE 754 doubles.
  return JSON.stringify(n);
}

function serializeString(s: string): string {
  return JSON.stringify(s);
}

function serializeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    // Skip undefined values (they are not valid JSON).
    if (obj[key] === undefined) continue;
    parts.push(serializeString(key) + ':' + serializeValue(obj[key]));
  }
  return '{' + parts.join(',') + '}';
}
