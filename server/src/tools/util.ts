// Shared helpers for the flattened (non-discriminatedUnion) tool schemas.
//
// The upstream server described every action as its own z.object inside a
// z.discriminatedUnion. That validates nicely, but serialises to one `anyOf`
// branch per action, which more than doubles the tool schema size we ship to
// the model. Flat `z.enum(action)` + optional fields keeps the schema small;
// these helpers put the required-field checks back at call time.

export function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`'${name}' is required for this action`);
  }
  return value;
}

export function requireNumber(value: unknown, name: string): number {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw new Error(`'${name}' is required for this action`);
  }
  return value;
}

/** Escape a value for use inside an x64dbg quoted command argument. */
export function quoteArg(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}
