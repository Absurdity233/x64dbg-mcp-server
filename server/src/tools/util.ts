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

export interface Page<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
  truncated: boolean;
}

/** Slice an array for a tool response without hiding the total count. */
export function pageArray<T>(items: T[], offset = 0, limit = 500): Page<T> {
  const start = Math.max(0, Math.floor(offset));
  const size = Math.max(0, Math.floor(limit));
  const slice = items.slice(start, start + size);
  return {
    items: slice,
    total: items.length,
    offset: start,
    limit: size,
    truncated: start + slice.length < items.length,
  };
}

/**
 * Page the first array-valued field of a plugin response, keeping the rest of
 * the object intact. Used by the list-heavy tools (strings, xrefs, search
 * matches, constants) whose JSON is not touched by X64DBG_MCP_MAX_BYTES.
 * Returns null when the response has no array field.
 */
export function pageFirstArray(data: unknown, offset = 0, limit = 500): any | null {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const obj = data as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (!Array.isArray(value)) continue;
    const page = pageArray(value, offset, limit);
    return {
      ...obj,
      [key]: page.items,
      total: page.total,
      returned: page.items.length,
      offset: page.offset,
      limit: page.limit,
      truncated: page.truncated,
    };
  }
  return null;
}

/** pageFirstArray with a fallback for responses that have no array field. */
export function pageResult(data: unknown, offset = 0, limit = 500): any {
  return pageFirstArray(data, offset, limit) ?? data;
}
