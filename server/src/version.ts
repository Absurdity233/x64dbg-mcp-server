import { readFileSync } from 'node:fs';

/**
 * Single source of truth for the server version: package.json, which the plugin's
 * build also reads (see plugin/CMakeLists.txt), so /api/meta can compare like
 * with like.
 */
let cached: string | null = null;

export function getVersion(): string {
  if (cached !== null) return cached;
  try {
    const pkgUrl = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgUrl, 'utf8')) as { version?: string };
    cached = pkg.version ?? '0.0.0';
  } catch {
    cached = '0.0.0';
  }
  return cached;
}
