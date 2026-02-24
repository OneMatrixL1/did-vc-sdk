/**
 * Minimal JSONPath resolver supporting `$.foo.bar.baz` dot-notation paths.
 * Does not support bracket notation, wildcards, or filters.
 */
export function resolveJsonPath(obj: unknown, path: string): { found: boolean; value: unknown } {
  if (!path.startsWith('$.')) {
    return { found: false, value: undefined };
  }

  const segments = path.slice(2).split('.');
  let current: unknown = obj;

  for (const seg of segments) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return { found: false, value: undefined };
    }
    if (!(seg in (current as Record<string, unknown>))) {
      return { found: false, value: undefined };
    }
    current = (current as Record<string, unknown>)[seg];
  }

  return { found: true, value: current };
}
