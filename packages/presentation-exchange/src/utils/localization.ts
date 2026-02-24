import type { LocalizableString, LocalizedValue } from '../types/localization.js';

/**
 * Resolve a LocalizableString to a plain string.
 * Tries to find a match for the preferred language, then falls back to the first entry.
 */
export function resolveLocalized(
  value: LocalizableString,
  preferredLanguage = 'en',
): string {
  if (typeof value === 'string') return value;
  if (value.length === 0) return '';

  const match = value.find(
    (v: LocalizedValue) => v['@language'] === preferredLanguage,
  );
  return match ? match['@value'] : value[0]['@value'];
}
