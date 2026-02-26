import type { ICAODocumentProfile } from './types.js';

/**
 * Compute the set of DG source names required to satisfy the requested fields.
 *
 * @param profile   - ICAO Document Profile
 * @param fieldIds  - Logical field IDs requested (e.g. ['fullName', 'gender'])
 * @returns Deduplicated array of source/DG names (e.g. ['dg13'])
 */
export function getRequiredDGs(
  profile: ICAODocumentProfile,
  fieldIds: string[],
): string[] {
  const dgSet = new Set<string>();
  for (const fieldId of fieldIds) {
    const binding = profile.fields[fieldId];
    if (binding) {
      dgSet.add(binding.source);
    }
  }
  return Array.from(dgSet);
}
