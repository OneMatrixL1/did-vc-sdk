import type { ICAODocumentProfile } from './types.js';
import { VN_CCCD_2024 } from './profiles/vn-cccd-2024.js';

const profileMap: Record<string, ICAODocumentProfile> = {
  'VN-CCCD-2024': VN_CCCD_2024,
};

/**
 * Retrieve an ICAO Document Profile by its profile ID.
 * Returns undefined if the profile is not registered.
 */
export function getProfile(profileId: string): ICAODocumentProfile | undefined {
  return profileMap[profileId];
}

/**
 * Retrieve an ICAO Document Profile by a credential docType string.
 * Searches all registered profiles for one whose `docType` array contains the given type.
 * Returns undefined if no profile matches.
 */
export function getProfileByDocType(docType: string): ICAODocumentProfile | undefined {
  return Object.values(profileMap).find((p) => p.docType.includes(docType));
}
