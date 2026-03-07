/**
 * ICAO 9303 SOD SchemaResolver
 *
 * Resolves fields from ICAO credentials (encoded DG blobs) and derives
 * presented credentials containing only the required DGs.
 *
 * Uses low-level functions from @1matrix/credential-sdk/icao-profile for
 * DG decoding, field mapping, and profile lookup.
 */

import {
  getProfile,
  getProfileByDocType,
  resolveField as resolveProfileField,
  getRequiredDGs,
} from '@1matrix/credential-sdk/icao-profile';
import type { ICAODocumentProfile } from '@1matrix/credential-sdk/icao-profile';
import type { SchemaResolver } from '../types/schema-resolver.js';
import type { MatchableCredential } from '../types/credential.js';
import type { PresentedCredential } from '../types/response.js';

/**
 * Detect the ICAO profile for a credential by:
 * 1. Looking at `credential.proof.dgProfile` (set during issuance)
 * 2. Falling back to matching credential type against registered profiles
 */
function detectProfile(credential: MatchableCredential): ICAODocumentProfile | undefined {
  // Try proof.dgProfile first
  const proof = credential.proof as Record<string, unknown> | undefined;
  if (proof && typeof proof.dgProfile === 'string') {
    const profile = getProfile(proof.dgProfile);
    if (profile) return profile;
  }

  // Fallback: match by credential type
  const credTypes = credential.type as readonly string[];
  for (const t of credTypes) {
    const profile = getProfileByDocType(t);
    if (profile) return profile;
  }

  return undefined;
}

/**
 * Extract raw DG data from a credential's credentialSubject.
 * DGs are stored as base64 strings keyed by DG name (e.g. 'dg1', 'dg2', 'dg13').
 */
function extractRawDGs(credential: MatchableCredential): Record<string, string> {
  const rawDGs: Record<string, string> = {};
  for (const [key, value] of Object.entries(credential.credentialSubject)) {
    if (key.startsWith('dg') && typeof value === 'string') {
      rawDGs[key] = value;
    }
  }
  return rawDGs;
}

/**
 * Creates an ICAO 9303 SOD schema resolver.
 *
 * @param defaultProfile - Optional default profile. If not provided,
 *   the profile is auto-detected from `credential.proof.dgProfile`
 *   or from the credential's type array.
 */
export function createICAOSchemaResolver(defaultProfile?: ICAODocumentProfile): SchemaResolver {
  return {
    type: 'ICAO9303SOD',

    resolveField(
      credential: MatchableCredential,
      field: string,
    ): { found: boolean; value: unknown } {
      const profile = defaultProfile ?? detectProfile(credential);
      if (!profile) {
        return { found: false, value: undefined };
      }

      const rawDGs = extractRawDGs(credential);
      const value = resolveProfileField(profile, field, rawDGs);

      if (value === undefined) {
        return { found: false, value: undefined };
      }
      return { found: true, value };
    },

    deriveCredential(
      credential: MatchableCredential,
      disclosedFields: string[],
    ): Promise<PresentedCredential> {
      const profile = defaultProfile ?? detectProfile(credential);
      if (!profile) {
        throw new Error(
          'Cannot derive ICAO credential: no matching profile found. ' +
          'Ensure credential.proof.dgProfile is set or credential type matches a registered profile.',
        );
      }

      const rawDGs = extractRawDGs(credential);
      const requiredDGNames = getRequiredDGs(profile, disclosedFields);

      // Build credentialSubject with only the required DGs
      const selectiveSubject: Record<string, unknown> = {};
      if (credential.credentialSubject.id !== undefined) {
        selectiveSubject.id = credential.credentialSubject.id;
      }
      for (const dgName of requiredDGNames) {
        if (rawDGs[dgName]) {
          selectiveSubject[dgName] = rawDGs[dgName];
        }
      }

      const types = [...(credential.type as readonly string[])];
      const issuer = typeof credential.issuer === 'string'
        ? credential.issuer
        : { ...credential.issuer };

      const presented: PresentedCredential = {
        type: types,
        issuer,
        credentialSubject: selectiveSubject,
      };

      if (credential['@context']) {
        presented['@context'] = [...(credential['@context'] as string[])];
      }
      if (credential.issuanceDate !== undefined) {
        presented.issuanceDate = credential.issuanceDate as string;
      }
      if (credential.id !== undefined) {
        presented.id = credential.id as string;
      }
      if (credential.proof !== undefined) {
        (presented as Record<string, unknown>).proof = credential.proof;
      }

      return Promise.resolve(presented);
    },
  };
}
