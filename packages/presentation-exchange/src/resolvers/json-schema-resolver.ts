import type { SchemaResolver } from '../types/schema-resolver.js';
import type { MatchableCredential } from '../types/credential.js';
import type { PresentedCredential } from '../types/response.js';
import { resolveJsonPath } from '../utils/jsonpath.js';

/**
 * Build a selectively-disclosed credential containing only the requested fields.
 * Moved from resolver.ts to be used as the JsonSchema resolver's deriveCredential.
 */
function credentialToSelective(
  cred: MatchableCredential,
  disclosedFields: string[],
): PresentedCredential {
  const selectiveSubject: Record<string, unknown> = {};
  if (cred.credentialSubject.id !== undefined) {
    selectiveSubject.id = cred.credentialSubject.id;
  }

  for (const fieldPath of disclosedFields) {
    const { found, value } = resolveJsonPath(cred, fieldPath);
    if (found && fieldPath.startsWith('$.credentialSubject.')) {
      const parts = fieldPath.split('.');
      const lastSeg = parts[parts.length - 1]!;
      selectiveSubject[lastSeg] = value;
    }
  }

  const types = [...(cred.type as readonly string[])];
  const issuer = typeof cred.issuer === 'string'
    ? cred.issuer
    : { ...cred.issuer };

  const presented: PresentedCredential = {
    type: types,
    issuer,
    credentialSubject: selectiveSubject,
  };

  if (cred['@context']) {
    presented['@context'] = [...(cred['@context'] as string[])];
  }
  if (cred.issuanceDate !== undefined) {
    presented.issuanceDate = cred.issuanceDate as string;
  }
  if (cred.id !== undefined) {
    presented.id = cred.id as string;
  }
  if (cred.proof !== undefined) {
    (presented as Record<string, unknown>).proof = cred.proof;
  }

  return presented;
}

/**
 * JsonSchema resolver — resolves fields via JSONPath and derives credentials
 * using standard selective disclosure (pick fields from credentialSubject).
 */
export const jsonSchemaResolver: SchemaResolver = {
  type: 'JsonSchema',

  resolveField(
    credential: MatchableCredential,
    field: string,
  ): { found: boolean; value: unknown } {
    return resolveJsonPath(credential, field);
  },

  deriveCredential(
    credential: MatchableCredential,
    disclosedFields: string[],
  ): Promise<PresentedCredential> {
    return Promise.resolve(credentialToSelective(credential, disclosedFields));
  },
};
