import type { MatchableCredential } from './credential.js';
import type { PresentedCredential } from './response.js';

/**
 * Schema-specific resolver for field resolution and credential derivation.
 *
 * Each DocumentRequest declares a `schemaType`, and the corresponding
 * SchemaResolver handles field resolution (for matching) and credential
 * derivation (for selective disclosure).
 */
export interface SchemaResolver {
  readonly type: string;

  /**
   * Resolve a field value from a credential.
   * The meaning of `field` is schema-dependent:
   *  - JsonSchema: JSONPath (e.g. `$.credentialSubject.fullName`)
   *  - ICAO9303SOD: profile field ID (e.g. `fullName`, `permanentAddress`)
   */
  resolveField(
    credential: MatchableCredential,
    field: string,
  ): { found: boolean; value: unknown };

  /**
   * Derive a presented credential containing only the disclosed fields.
   * Used for selective disclosure mode.
   */
  deriveCredential(
    credential: MatchableCredential,
    disclosedFields: string[],
  ): Promise<PresentedCredential>;
}

/** Map of schemaType string to its SchemaResolver. Passed as a required parameter. */
export type SchemaResolverMap = Record<string, SchemaResolver>;
