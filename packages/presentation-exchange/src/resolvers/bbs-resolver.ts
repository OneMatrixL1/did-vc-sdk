/**
 * BBS+ selective disclosure resolver wrapper.
 *
 * Decorates any SchemaResolver with BBS+ derivation using credential-sdk's
 * Presentation class. Instead of stripping fields (which invalidates the
 * original proof), this produces a derived BBS proof that is independently
 * verifiable over only the revealed fields.
 */

import { Presentation } from '@1matrix/credential-sdk/vc';
import type { SchemaResolver, DeriveOptions } from '../types/schema-resolver.js';
import type { MatchableCredential } from '../types/credential.js';
import type { PresentedCredential } from '../types/response.js';

const BBS_PROOF_TYPES = new Set([
  'Bls12381BBSSignatureDock2023',
  'Bls12381BBS+SignatureDock2022',
]);

/** Check whether a credential uses a BBS signature type. */
export function isBBSProof(cred: MatchableCredential): boolean {
  const proof = cred.proof as Record<string, unknown> | undefined;
  return !!proof && BBS_PROOF_TYPES.has(proof.type as string);
}

/** Strip `$.` prefix: `$.credentialSubject.fullName` → `credentialSubject.fullName` */
function toBBSPaths(fields: string[]): string[] {
  return fields.map((f) => (f.startsWith('$.') ? f.slice(2) : f));
}

/**
 * Wrap any SchemaResolver with BBS+ derivation.
 *
 * `resolveField` delegates to the inner resolver unchanged.
 * `deriveCredential` uses the Presentation class to produce a derived
 * credential with a `Bls12381BBSSignatureProofDock2023` proof.
 */
export function createBBSResolver(inner: SchemaResolver): SchemaResolver {
  return {
    type: inner.type,

    resolveField(credential: MatchableCredential, field: string) {
      return inner.resolveField(credential, field);
    },

    async deriveCredential(
      credential: MatchableCredential,
      disclosedFields: string[],
      options?: DeriveOptions,
    ): Promise<PresentedCredential> {
      const bbsPaths = toBBSPaths(disclosedFields);

      const presentation = new Presentation();
      await presentation.addCredentialToPresent(credential);
      presentation.addAttributeToReveal(0, bbsPaths);
      const derived = presentation.deriveCredentials({ nonce: options?.nonce });

      return derived[0] as PresentedCredential;
    },
  };
}
