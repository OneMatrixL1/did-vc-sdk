import type { KeyDoc } from '../types/request.js';
import type { VerifiablePresentation } from '../types/response.js';
import type { UnsignedPresentation } from '../resolver/resolver.js';
import { signPresentation } from '@1matrix/credential-sdk/vc';

/**
 * Inline context that maps VP-response–specific fields to IRIs so that
 * JSON-LD canonicalization includes them in the signed hash.
 *
 * Same pattern as `VPRequestBuilder.buildSigned()` uses for VPRequests.
 */
const vpResponseContext: Record<string, unknown> = {
  verifier: { '@id': 'https://w3id.org/vprequest#verifier', '@type': '@id' },
  requestId: 'https://w3id.org/vprequest#requestId',
  requestNonce: 'https://w3id.org/security#nonce',
  presentationSubmission: {
    '@id': 'https://w3id.org/vprequest#presentationSubmission',
    '@type': '@json',
  },
};

/**
 * Sign a VP response using credential-sdk's `signPresentation`.
 *
 * Returns the complete signed VP document — never partial data.
 * `signPresentation` may mutate the document (e.g. attach didOwnerProof),
 * so the full signed object must be returned to preserve the exact
 * data that was covered by the signature.
 *
 * @param unsigned    The unsigned presentation payload from `resolvePresentation`.
 * @param keyDoc      Key document (id, controller, type, keypair).
 * @param nonce       Challenge nonce (from VPRequest.nonce).
 * @param verifierUrl Verifier URL — hostname is used as the proof domain.
 * @param resolver    Optional DID resolver forwarded to credential-sdk.
 * @returns The complete signed VerifiablePresentation.
 */
export async function signVPResponse(
  unsigned: UnsignedPresentation,
  keyDoc: KeyDoc,
  nonce: string,
  verifierUrl: string,
  resolver?: object,
): Promise<VerifiablePresentation> {
  const domain = new URL(verifierUrl).hostname;

  const vpDoc = {
    ...unsigned,
    type: ['VerifiablePresentation'] as ['VerifiablePresentation'],
    holder: unsigned.holder,
  };

  const signed = await signPresentation(
    vpDoc,
    keyDoc,
    nonce,   // challenge
    domain,  // domain
    resolver ?? null,
  );

  return signed as unknown as VerifiablePresentation;
}

export { vpResponseContext };
