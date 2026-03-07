import type { KeyDoc } from '../types/request.js';
import type { HolderProof } from '../types/response.js';
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
 * Builds a JSON-LD–compatible VP document from the unsigned presentation,
 * signs it with `AuthenticationProofPurpose` (the default), and returns
 * the `proof` object.
 *
 * @param unsigned  The unsigned presentation payload from `resolvePresentation`.
 * @param keyDoc    Key document (id, controller, type, keypair).
 * @param nonce     Challenge nonce (from VPRequest.nonce).
 * @param verifierUrl  Verifier URL — hostname is used as the proof domain.
 * @param resolver  Optional DID resolver forwarded to credential-sdk.
 * @returns The proof object to attach to the VP.
 */
export async function signVPResponse(
  unsigned: UnsignedPresentation,
  keyDoc: KeyDoc,
  nonce: string,
  verifierUrl: string,
  resolver?: object,
): Promise<HolderProof> {
  const domain = new URL(verifierUrl).hostname;

  // Destructure to separate @context from the rest, then override it
  const { '@context': _ctx, ...rest } = unsigned;

  const vpDoc = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      vpResponseContext,
    ],
    ...rest,
    type: ['VerifiablePresentation'],
    holder: unsigned.holder,
  };

  const signed = await signPresentation(
    vpDoc,
    keyDoc,
    nonce,   // challenge
    domain,  // domain
    resolver ?? null,
  );

  return (signed as Record<string, unknown>).proof as HolderProof;
}

export { vpResponseContext };
