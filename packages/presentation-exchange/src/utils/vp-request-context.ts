/**
 * Inline JSON-LD context that maps VPRequest-specific fields to IRIs.
 *
 * Used by both `buildSigned` (signing) and `verifyVPRequestProof` (verification)
 * so that JSON-LD canonicalization produces identical hashes on both sides.
 */
export const vpRequestContext: Record<string, unknown> = {
  verifier: { '@id': 'https://w3id.org/vprequest#verifier', '@type': '@id' },
  version: 'https://schema.org/version',
  name: 'https://schema.org/name',
  nonce: 'https://w3id.org/security#nonce',
  verifierName: 'https://schema.org/alternateName',
  verifierUrl: 'https://schema.org/url',
  verifierCredentials: 'https://w3id.org/security#verifiableCredential',
  verifierDisclosure: { '@id': 'https://w3id.org/vprequest#verifierDisclosure', '@type': '@json' },
  createdAt: 'https://schema.org/dateCreated',
  expiresAt: 'https://schema.org/expires',
  rules: { '@id': 'https://w3id.org/vprequest#rules', '@type': '@json' },
};
