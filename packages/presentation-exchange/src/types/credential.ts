/**
 * Structural supertype for credentials that can be matched against a VPRequest.
 * Compatible with the app's existing VerifiableCredential from vc.types.ts
 * without requiring an import or conversion.
 */
export interface MatchableCredential {
  type: readonly string[] | string[];
  issuer: string | { id: string; name?: string };
  credentialSubject: Record<string, unknown> | readonly Record<string, unknown>[];
  proof?: unknown;
  [key: string]: unknown;
}

/** Extract issuer ID string from a MatchableCredential */
export function getCredentialIssuerId(cred: MatchableCredential): string {
  return typeof cred.issuer === 'string' ? cred.issuer : cred.issuer.id;
}
