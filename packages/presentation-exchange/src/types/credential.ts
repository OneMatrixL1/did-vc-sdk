// ---------------------------------------------------------------------------
// Proof system & credential proof types (shared leaf — no type-file imports)
// ---------------------------------------------------------------------------

export type ProofSystem = 'groth16' | 'plonk' | 'fflonk' | 'halo2' | 'stark' | (string & {});

export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: string;
  proofValue?: string;
  sodSignature?: string;
  dgHashes?: Record<string, string>;
  [key: string]: unknown;
}

export interface ZKPProof {
  type: 'ZKPProof';
  conditionID: string;
  circuitId: string;
  proofSystem: ProofSystem;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
  proofValue: string;
}

export type CredentialProof = DataIntegrityProof | ZKPProof;

// ---------------------------------------------------------------------------
// Presented credential (may have derived proof)
// ---------------------------------------------------------------------------

export interface PresentedCredential {
  '@context'?: string[];
  id?: string;
  type: string[] | readonly string[];
  issuer: string | { id: string; name?: string };
  issuanceDate?: string;
  credentialSubject: Record<string, unknown>;
  proof?: CredentialProof | CredentialProof[];
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Matchable credential (structural supertype for matching against a VPRequest)
// ---------------------------------------------------------------------------

/**
 * Structural supertype for credentials that can be matched against a VPRequest.
 * Compatible with the app's existing VerifiableCredential from vc.types.ts
 * without requiring an import or conversion.
 */
export interface MatchableCredential {
  type: readonly string[] | string[];
  issuer: string | { id: string; name?: string };
  credentialSubject: Record<string, unknown>;
  proof?: CredentialProof | CredentialProof[] | undefined;
  [key: string]: unknown;
}

/** Extract issuer ID string from a MatchableCredential */
export function getCredentialIssuerId(cred: MatchableCredential): string {
  return typeof cred.issuer === 'string' ? cred.issuer : cred.issuer.id;
}
