// ---------------------------------------------------------------------------
// Proof system & credential proof types
// ---------------------------------------------------------------------------

import type { MerkleDisclosureProof } from './merkle.js';

export type { MerkleDisclosureProof } from './merkle.js';

export type ProofSystem = 'groth16' | 'plonk' | 'fflonk' | 'halo2' | 'ultra_honk' | 'stark' | (string & {});

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
  dependsOn?: Record<string, string>;
}

export type CredentialProof = DataIntegrityProof | ZKPProof | MerkleDisclosureProof;

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

export interface MatchableCredential {
  type: readonly string[] | string[];
  issuer: string | { id: string; name?: string };
  credentialSubject: Record<string, unknown>;
  proof?: CredentialProof | CredentialProof[] | undefined;
  [key: string]: unknown;
}

export function getCredentialIssuerId(cred: MatchableCredential): string {
  return typeof cred.issuer === 'string' ? cred.issuer : cred.issuer.id;
}
