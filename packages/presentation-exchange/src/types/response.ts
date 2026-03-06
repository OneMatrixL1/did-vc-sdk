import type { ProofSystem } from './request.js';

// ---------------------------------------------------------------------------
// Supporting types (defined before they are referenced)
// ---------------------------------------------------------------------------

export interface SubmissionEntry {
  docRequestID: string;
  credentialIndex: number;
}

export interface HolderProof {
  type: string;
  cryptosuite?: string;
  verificationMethod: string;
  proofPurpose: 'authentication';
  challenge: string;
  domain: string;
  proofValue: string;
}

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
  '@context'?: (string | Record<string, unknown>)[];
  id?: string;
  type: string[] | readonly string[];
  issuer: string | { id: string; name?: string };
  issuanceDate?: string;
  credentialSubject: Record<string, unknown>;
  proof?: CredentialProof | CredentialProof[];
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Verifiable Presentation (VP response)
// ---------------------------------------------------------------------------

export interface VerifiablePresentation {
  '@context': (string | Record<string, unknown>)[];
  type: ['VerifiablePresentation'];
  holder: string;
  /** Echoed request ID — binds this VP to the specific VPRequest. */
  requestId?: string;
  /** Echoed request nonce — binds this VP to the specific VPRequest. */
  requestNonce?: string;
  /** Echoed verifier DID — binds this VP to the intended verifier. */
  verifier?: string;
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];
  proof: HolderProof;
}
