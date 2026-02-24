import type { ProofSystem } from './request.js';

// ---------------------------------------------------------------------------
// Verifiable Presentation (VP response)
// ---------------------------------------------------------------------------

export interface VerifiablePresentation {
  '@context': string[];
  type: ['VerifiablePresentation'];
  holder: string;
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];
  proof: HolderProof;
}

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

// ---------------------------------------------------------------------------
// Presented credential (may have derived proof)
// ---------------------------------------------------------------------------

export interface PresentedCredential {
  '@context'?: string[];
  id?: string;
  type: string[];
  issuer: string | { id: string; name?: string };
  issuanceDate?: string;
  credentialSubject: Record<string, unknown>;
  proof?: CredentialProof | CredentialProof[];
  [key: string]: unknown;
}

export type CredentialProof = DataIntegrityProof | ZKPProof;

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
