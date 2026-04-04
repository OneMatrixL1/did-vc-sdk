export type {
  ProofSystem,
  DataIntegrityProof,
  ZKPProof,
  CredentialProof,
  PresentedCredential,
  MerkleDisclosureProof,
} from './credential.js';

import type { PresentedCredential } from './credential.js';

// ---------------------------------------------------------------------------
// Supporting types
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
  jws?: string;
  proofValue?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Verifiable Presentation (VP response)
// ---------------------------------------------------------------------------

export interface VerifiablePresentation {
  '@context': (string | Record<string, unknown>)[];
  type: ['VerifiablePresentation'];
  holder: string;
  verifier: string;
  requestId: string;
  requestNonce: string;
  verifierCredentials?: PresentedCredential[];
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];
  proof: HolderProof;
}
