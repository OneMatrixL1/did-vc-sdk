// Re-export credential proof types for backward compatibility
export type {
  ProofSystem,
  DataIntegrityProof,
  ZKPProof,
  CredentialProof,
  PresentedCredential,
} from './credential.js';

import type { PresentedCredential } from './credential.js';
import type { VerifierDisclosure } from './request.js';

// ---------------------------------------------------------------------------
// Supporting types (defined before they are referenced)
// ---------------------------------------------------------------------------

export interface SubmissionEntry {
  docRequestID: string;
  credentialIndex: number;
}

/**
 * Proof attached to a VerifiablePresentation by the holder.
 *
 * Supports multiple signature suites:
 * - `jws` — EcdsaSecp256k1 suites (Signature2019, Signature2020)
 * - `proofValue` — DataIntegrity / BBS+ suites
 */
export interface HolderProof {
  type: string;
  cryptosuite?: string;
  verificationMethod: string;
  proofPurpose: 'authentication';
  challenge: string;
  domain: string;
  /** JWS value — present for EcdsaSecp256k1 signature suites. */
  jws?: string;
  /** Proof value — present for DataIntegrity / BBS+ suites. */
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
  /** @deprecated Use `verifierDisclosure` instead. */
  verifierCredentials?: PresentedCredential[];
  /** Verifier's self-disclosure — passed through from VPRequest. */
  verifierDisclosure?: VerifierDisclosure;
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];
  proof: HolderProof;
}
