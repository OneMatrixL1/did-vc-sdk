import type { VPRequest } from '../types/request.js';
import type { VerificationResult } from './structural-verifier.js';

export interface VerifyRequestOptions {
  /** Override current time for testing (default: new Date()) */
  now?: Date;
}

/**
 * Structurally validate a VPRequest before the holder builds a VP response.
 *
 * Checks required fields, expiration, verifier credential structure,
 * and optional proof envelope.
 * Does NOT verify cryptographic proofs — use credential-sdk's
 * `verifyCredential()` for that.
 */
export function verifyVPRequest(
  request: VPRequest,
  options?: VerifyRequestOptions,
): VerificationResult {
  const errors: string[] = [];
  validateRequiredFields(request, errors);
  validateExpiration(request, errors, options?.now ?? new Date());
  validateVerifierCredentials(request, errors);
  validateRequestProof(request, errors);
  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validateRequiredFields(request: VPRequest, errors: string[]): void {
  if (!request.id) {
    errors.push('VPRequest is missing required field "id"');
  }
  if (!request.nonce) {
    errors.push('VPRequest is missing required field "nonce"');
  }
  if (!request.verifier) {
    errors.push('VPRequest is missing required field "verifier"');
  }
  if (!request.verifierUrl) {
    errors.push('VPRequest is missing required field "verifierUrl"');
  }
  if (!request.rules) {
    errors.push('VPRequest is missing required field "rules"');
  }
}

function validateExpiration(
  request: VPRequest,
  errors: string[],
  now: Date,
): void {
  if (!request.expiresAt) return;
  const expires = new Date(request.expiresAt);
  if (expires <= now) {
    errors.push(
      `VPRequest has expired (expiresAt: ${request.expiresAt})`,
    );
  }
}

function validateVerifierCredentials(
  request: VPRequest,
  errors: string[],
): void {
  const creds = request.verifierCredentials;
  if (!creds) return;

  for (let i = 0; i < creds.length; i++) {
    const cred = creds[i]!;

    if (!Array.isArray(cred.type) || cred.type.length === 0) {
      errors.push(
        `verifierCredentials[${i}] is missing or has empty "type"`,
      );
    }

    if (!cred.issuer) {
      errors.push(`verifierCredentials[${i}] is missing "issuer"`);
    }

    if (!cred.credentialSubject) {
      errors.push(
        `verifierCredentials[${i}] is missing "credentialSubject"`,
      );
    }
  }
}

function validateRequestProof(request: VPRequest, errors: string[]): void {
  const { proof } = request;
  if (!proof) return;

  if (!proof.verificationMethod) {
    errors.push('VPRequest proof is missing "verificationMethod"');
  }

  if (proof.proofPurpose !== 'assertionMethod' && proof.proofPurpose !== 'authentication') {
    errors.push(
      `VPRequest proof purpose must be "assertionMethod" or "authentication", got "${proof.proofPurpose}"`,
    );
  }

  if (proof.challenge !== request.nonce) {
    errors.push(
      `VPRequest proof challenge mismatch: expected "${request.nonce}", got "${proof.challenge}"`,
    );
  }

  if (request.verifierUrl) {
    let expectedDomain: string;
    try {
      expectedDomain = new URL(request.verifierUrl).hostname;
    } catch {
      expectedDomain = request.verifierUrl;
    }

    if (proof.domain !== expectedDomain && proof.domain !== request.verifierUrl) {
      errors.push(
        `VPRequest proof domain mismatch: expected "${expectedDomain}" or "${request.verifierUrl}", got "${proof.domain}"`,
      );
    }
  }
}
