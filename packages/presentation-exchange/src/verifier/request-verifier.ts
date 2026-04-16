import type { VPRequest } from '../types/request.js';
import type { PresentedCredential, ZKPProof, CredentialProof } from '../types/credential.js';
import type { ZKPProvider } from '../proof-system/types.js';
import type { VerificationResult } from './structural-verifier.js';
import { verifyPresentation } from '@1matrix/credential-sdk/vc';
// @ts-ignore -- JS module, no .d.ts
import { createOptimisticResolver } from '@1matrix/credential-sdk/ethr-did';
import { vpRequestContext } from '../utils/vp-request-context.js';

export interface VerifyRequestOptions {
  /** DID resolver for cryptographic proof verification. */
  resolver?: {
    supports(id: string): boolean;
    resolve(id: string, opts?: unknown): Promise<unknown>;
  };
  /** ZKP provider for verifying verifierCredentials' ZKP proofs. */
  zkpProvider?: ZKPProvider;
}

export interface VerifierCredentialResult {
  verified: boolean;
  errors: string[];
}

export interface VerifyVPRequestResult {
  /** `true` if both structural and cryptographic verification passed. */
  verified: boolean;
  /** Result of structural validation. */
  structural: VerificationResult;
  /** Result of cryptographic proof verification (null if no proof present). */
  crypto: { verified: boolean; error?: Error } | null;
  /** Result of verifierCredentials ZKP verification (null if none present). */
  verifierCredentials: VerifierCredentialResult | null;
  /** All error messages. */
  errors: string[];
}

/**
 * Structurally validate a VPRequest before the holder builds a VP response.
 *
 * Checks required fields, expiration, verifier credential structure,
 * and optional proof envelope.
 * Does NOT verify cryptographic proofs — use {@link verifyVPRequestFull} for that.
 */
export function verifyVPRequest(
  request: VPRequest,
  options?: VerifyRequestOptions,
): VerificationResult {
  const errors: string[] = [];
  validateRequiredFields(request, errors);
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

  if (proof.proofPurpose !== 'assertionMethod') {
    errors.push(
      `VPRequest proof purpose must be "assertionMethod", got "${proof.proofPurpose}"`,
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

// ---------------------------------------------------------------------------
// Full verification (structural + crypto)
// ---------------------------------------------------------------------------

/**
 * Full verification of a signed VPRequest: structural + cryptographic.
 *
 * 1. Structural validation (required fields, expiration, proof envelope).
 * 2. Cryptographic proof verification — reconstructs the VP-like envelope
 *    that `buildSigned` created and verifies the signature via credential-sdk.
 *
 * If the request has no proof, crypto is skipped and only structural is checked.
 *
 * @param request  The VPRequest to verify.
 * @param options  Optional resolver and time override.
 */
export async function verifyVPRequestFull(
  request: VPRequest,
  options?: VerifyRequestOptions,
): Promise<VerifyVPRequestResult> {
  const errors: string[] = [];

  // --- 1. Structural ---
  const structural = verifyVPRequest(request, options);
  if (!structural.valid) {
    return {
      verified: false,
      structural,
      crypto: null,
      verifierCredentials: null,
      errors: structural.errors,
    };
  }

  // --- 2. Crypto — proof is required ---
  if (!request.proof) {
    return {
      verified: false,
      structural,
      crypto: null,
      verifierCredentials: null,
      errors: ['VPRequest has no proof — unsigned requests are not accepted'],
    };
  }

  const { proof, ...unsigned } = request;
  const domain = proof.domain;
  const challenge = proof.challenge;

  // Reconstruct the same VP-like envelope that buildSigned created
  const vpToVerify = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      vpRequestContext,
    ],
    ...unsigned,
    type: ['VerifiablePresentation'],
    holder: unsigned.verifier,
    proof,
  };

  const resolver = options?.resolver ?? createOptimisticResolver();

  let crypto: VerifyVPRequestResult['crypto'];
  try {
    // @ts-ignore -- no .d.ts for jsonld-signatures
    const jsigs = (await import('jsonld-signatures')).default;
    const { AssertionProofPurpose } = jsigs.purposes;
    const purpose = new AssertionProofPurpose({ domain, challenge });

    const result = (await verifyPresentation(vpToVerify, {
      challenge,
      domain,
      presentationPurpose: purpose,
      resolver,
    })) as Record<string, unknown>;

    const verified = result.verified as boolean;
    crypto = { verified };

    if (!verified) {
      const msgs = extractErrorMessages(result.error ?? result);
      errors.push(...msgs);
      if (msgs.length > 0) {
        crypto.error = new Error(msgs.join('; '));
      }
    }
  } catch (err) {
    const msgs = extractErrorMessages(err);
    crypto = { verified: false, error: new Error(msgs.join('; ') || String(err)) };
    errors.push(...msgs.length > 0 ? msgs : [String(err)]);
  }

  // --- 3. Verify verifierCredentials ZKP proofs ---
  const vcResult = await verifyVerifierCredentials(request, options?.zkpProvider);

  return {
    verified: structural.valid && (crypto?.verified ?? false),
    structural,
    crypto,
    verifierCredentials: vcResult,
    errors: [...errors, ...vcResult.errors],
  };
}

// ---------------------------------------------------------------------------
// Verifier credential ZKP verification
// ---------------------------------------------------------------------------

function extractZKPProofs(cred: PresentedCredential): ZKPProof[] {
  if (!cred.proof) return [];
  const proofs: CredentialProof[] = Array.isArray(cred.proof) ? cred.proof : [cred.proof];
  return proofs.filter((p): p is ZKPProof => p.type === 'ZKPProof');
}

async function verifyVerifierCredentials(
  request: VPRequest,
  zkpProvider?: ZKPProvider,
): Promise<VerifierCredentialResult> {
  const creds = request.verifierCredentials;
  if (!creds || creds.length === 0) {
    return { verified: false, errors: [] };
  }

  if (!zkpProvider?.verify) {
    return { verified: false, errors: ['verifierCredentials have ZKP proofs but no zkpProvider supplied'] };
  }

  const errors: string[] = [];
  let allValid = true;

  for (let i = 0; i < creds.length; i++) {
    const zkpProofs = extractZKPProofs(creds[i]!);
    if (zkpProofs.length === 0) {
      errors.push(`verifierCredentials[${i}] has no ZKP proofs`);
      allValid = false;
      continue;
    }

    for (const p of zkpProofs) {
      const valid = await zkpProvider.verify({
        circuitId: p.circuitId,
        proofValue: p.proofValue,
        publicInputs: p.publicInputs,
        publicOutputs: p.publicOutputs,
      });
      if (!valid) {
        errors.push(`verifierCredentials[${i}]: ZKP proof "${p.conditionID}" (${p.circuitId}) invalid`);
        allValid = false;
      }
    }
  }

  return { verified: allValid, errors };
}

// ---------------------------------------------------------------------------
// Error extraction — unwrap nested VerificationError.errors
// ---------------------------------------------------------------------------

function extractErrorMessages(err: unknown): string[] {
  if (!err) return [];
  const msgs: string[] = [];
  if (err instanceof Error) {
    // VerificationError from jsonld-signatures has .errors array
    const nested = (err as { errors?: unknown[] }).errors;
    if (Array.isArray(nested)) {
      for (const e of nested) msgs.push(...extractErrorMessages(e));
    } else if (err.message && err.message !== 'Verification error(s).') {
      msgs.push(err.message);
    }
  }
  // verifyPresentation result may have presentationResult.results[].error
  if (typeof err === 'object' && err !== null) {
    const obj = err as Record<string, unknown>;
    if (obj.presentationResult && typeof obj.presentationResult === 'object') {
      const pr = obj.presentationResult as Record<string, unknown>;
      if (pr.error) msgs.push(...extractErrorMessages(pr.error));
      if (Array.isArray(pr.results)) {
        for (const r of pr.results) {
          if (r && typeof r === 'object' && (r as Record<string, unknown>).error) {
            msgs.push(...extractErrorMessages((r as Record<string, unknown>).error));
          }
        }
      }
    }
  }
  return msgs.length > 0 ? msgs : (err instanceof Error && err.message ? [err.message] : []);
}

