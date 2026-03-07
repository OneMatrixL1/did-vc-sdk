import type { VPRequest } from '../types/request.js';
import type { VerifiablePresentation } from '../types/response.js';
import { verifyPresentationStructure, type VerificationResult } from './structural-verifier.js';
import { verifyPresentation } from '@1matrix/credential-sdk/vc';

// ---------------------------------------------------------------------------
// Options & result types
// ---------------------------------------------------------------------------

/**
 * Options for {@link verifyVPResponse}.
 *
 * @example
 * // With a DID resolver (needed after key rotation or for non-default keys)
 * await verifyVPResponse(request, vp, { resolver: ethrRegistryResolver });
 *
 * // Without resolver (uses optimistic resolution — works when DID address = controller)
 * await verifyVPResponse(request, vp);
 */
export interface VerifyVPResponseOptions {
  /** DID resolver used to fetch the holder's DID document for signature verification. */
  resolver?: {
    supports(id: string): boolean;
    resolve(id: string, opts?: unknown): Promise<unknown>;
  };
}

/**
 * Combined result of structural + cryptographic VP verification.
 *
 * - `verified` is `true` only when both checks pass.
 * - `errors` aggregates all error messages from both stages.
 */
export interface VerifyVPResponseResult {
  /** `true` if both structural and cryptographic verification passed. */
  verified: boolean;
  /** Result of structural validation (nonce, domain, submissions, credential types). */
  structural: VerificationResult;
  /** Result of cryptographic proof verification via credential-sdk. */
  crypto: {
    verified: boolean;
    presentationResult?: unknown;
    credentialResults?: unknown[];
    error?: Error;
  };
  /** All error messages from both structural and crypto verification. */
  errors: string[];
}

// ---------------------------------------------------------------------------
// verifyVPResponse
// ---------------------------------------------------------------------------

/**
 * Full verification of a VP response against the original VPRequest.
 *
 * 1. Structural validation (nonce, domain, submissions, credential types).
 * 2. Cryptographic verification via credential-sdk's `verifyPresentation`.
 *
 * @param request       The original VPRequest that was sent to the holder.
 * @param presentation  The holder's VP response.
 * @param options       Optional resolver for DID resolution.
 */
export async function verifyVPResponse(
  request: VPRequest,
  presentation: VerifiablePresentation,
  options?: VerifyVPResponseOptions,
): Promise<VerifyVPResponseResult> {
  const errors: string[] = [];

  // --- 1. Structural ---
  const structural = verifyPresentationStructure(request, presentation);
  if (!structural.valid) {
    return {
      verified: false,
      structural,
      crypto: { verified: false },
      errors: structural.errors,
    };
  }

  // --- 2. Crypto ---
  // Use the VP's own @context — it's what was signed.
  // Do NOT hardcode vpResponseContext; the signed doc may include
  // additional suite contexts added by credential-sdk.
  const { proof, ...vpWithoutProof } = presentation;
  const vpDoc = { ...vpWithoutProof, proof };

  let crypto: VerifyVPResponseResult['crypto'];
  try {
    const result = (await verifyPresentation(vpDoc, {
      challenge: request.nonce,
      domain: presentation.proof.domain,
      resolver: options?.resolver ?? null,
      unsignedPresentation: false,
      compactProof: true,
    })) as Record<string, unknown>;

    const verified = result.verified as boolean;
    crypto = {
      verified,
      presentationResult: result.presentationResult,
      credentialResults: result.credentialResults as unknown[] | undefined,
    };

    if (!verified && result.error) {
      crypto.error = result.error instanceof Error
        ? result.error
        : new Error(String(result.error));
      errors.push(crypto.error.message);
    }
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    crypto = { verified: false, error };
    errors.push(error.message);
  }

  return {
    verified: structural.valid && crypto.verified,
    structural,
    crypto,
    errors,
  };
}
