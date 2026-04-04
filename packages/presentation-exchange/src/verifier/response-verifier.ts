import type { VPRequest } from '../types/request.js';
import type { VerifiablePresentation } from '../types/response.js';
import type { ZKPProvider, Poseidon2Hasher } from '../types/zkp-provider.js';
import { verifyPresentationStructure, type VerificationResult } from './structural-verifier.js';
import { verifyZKPProofs, type ZKPVerificationResult } from './zkp-verifier.js';
import { verifyPresentation } from '@1matrix/credential-sdk/vc';
// @ts-expect-error -- JS module, no .d.ts
import { createOptimisticResolver } from '@1matrix/credential-sdk/ethr-did';

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
  /** Poseidon2 hasher for Merkle disclosure verification. */
  poseidon2?: Poseidon2Hasher;
  /** ZKP provider for proof verification (predicates, trust chain). */
  zkpProvider?: ZKPProvider;
}

/**
 * Combined result of structural + cryptographic VP verification.
 *
 * - `verified` is `true` only when both checks pass.
 * - `errors` aggregates all error messages from both stages.
 */
export interface VerifyVPResponseResult {
  /** `true` if structural, cryptographic, and ZKP verification all passed. */
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
  /** Result of ZKP and Merkle disclosure verification (present when proofs exist). */
  zkp?: ZKPVerificationResult;
  /** All error messages from structural, crypto, and ZKP verification. */
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
  const vpDoc = { ...presentation };

  const resolver = options?.resolver ?? createOptimisticResolver();

  let crypto: VerifyVPResponseResult['crypto'];
  try {
    const result = (await verifyPresentation(vpDoc, {
      challenge: request.nonce,
      domain: presentation.proof.domain,
      resolver,
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

  let zkp: ZKPVerificationResult | undefined;

  const hasZKPProofs = presentation.verifiableCredential.some((cred) => {
    const proofs = cred.proof
      ? (Array.isArray(cred.proof) ? cred.proof : [cred.proof])
      : [];

    return proofs.some(
      (p) => p.type === 'MerkleDisclosureProof' || p.type === 'ZKPProof',
    );
  });

  if (hasZKPProofs) {
    if (!options?.poseidon2) {
      errors.push(
        'Presentation contains ZKP/Merkle proofs but no Poseidon2 hasher was provided for verification',
      );

      return {
        verified: false,
        structural,
        crypto,
        errors,
      };
    }

    zkp = await verifyZKPProofs(
      request,
      presentation,
      options.poseidon2,
      options.zkpProvider,
    );

    if (!zkp.verified) {
      for (const r of zkp.proofResults) {
        if (!r.verified && r.error) {
          errors.push(`ZKP[${r.conditionID}]: ${r.error}`);
        }
      }
    }
  }

  const zkpOk = zkp ? zkp.verified : true;

  return {
    verified: structural.valid && crypto.verified && zkpOk,
    structural,
    crypto,
    zkp,
    errors,
  };
}

