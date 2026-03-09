import type { VPRequest } from '../types/request.js';
import type { VerificationResult } from './structural-verifier.js';
import { verifyPresentation } from '@1matrix/credential-sdk/vc';
// @ts-ignore -- JS module, no .d.ts
import { isEthrDID, generateDefaultDocument } from '@1matrix/credential-sdk/ethr-did';
import { vpRequestContext } from '../utils/vp-request-context.js';

export interface VerifyRequestOptions {
  /** Override current time for testing (default: new Date()) */
  now?: Date;
  /** DID resolver for cryptographic proof verification. */
  resolver?: {
    supports(id: string): boolean;
    resolve(id: string, opts?: unknown): Promise<unknown>;
  };
}

export interface VerifyVPRequestResult {
  /** `true` if both structural and cryptographic verification passed. */
  verified: boolean;
  /** Result of structural validation. */
  structural: VerificationResult;
  /** Result of cryptographic proof verification (null if no proof present). */
  crypto: { verified: boolean; error?: Error } | null;
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
      errors: structural.errors,
    };
  }

  // --- 2. Crypto (only if proof is present) ---
  if (!request.proof) {
    return { verified: true, structural, crypto: null, errors: [] };
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

  const resolver = options?.resolver ?? defaultEthrResolver();

  let crypto: VerifyVPRequestResult['crypto'];
  try {
    // Use dynamic import to avoid pulling jsonld-signatures into the main bundle
    // for consumers that only need structural validation.
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

  return {
    verified: structural.valid && (crypto?.verified ?? false),
    structural,
    crypto,
    errors,
  };
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

// ---------------------------------------------------------------------------
// Default resolver for did:ethr — uses generateDefaultDocument (zero RPC)
// ---------------------------------------------------------------------------

function defaultEthrResolver() {
  return {
    supports: (id: string) => typeof id === 'string' && id.startsWith('did:ethr:'),
    resolve: (id: string) => {
      const did = id.split('#')[0]!;
      if (!isEthrDID(did)) {
        return Promise.reject(new Error(`Unsupported DID: ${did}`));
      }
      const doc = generateDefaultDocument(did) as {
        verificationMethod: Array<{ id: string; [k: string]: unknown }>;
        [k: string]: unknown;
      };
      if (!id.includes('#')) {
        return Promise.resolve(doc);
      }
      const vm = doc.verificationMethod.find(
        (m: { id: string }) => m.id === id,
      );
      if (!vm) {
        return Promise.reject(new Error(`Verification method not found: ${id}`));
      }
      return Promise.resolve({ '@context': 'https://w3id.org/security/v2', ...vm });
    },
  };
}
