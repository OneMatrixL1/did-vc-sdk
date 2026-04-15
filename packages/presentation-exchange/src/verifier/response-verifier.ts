import type { VPRequest } from '../types/request.js';
import type { VerifiablePresentation } from '../types/response.js';
import type { PresentedCredential, ZKPProof, CredentialProof } from '../types/credential.js';
import type { ZKPProvider, ZKPVerifyParams } from '../proof-system/types.js';
import { verifyPresentationStructure, type VerificationResult } from './structural-verifier.js';
import { verifyPresentation } from '@1matrix/credential-sdk/vc';
// @ts-ignore -- JS module, no .d.ts
import { createOptimisticResolver } from '@1matrix/credential-sdk/ethr-did';

// ---------------------------------------------------------------------------
// Options & result types
// ---------------------------------------------------------------------------

export interface VerifyVPResponseOptions {
  /** DID resolver used to fetch the holder's DID document for signature verification. */
  resolver?: {
    supports(id: string): boolean;
    resolve(id: string, opts?: unknown): Promise<unknown>;
  };
  /** ZKP provider for proof verification. Required when VP contains ZKP proofs. */
  zkpProvider?: ZKPProvider;
}

export interface VerifyVPResponseResult {
  verified: boolean;
  structural: VerificationResult;
  crypto: {
    verified: boolean;
    presentationResult?: unknown;
    credentialResults?: unknown[];
    error?: Error;
  };
  /** Disclosed fields from verified ZKP proofs, keyed by docRequestID. */
  documents: Record<string, Record<string, unknown>>;
  errors: string[];
}

// ---------------------------------------------------------------------------
// verifyVPResponse
// ---------------------------------------------------------------------------

export async function verifyVPResponse(
  request: VPRequest,
  presentation: VerifiablePresentation,
  options?: VerifyVPResponseOptions,
): Promise<VerifyVPResponseResult> {
  const errors: string[] = [];
  const documents: Record<string, Record<string, unknown>> = {};

  // --- 1. Structural ---
  const structural = verifyPresentationStructure(request, presentation);
  if (!structural.valid) {
    return { verified: false, structural, crypto: { verified: false }, documents, errors: structural.errors };
  }

  // --- 2. Crypto (holder presentation signature) ---
  const { proof, ...vpWithoutProof } = presentation;
  const vpDoc = { ...vpWithoutProof, proof };
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

  // --- 3. ZKP proof chain verification ---
  let zkpOk = true;
  const zkpProvider = options?.zkpProvider;

  for (const entry of presentation.presentationSubmission) {
    const cred = presentation.verifiableCredential[entry.credentialIndex];
    if (!cred) continue;

    const zkpProofs = extractZKPProofs(cred);
    if (zkpProofs.length === 0) continue;

    if (!zkpProvider?.verify) {
      errors.push(`ZKP provider with verify() required for credential "${entry.docRequestID}"`);
      zkpOk = false;
      continue;
    }

    // 3a. Verify each proof individually
    for (const p of zkpProofs) {
      const valid = await zkpProvider.verify({
        circuitId: p.circuitId,
        proofValue: p.proofValue,
        publicInputs: p.publicInputs,
        publicOutputs: p.publicOutputs,
      });
      if (!valid) {
        const label = p.conditionID ? `${p.circuitId}[${p.conditionID}]` : p.circuitId;
        errors.push(`ZKP proof invalid: ${label}`);
        zkpOk = false;
      }
    }

    // 3b. Verify binding chain
    const chainErrors = verifyBindingChain(zkpProofs);
    if (chainErrors.length > 0) {
      errors.push(...chainErrors);
      zkpOk = false;
    }

    documents[entry.docRequestID] = {};
  }

  // ZKP proof chain IS the credential proof for ICAO credentials,
  // so credential-level LD-Signature verification is not required
  // when ZKP chain passes. Presentation-level signature must still pass.
  const presentationCryptoOk = !!(crypto.presentationResult as Record<string, unknown>)?.verified;
  const hasZKPProofs = presentation.verifiableCredential.some(c => extractZKPProofs(c).length > 0);
  const effectiveCryptoOk = crypto.verified || (presentationCryptoOk && hasZKPProofs && zkpOk);

  return {
    verified: structural.valid && effectiveCryptoOk && zkpOk,
    structural,
    crypto,
    documents,
    errors: structural.valid && effectiveCryptoOk && zkpOk ? [] : errors,
  };
}

// ---------------------------------------------------------------------------
// ZKP helpers
// ---------------------------------------------------------------------------

function extractZKPProofs(cred: PresentedCredential): ZKPProof[] {
  if (!cred.proof) return [];
  const proofs: CredentialProof[] = Array.isArray(cred.proof) ? cred.proof : [cred.proof];
  return proofs.filter((p): p is ZKPProof => p.type === 'ZKPProof');
}

/**
 * Verify the ICAO binding chain between ZKP proofs:
 *   sod-validate.eContentBinding → dg-bridge.eContentBinding (input)
 *   dg-bridge.dgBinding → dg13-merklelize.dgBinding
 *   dg13-merklelize.commitment → predicate.commitment (input)
 */
function verifyBindingChain(proofs: ZKPProof[]): string[] {
  const errors: string[] = [];

  const sodValidate = proofs.find(p => p.circuitId === 'sod-validate');
  const dgBridge = proofs.find(p => p.circuitId === 'dg-bridge');
  const dg13 = proofs.find(p => p.circuitId === 'dg13-merklelize');

  if (!sodValidate || !dgBridge || !dg13) {
    if (!sodValidate) errors.push('Missing sod-validate proof in chain');
    if (!dgBridge) errors.push('Missing dg-bridge proof in chain');
    if (!dg13) errors.push('Missing dg13-merklelize proof in chain');
    return errors;
  }

  // sod-validate outputs eContentBinding → dg-bridge expects it as public input
  if (dgBridge.publicInputs['eContentBinding'] !== sodValidate.publicOutputs['eContentBinding']) {
    errors.push('dg-bridge eContentBinding does not match sod-validate output');
  }

  // dg-bridge outputs dgBinding → dg13-merklelize outputs dgBinding (must match)
  if (dg13.publicOutputs['dgBinding'] !== dgBridge.publicOutputs['dgBinding']) {
    errors.push('dg13-merklelize dgBinding does not match dg-bridge output');
  }

  // All chain proofs must share the same domain
  const domain = sodValidate.publicInputs['domain'];
  if (dgBridge.publicInputs['domain'] !== domain) {
    errors.push('dg-bridge domain does not match sod-validate domain');
  }
  if (dg13.publicInputs['domain'] !== domain) {
    errors.push('dg13-merklelize domain does not match sod-validate domain');
  }

  // Predicate proofs must reference dg13's commitment
  const commitment = dg13.publicOutputs['commitment'];
  const predicates = proofs.filter(p =>
    p.circuitId !== 'sod-validate' &&
    p.circuitId !== 'dg-bridge' &&
    p.circuitId !== 'dg13-merklelize' &&
    p.circuitId !== 'did-delegate',
  );
  for (const pred of predicates) {
    if (pred.publicInputs['commitment'] !== commitment) {
      errors.push(`Predicate ${pred.conditionID ?? pred.circuitId} commitment does not match dg13-merklelize`);
    }
  }

  // did-delegate (optional) must share the same domain
  const didDelegate = proofs.find(p => p.circuitId === 'did-delegate');
  if (didDelegate && didDelegate.publicInputs['domain'] !== domain) {
    errors.push('did-delegate domain does not match sod-validate domain');
  }

  return errors;
}
