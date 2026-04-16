import type { VPRequest, DocumentRequestNode, DocumentRequest } from '../types/request.js';
import type { VerifiablePresentation } from '../types/response.js';
import type { PresentedCredential, ZKPProof, CredentialProof } from '../types/credential.js';
import type { ZKPProvider, ZKPVerifyParams } from '../proof-system/types.js';
import { verifyPresentationStructure, type VerificationResult } from './structural-verifier.js';
import { extractConditions } from '../resolver/field-extractor.js';
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

  // --- 2. Crypto (holder VP envelope signature) ---
  // Credential-level proof verification is skipped here — credential-sdk
  // doesn't understand ZKPProof type. Credential authenticity is verified
  // via the ZKP chain in step 3. We only verify the VP holder signature.
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

    // VP envelope signature must pass. Credential-level verification may fail
    // for ZKP-proven credentials (credential-sdk doesn't know ZKPProof type) —
    // that's OK because ZKP chain verification in step 3 handles it.
    const presentationResult = result.presentationResult as Record<string, unknown> | undefined;
    const vpSignatureOk = presentationResult?.verified === true;
    crypto = {
      verified: vpSignatureOk,
      presentationResult,
      credentialResults: result.credentialResults as unknown[] | undefined,
    };

    if (!vpSignatureOk) {
      const err = (presentationResult?.error ?? result.error) as Error | string | undefined;
      const msg = err instanceof Error ? err.message : String(err ?? 'VP signature failed');
      crypto.error = new Error(msg);
      errors.push(msg);
    }
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    crypto = { verified: false, error };
    errors.push(error.message);
  }

  // --- 3. ZKP proof chain verification ---
  let zkpOk = true;
  const zkpProvider = options?.zkpProvider;
  const docRequests = collectAllDocumentRequests(request.rules);
  const zkpVerifiedIndices = new Set<number>();

  for (const entry of presentation.presentationSubmission) {
    const cred = presentation.verifiableCredential[entry.credentialIndex];
    if (!cred) continue;

    const zkpProofs = extractZKPProofs(cred);
    if (zkpProofs.length === 0) continue;

    zkpVerifiedIndices.add(entry.credentialIndex);

    if (!zkpProvider?.verify) {
      errors.push('ZKP proofs present but no zkpProvider was supplied — cannot verify');
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

    // 3b. Verify binding chain (did-delegate is required)
    const chainErrors = verifyBindingChain(zkpProofs);
    if (chainErrors.length > 0) {
      errors.push(...chainErrors);
      zkpOk = false;
    }

    // 3c. Per-document holder binding: did-delegate "did" must match VP holder
    const docReq = docRequests.get(entry.docRequestID);
    if (docReq?.requireHolderBinding) {
      const didDelegate = zkpProofs.find(p => p.circuitId === 'did-delegate');
      if (didDelegate) {
        const proofDid = String(didDelegate.publicInputs['did'] ?? '');
        const holderAddress = extractHolderAddress(presentation.holder);
        if (!holderAddress || proofDid !== holderAddress) {
          errors.push(
            `${entry.docRequestID}: did-delegate "did" (${proofDid}) does not match VP holder (${holderAddress ?? 'unknown'})`,
          );
          zkpOk = false;
        }
      }
    }

    // 3d. Verify all requested ZKP conditions have matching proofs with correct circuit
    const docReqForConds = docRequests.get(entry.docRequestID);
    if (docReqForConds) {
      const { zkp: zkpConditions } = extractConditions(docReqForConds.conditions);
      const proofByConditionID = new Map(zkpProofs.map(p => [p.conditionID, p]));
      for (const cond of zkpConditions) {
        const proof = proofByConditionID.get(cond.conditionID);
        if (!proof) {
          errors.push(
            `${entry.docRequestID}: missing ZKP proof for requested condition "${cond.conditionID}" (circuit: ${cond.circuitId})`,
          );
          zkpOk = false;
        } else if (proof.circuitId !== cond.circuitId) {
          errors.push(
            `${entry.docRequestID}: condition "${cond.conditionID}" requires circuit "${cond.circuitId}" but proof uses "${proof.circuitId}"`,
          );
          zkpOk = false;
        }
      }
    }

    documents[entry.docRequestID] = {};
  }

  // --- 4. Credential-level proof verification for non-ZKP credentials ---
  // Credentials verified via ZKP chain (step 3) don't need LD-Signature checks.
  // All other credentials must have a valid issuer signature verified by credential-sdk.
  const credentialResults = crypto.credentialResults as { verified?: boolean }[] | undefined;
  for (const entry of presentation.presentationSubmission) {
    if (zkpVerifiedIndices.has(entry.credentialIndex)) continue;

    const credResult = credentialResults?.[entry.credentialIndex];
    if (!credResult?.verified) {
      errors.push(
        `Credential at index ${entry.credentialIndex} (docRequestID "${entry.docRequestID}") has no ZKP proofs and failed issuer signature verification`,
      );
      zkpOk = false;
    }
  }

  // VP envelope signature (holder's proof) must always pass.
  // Credential-level LD-Signature may fail for ZKP credentials — that's
  // expected because credential-sdk doesn't verify ZKPProof type.
  // The ZKP chain verification above handles credential authenticity.
  const vpSignatureOk = crypto.verified;
  const verified = structural.valid && vpSignatureOk && zkpOk;

  return {
    verified,
    structural,
    crypto,
    documents,
    errors: verified ? [] : errors,
  };
}

// ---------------------------------------------------------------------------
// ZKP helpers
// ---------------------------------------------------------------------------

function extractHolderAddress(holder: string): string | undefined {
  // did:ethr:0x1234... → 0x1234...
  const parts = holder.split(':');
  const last = parts[parts.length - 1];
  if (last && last.startsWith('0x')) return last;
  return undefined;
}

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
  const didDelegate = proofs.find(p => p.circuitId === 'did-delegate');

  if (!sodValidate || !dgBridge || !dg13 || !didDelegate) {
    if (!sodValidate) errors.push('Missing sod-validate proof in chain');
    if (!dgBridge) errors.push('Missing dg-bridge proof in chain');
    if (!dg13) errors.push('Missing dg13-merklelize proof in chain');
    if (!didDelegate) errors.push('Missing did-delegate proof in chain');
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

  // did-delegate must share the same domain.
  // Note: did-delegate.dgBinding is for DG15 (chip key), dg-bridge.dgBinding is
  // for DG13 (identity data) — they are different data groups, so bindings differ.
  if (didDelegate.publicInputs['domain'] !== domain) {
    errors.push('did-delegate domain does not match sod-validate domain');
  }

  return errors;
}

function collectAllDocumentRequests(
  node: DocumentRequestNode,
): Map<string, DocumentRequest> {
  const map = new Map<string, DocumentRequest>();
  function walk(n: DocumentRequestNode): void {
    if (n.type === 'Logical') {
      for (const child of n.values) walk(child);
    } else {
      map.set(n.docRequestID, n);
    }
  }
  walk(node);
  return map;
}
