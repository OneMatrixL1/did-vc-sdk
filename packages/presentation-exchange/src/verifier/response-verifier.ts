import type { VPRequest, DocumentRequestNode } from '../types/request.js';
import type { VerifiablePresentation } from '../types/response.js';
import type { ZKPProvider } from '../types/zkp-provider.js';
import type { SchemaProofSystem, ProofSystemMap, ProofVerificationResult } from '../types/proof-system.js';
import { verifyPresentationStructure, type VerificationResult } from './structural-verifier.js';
import { defaultProofSystems } from '../proof-system/index.js';
import { extractConditions } from '../resolver/field-extractor.js';
import { verifyPresentation } from '@1matrix/credential-sdk/vc';
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
  /** ZKP provider for proof verification. */
  zkpProvider?: ZKPProvider;
  /** Extra or overriding proof systems. */
  proofSystems?: ProofSystemMap;
}

export interface VerifyVPResponseResult {
  /** `true` if structural, cryptographic, and proof system verification all passed. */
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
  /** Results from proof system verification (per credential). */
  proofSystemResults?: ProofVerificationResult[];
  /** Disclosed fields from ZKP proofs, keyed by docRequestID. */
  documents: Record<string, Record<string, string>>;
  /** All error messages. */
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
  const documents: Record<string, Record<string, string>> = {};
  const systems = { ...defaultProofSystems, ...options?.proofSystems };

  // --- 1. Structural ---
  const structural = verifyPresentationStructure(request, presentation);
  if (!structural.valid) {
    return { verified: false, structural, crypto: { verified: false }, documents, errors: structural.errors };
  }

  // --- 2. Crypto ---
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
      crypto.error = result.error instanceof Error ? result.error : new Error(String(result.error));
      errors.push(crypto.error.message);
    }
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    crypto = { verified: false, error };
    errors.push(error.message);
  }

  // --- 3. Proof system verification ---
  const docRequests = collectDocumentRequests(request.rules);
  const proofSystemResults: ProofVerificationResult[] = [];
  let proofSystemOk = true;

  for (const entry of presentation.presentationSubmission) {
    const docReq = docRequests.get(entry.docRequestID);
    if (!docReq) continue;

    const system = systems[docReq.schemaType];
    if (!system) continue;

    const cred = presentation.verifiableCredential[entry.credentialIndex];
    if (!cred) continue;

    const { disclose, predicates } = extractConditions(docReq.conditions);

    if (!options?.zkpProvider && (disclose.length > 0 || predicates.length > 0)) {
      errors.push(`ZKPProvider required for verification of "${entry.docRequestID}"`);
      proofSystemOk = false;
      continue;
    }

    const result = await system.verify(cred, { disclose, predicates }, {
      zkpProvider: options!.zkpProvider!,
    });

    proofSystemResults.push(result);

    if (!result.verified) {
      proofSystemOk = false;
      errors.push(...result.errors);
    }

    documents[entry.docRequestID] = result.disclosedFields;
  }

  // For ICAO credentials the ZKP proof chain (SOD → DG → Merkle) IS the
  // issuer proof, so credential-level LD-Signature verification is not
  // required when all proof-system checks pass.
  // Presentation-level crypto (holder signature) must still pass.
  const presentationCryptoOk = !!(crypto.presentationResult as Record<string, unknown>)?.verified;
  const zkpCoversCredentials = proofSystemOk && proofSystemResults.length > 0;
  const effectiveCryptoOk = crypto.verified || (presentationCryptoOk && zkpCoversCredentials);

  return {
    verified: structural.valid && effectiveCryptoOk && proofSystemOk,
    structural,
    crypto,
    proofSystemResults,
    documents,
    errors: structural.valid && effectiveCryptoOk && proofSystemOk ? [] : errors,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function collectDocumentRequests(
  node: DocumentRequestNode,
): Map<string, import('../types/request.js').DocumentRequest> {
  const map = new Map<string, import('../types/request.js').DocumentRequest>();

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
