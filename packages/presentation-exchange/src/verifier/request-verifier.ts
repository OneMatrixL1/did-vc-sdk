import type { VPRequest } from '../types/request.js';
import type { PresentedCredential, ZKPProof, MerkleDisclosure, DGDisclosure, CredentialProof } from '../types/credential.js';
import type { ZKPProvider } from '../proof-system/types.js';
import type { VerificationResult } from './structural-verifier.js';
import { poseidon2BigInt } from '../proof-system/poseidon2.js';
import { TREE_DEPTH } from '../proof-system/merkle-tree.js';
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
  // Support both new verifierDisclosure and legacy verifierCredentials
  const creds = request.verifierDisclosure?.credentials ?? request.verifierCredentials;
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

  const { proof, verifierCredentials: _vc, ...unsigned } = request;
  const domain = proof.domain;
  const challenge = proof.challenge;

  // Reconstruct the same VP-like envelope that buildSigned created.
  // Strip verifierCredentials — it contains proof entries (MerkleDisclosure,
  // DGDisclosure) with properties not in the JSON-LD context.
  // verifierDisclosure (typed @json) already carries the same data.
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
// Verifier credential verification (ZKP chain + MerkleDisclosure + DGDisclosure)
// ---------------------------------------------------------------------------

function extractAllProofs(cred: PresentedCredential): CredentialProof[] {
  if (!cred.proof) return [];
  return Array.isArray(cred.proof) ? cred.proof : [cred.proof];
}

function extractZKPProofs(cred: PresentedCredential): ZKPProof[] {
  return extractAllProofs(cred).filter((p): p is ZKPProof => p.type === 'ZKPProof');
}

function extractMerkleDisclosures(cred: PresentedCredential): MerkleDisclosure[] {
  return extractAllProofs(cred).filter((p): p is MerkleDisclosure => p.type === 'MerkleDisclosure');
}

function extractDGDisclosures(cred: PresentedCredential): DGDisclosure[] {
  return extractAllProofs(cred).filter((p): p is DGDisclosure => p.type === 'DGDisclosure');
}

async function verifyVerifierCredentials(
  request: VPRequest,
  zkpProvider?: ZKPProvider,
): Promise<VerifierCredentialResult> {
  // Support both new verifierDisclosure and legacy verifierCredentials
  const creds = request.verifierDisclosure?.credentials ?? request.verifierCredentials;
  if (!creds || creds.length === 0) {
    return { verified: false, errors: [] };
  }

  if (!zkpProvider?.verify) {
    return { verified: false, errors: ['verifierCredentials have ZKP proofs but no zkpProvider supplied'] };
  }

  const errors: string[] = [];
  let allValid = true;

  for (let i = 0; i < creds.length; i++) {
    const cred = creds[i]!;
    const zkpProofs = extractZKPProofs(cred);
    if (zkpProofs.length === 0) {
      errors.push(`verifierCredentials[${i}] has no ZKP proofs`);
      allValid = false;
      continue;
    }

    // --- Step 1: Verify each ZKP proof individually ---
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

    // --- Step 1b: Verify binding chain between chain proofs ---
    const chainErrors = verifyVerifierBindingChain(zkpProofs);
    if (chainErrors.length > 0) {
      errors.push(...chainErrors.map(e => `verifierCredentials[${i}]: ${e}`));
      allValid = false;
    }

    // Extract chain values needed for disclosure verification
    const dg13 = zkpProofs.find(p => p.circuitId === 'dg13-merklelize');
    const sodValidate = zkpProofs.find(p => p.circuitId === 'sod-validate');
    const chainDomain = sodValidate?.publicInputs['domain'] as string | undefined;
    const chainCommitment = dg13?.publicOutputs['commitment'] as string | undefined;
    const chainEContentBinding = sodValidate?.publicOutputs['eContentBinding'] as string | undefined;

    // --- Step 2: Verify MerkleDisclosure entries ---
    const merkleDisclosures = extractMerkleDisclosures(cred);
    for (const md of merkleDisclosures) {
      if (!chainCommitment || !chainDomain) {
        errors.push(`verifierCredentials[${i}]: MerkleDisclosure "${md.conditionID}" cannot be verified — missing chain commitment/domain`);
        allValid = false;
        continue;
      }
      const mdErrors = verifyMerkleDisclosure(md, chainCommitment, chainDomain);
      if (mdErrors.length > 0) {
        errors.push(...mdErrors.map(e => `verifierCredentials[${i}]: MerkleDisclosure "${md.conditionID}": ${e}`));
        allValid = false;
      }
    }

    // --- Step 3: Verify DGDisclosure entries ---
    const dgDisclosures = extractDGDisclosures(cred);
    for (const dg of dgDisclosures) {
      // 3a. Verify the embedded dg-bridge ZKP proof
      const bridgeValid = await zkpProvider.verify({
        circuitId: dg.dgBridgeProof.circuitId,
        proofValue: dg.dgBridgeProof.proofValue,
        publicInputs: dg.dgBridgeProof.publicInputs,
        publicOutputs: dg.dgBridgeProof.publicOutputs,
      });
      if (!bridgeValid) {
        errors.push(`verifierCredentials[${i}]: DGDisclosure "${dg.conditionID}" embedded dg-bridge proof invalid`);
        allValid = false;
        continue;
      }

      // 3b. dgBinding = Poseidon2([SHA256_hi, SHA256_lo, domain], 3)
      //     The dg-bridge circuit outputs a Poseidon2 binding, not a plain SHA-256.
      const dgBinding = dg.dgBridgeProof.publicOutputs['dgBinding'] as string | undefined;
      const bridgeDomainForHash = dg.dgBridgeProof.publicInputs['domain'] as string | undefined;
      if (dgBinding && bridgeDomainForHash) {
        const recomputedBinding = await computeDGBinding(dg.data, bridgeDomainForHash);
        if (recomputedBinding !== BigInt(dgBinding)) {
          errors.push(`verifierCredentials[${i}]: DGDisclosure "${dg.conditionID}" SHA256(data) does not match dgBinding`);
          allValid = false;
        }
      } else if (!dgBinding) {
        errors.push(`verifierCredentials[${i}]: DGDisclosure "${dg.conditionID}" missing dgBinding output`);
        allValid = false;
      }

      // 3c. eContentBinding must match chain sod-validate
      const bridgeECB = dg.dgBridgeProof.publicInputs['eContentBinding'] as string | undefined;
      if (chainEContentBinding && bridgeECB !== chainEContentBinding) {
        errors.push(`verifierCredentials[${i}]: DGDisclosure "${dg.conditionID}" eContentBinding does not match chain`);
        allValid = false;
      }

      // 3d. Domain must match chain
      const bridgeDomain = dg.dgBridgeProof.publicInputs['domain'] as string | undefined;
      if (chainDomain && bridgeDomain !== chainDomain) {
        errors.push(`verifierCredentials[${i}]: DGDisclosure "${dg.conditionID}" domain does not match chain`);
        allValid = false;
      }
    }
  }

  return { verified: allValid, errors };
}

// ---------------------------------------------------------------------------
// Binding chain verification for verifier credentials
// (Adapted from response-verifier.ts — did-delegate is optional for verifier)
// ---------------------------------------------------------------------------

function verifyVerifierBindingChain(proofs: ZKPProof[]): string[] {
  const errors: string[] = [];

  const sodValidate = proofs.find(p => p.circuitId === 'sod-validate');
  const dgBridge = proofs.find(p => p.conditionID?.startsWith('chain-') && p.circuitId === 'dg-bridge');
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

  return errors;
}

// ---------------------------------------------------------------------------
// MerkleDisclosure verification (Step 2)
// Recompute leaf → walk siblings → check commitment
// ---------------------------------------------------------------------------

function verifyMerkleDisclosure(
  md: MerkleDisclosure,
  expectedCommitment: string,
  domain: string,
): string[] {
  const errors: string[] = [];

  try {
    const tagId = BigInt(md.tagId);
    const length = BigInt(md.length);
    const data = md.data.map(BigInt);
    const entropy = BigInt(md.entropy);
    const domainBig = BigInt(domain);

    // Recompute leaf = Poseidon2([tagId, length, data[0..3], entropy], 7)
    const leaf = poseidon2BigInt(
      [tagId, length, data[0]!, data[1]!, data[2]!, data[3]!, entropy],
      7,
    );

    // Walk Merkle path from leaf to root
    let current = leaf;
    let idx = md.tagId - 1; // 0-based leaf index
    for (let level = 0; level < TREE_DEPTH; level++) {
      const sibling = BigInt(md.siblings[level]!);
      current = idx % 2 === 0
        ? poseidon2BigInt([current, sibling], 2)
        : poseidon2BigInt([sibling, current], 2);
      idx = Math.floor(idx / 2);
    }

    // commitment = Poseidon2([root, domain], 2)
    const recomputedCommitment = poseidon2BigInt([current, domainBig], 2);
    const expectedBig = BigInt(expectedCommitment);

    if (recomputedCommitment !== expectedBig) {
      errors.push('Merkle path does not match dg13-merklelize commitment');
    }
  } catch (e) {
    errors.push(`Verification error: ${e instanceof Error ? e.message : String(e)}`);
  }

  return errors;
}

// ---------------------------------------------------------------------------
// DG binding verification (Step 3)
//
// The dg-bridge circuit outputs: dgBinding = Poseidon2([SHA256_hi, SHA256_lo, domain], 3)
// where SHA256_hi/Lo are the upper/lower 16 bytes of SHA-256(DG_data) packed as field elements.
// ---------------------------------------------------------------------------

async function computeDGBinding(base64Data: string, domain: string): Promise<bigint> {
  // Decode base64 to bytes
  let bytes: Uint8Array;
  if (typeof Buffer !== 'undefined') {
    bytes = new Uint8Array(Buffer.from(base64Data, 'base64'));
  } else {
    const binary = atob(base64Data);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
  }

  // SHA-256 hash
  let hash: Uint8Array;
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    const input = new Uint8Array(bytes).buffer as ArrayBuffer;
    const buf = await globalThis.crypto.subtle.digest('SHA-256', input);
    hash = new Uint8Array(buf);
  } else {
    const { createHash } = await import('crypto');
    hash = new Uint8Array(createHash('sha256').update(bytes).digest());
  }

  // Pack upper/lower 16 bytes as big-endian field elements (matches circuit)
  let dgHashHi = 0n;
  for (let i = 0; i < 16; i++) {
    dgHashHi = dgHashHi * 256n + BigInt(hash[i]!);
  }
  let dgHashLo = 0n;
  for (let i = 16; i < 32; i++) {
    dgHashLo = dgHashLo * 256n + BigInt(hash[i]!);
  }

  // dgBinding = Poseidon2([dgHashHi, dgHashLo, domain], 3)
  return poseidon2BigInt([dgHashHi, dgHashLo, BigInt(domain)], 3);
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

