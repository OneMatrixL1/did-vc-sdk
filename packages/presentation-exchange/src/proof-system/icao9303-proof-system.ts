/**
 * ICAO 9303 ZKP Proof System — orchestrates domain-scoped proof generation.
 *
 * Proof chain: sod-validate → dg-bridge → dg13-merklelize
 * Optional: did-delegate (Active Authentication delegation)
 * All proofs share the same domain hash for binding.
 *
 * Hashing (Poseidon2) and Merkle tree building are done in pure JS.
 * Only ZKP proof generation goes to the native/WASM ZKPProvider.
 */

import type {
  Domain,
  DomainProofSet,
  ChainProof,
  LeafData,
  ZKPProvider,
  ProofStore,
  ProofGenPhase,
  CachedMerkleTree,
} from './types.js';
import type { MatchableCredential, ZKPProof, MerkleDisclosure, DGDisclosure, PresentedCredential, CredentialProof } from '../types/credential.js';
import type { DocumentConditionNode, VerifierDisclosure, DocumentRequest } from '../types/request.js';
import type { SubmissionEntry } from '../types/response.js';
import { extractConditions } from '../resolver/field-extractor.js';
import { createICAOSchemaResolver } from '../resolvers/icao-schema-resolver.js';
import { deriveDomain, DEFAULT_DOMAIN_NAME } from './domain.js';
import { zkpProofContext } from '../utils/zkp-proof-context.js';
import { buildMerkleTree } from './merkle-tree.js';
import {
  buildSodValidateInputs,
  buildDgBridgeInputs,
  buildDg13MerklelizeInputs,
  buildPredicateInputs,
  buildDIDDelegateInputs,
} from './witness-builder.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface ICAO9303ProofSystemConfig {
  /** Circuit prover (native plugin or WASM). */
  zkpProvider: ZKPProvider;
  /** Optional persistent proof store. Without one, proofs are not cached. */
  proofStore?: ProofStore;
}

/** Optional delegation data for did-delegate circuit. */
export interface DelegationData {
  /** Base64-encoded DG15 from credential */
  dg15Base64: string;
  /** Base64-encoded Active Authentication signature from chip */
  aaSignatureBase64: string;
  /** Holder DID as hex field element */
  did: string;
}

// ---------------------------------------------------------------------------
// Proof System
// ---------------------------------------------------------------------------

export class ICAO9303ProofSystem {
  private readonly zkp: ZKPProvider;
  private readonly store: ProofStore | undefined;

  constructor(config: ICAO9303ProofSystemConfig) {
    this.zkp = config.zkpProvider;
    this.store = config.proofStore;
  }

  // -------------------------------------------------------------------------
  // Domain
  // -------------------------------------------------------------------------

  /** Derive a Domain from a human-readable name. Pure JS, no async. */
  deriveDomain(name: string = DEFAULT_DOMAIN_NAME): Domain {
    return deriveDomain(name);
  }

  // -------------------------------------------------------------------------
  // Chain proof generation
  // -------------------------------------------------------------------------

  /**
   * Generate the full chain proof set for a credential under a domain.
   *
   * Steps:
   * 1. Parse SOD → build sod-validate inputs → prove
   * 2. Build dg-bridge inputs (using eContentBinding) → prove
   * 3. Build Merkle tree from DG13 fields (pure JS Poseidon2)
   * 4. Build dg13-merklelize inputs → prove
   * 5. Assert dgBinding match (sanity check)
   * 6. (Optional) Build did-delegate inputs → prove
   */
  async generateChainProofs(
    credential: MatchableCredential,
    credentialId: string,
    domain: Domain,
    onProgress?: (phase: ProofGenPhase) => void,
    delegation?: DelegationData,
  ): Promise<DomainProofSet> {
    const sodBase64 = this.extractSOD(credential);
    const dg13Base64 = this.extractDG13(credential);

    // Step 1: SOD validate
    onProgress?.('sod-validate');
    const { inputs: sodInputs, witness: sodWitness } = buildSodValidateInputs(sodBase64, domain.hash);
    const sodResult = await this.zkp.prove({
      circuitId: 'sod-validate',
      privateInputs: sodInputs.privateInputs,
      publicInputs: sodInputs.publicInputs,
    });
    const eContentBinding = sodResult.publicOutputs['eContentBinding'] as string;
    const sodProof: ChainProof = {
      circuitId: 'sod-validate',
      proofValue: sodResult.proofValue,
      publicInputs: sodInputs.publicInputs,
      publicOutputs: sodResult.publicOutputs,
    };

    // Step 2: DG bridge
    onProgress?.('dg-bridge');
    const dgBridgeInputs = buildDgBridgeInputs(sodWitness, domain.hash, eContentBinding);
    const dgBridgeResult = await this.zkp.prove({
      circuitId: 'dg-bridge',
      privateInputs: dgBridgeInputs.privateInputs,
      publicInputs: dgBridgeInputs.publicInputs,
    });
    const dgBinding = dgBridgeResult.publicOutputs['dgBinding'] as string;
    const dgBridgeProof: ChainProof = {
      circuitId: 'dg-bridge',
      proofValue: dgBridgeResult.proofValue,
      publicInputs: dgBridgeInputs.publicInputs,
      publicOutputs: dgBridgeResult.publicOutputs,
    };

    // Step 3: Build Merkle tree (pure JS — no native/WASM)
    onProgress?.('merkle-tree');
    const dg13Inputs = buildDg13MerklelizeInputs(dg13Base64, domain.hash);
    const merkleTree = this.buildMerkleTreeFromDG13(dg13Inputs, domain.hash);

    // Step 4: DG13 merklelize
    onProgress?.('dg13-merklelize');
    const dg13Result = await this.zkp.prove({
      circuitId: 'dg13-merklelize',
      privateInputs: dg13Inputs.privateInputs,
      publicInputs: dg13Inputs.publicInputs,
    });
    const dg13Binding = dg13Result.publicOutputs['dgBinding'] as string;
    const dg13Proof: ChainProof = {
      circuitId: 'dg13-merklelize',
      proofValue: dg13Result.proofValue,
      publicInputs: dg13Inputs.publicInputs,
      publicOutputs: dg13Result.publicOutputs,
    };

    // Sanity check: dg-bridge binding must match dg13-merklelize binding
    if (dgBinding !== dg13Binding) {
      throw new Error(
        `Binding mismatch: dg-bridge produced ${dgBinding} but dg13-merklelize produced ${dg13Binding}`,
      );
    }



    // Step 5: DID delegation (optional)
    let didDelegateProof: ChainProof | undefined;
    if (delegation) {
      onProgress?.('did-delegate');
      const delegateInputs = buildDIDDelegateInputs(
        delegation.dg15Base64,
        delegation.aaSignatureBase64,
        domain.hash,
        delegation.did,
      );
      const delegateResult = await this.zkp.prove({
        circuitId: 'did-delegate',
        privateInputs: delegateInputs.privateInputs,
        publicInputs: delegateInputs.publicInputs,
      });
      didDelegateProof = {
        circuitId: 'did-delegate',
        proofValue: delegateResult.proofValue,
        publicInputs: delegateInputs.publicInputs,
        publicOutputs: delegateResult.publicOutputs,
      };
    }

    const proofSet: DomainProofSet = {
      domain,
      credentialId,
      createdAt: new Date().toISOString(),
      sodValidate: sodProof,
      dgBridge: dgBridgeProof,
      dg13Merklelize: dg13Proof,
      ...(didDelegateProof ? { didDelegate: didDelegateProof } : {}),
      merkleTree,
    };

    if (this.store) {
      await this.store.save(proofSet);
    }

    onProgress?.('complete');
    return proofSet;
  }

  /**
   * Get cached proof set or generate if missing.
   */
  async getOrGenerateProofs(
    credential: MatchableCredential,
    credentialId: string,
    domain: Domain,
    onProgress?: (phase: ProofGenPhase) => void,
    delegation?: DelegationData,
  ): Promise<DomainProofSet> {
    if (this.store) {
      const cached = await this.store.get(credentialId, domain.hash);
      if (cached) {
        // Validate cached Merkle tree against circuit commitment.
        // Invalidate if tree data is stale (e.g. packing bug fix).
        const cc = cached.dg13Merklelize.publicOutputs['commitment'] as string | undefined;
        const commitmentOk = cc && BigInt(cached.merkleTree.commitment) === BigInt(cc);
        const delegationOk = !delegation || !!cached.didDelegate;
        if (commitmentOk && delegationOk) {
          return cached;
        }
        await this.store.deleteAll(credentialId);
      }
    }
    return this.generateChainProofs(credential, credentialId, domain, onProgress, delegation);
  }

  // -------------------------------------------------------------------------
  // On-demand predicate proofs
  // -------------------------------------------------------------------------

  async generatePredicateProof(
    proofSet: DomainProofSet,
    circuitId: string,
    tagId: number,
    extra: {
      threshold?: number;
      thresholdMin?: number;
      thresholdMax?: number;
      dateBytes?: number[];
    },
  ): Promise<ChainProof> {
    const commitment = proofSet.dg13Merklelize.publicOutputs['commitment'] as string;
    const domain = proofSet.domain.hash;
    const leafIndex = tagId - 1;
    const siblings = proofSet.merkleTree.siblings[leafIndex]!;
    const leafData = this.extractLeafData(proofSet, leafIndex);
    const entropy = proofSet.merkleTree.leaves[leafIndex]!;

    const inputs = buildPredicateInputs(commitment, domain, tagId, siblings, leafData, entropy, extra);
    const result = await this.zkp.prove({
      circuitId,
      privateInputs: inputs.privateInputs,
      publicInputs: inputs.publicInputs,
    });

    return {
      circuitId,
      proofValue: result.proofValue,
      publicInputs: inputs.publicInputs,
      publicOutputs: result.publicOutputs,
    };
  }

  // -------------------------------------------------------------------------
  // Disclosure proof building (prover side)
  // -------------------------------------------------------------------------

  /**
   * Build disclosure proofs for a prover's VP response.
   *
   * Creates MerkleDisclosure entries for DG13 fields and DGDisclosure entries
   * for non-DG13 fields (e.g. photo from DG2). These are attached alongside
   * the chain ZKP proofs so the verifier can read disclosed values from the
   * proof array instead of raw credentialSubject.
   *
   * @param credential   - The raw credential (with DG blobs in credentialSubject)
   * @param proofSet     - Pre-generated chain proofs (includes Merkle tree)
   * @param conditions   - Request conditions (disclose + zkp)
   * @param fieldTagMap  - Map of fieldId → tagId (DG13 1-based field index)
   * @returns Array of MerkleDisclosure and DGDisclosure proof entries
   */
  async buildDisclosureProofs(
    credential: MatchableCredential,
    proofSet: DomainProofSet,
    conditions: DocumentConditionNode[],
    fieldTagMap: Record<string, number>,
  ): Promise<CredentialProof[]> {
    const { disclose } = extractConditions(conditions);
    const proofs: CredentialProof[] = [];

    for (const cond of disclose) {
      const fieldId = stripJsonPathPrefix(cond.field);
      const tagId = fieldTagMap[fieldId];
      if (tagId === undefined) continue;

      // Photo: DGDisclosure with embedded dg-bridge proof
      if (fieldId === 'photo') {
        const dg2 = credential.credentialSubject['dg2'];
        if (typeof dg2 === 'string') {
          const sodBase64 = this.extractSOD(credential);
          const { witness: sodWitness } = buildSodValidateInputs(sodBase64, proofSet.domain.hash);
          const eContentBinding = proofSet.sodValidate.publicOutputs['eContentBinding'] as string;
          const dg2BridgeInputs = buildDgBridgeInputs(sodWitness, proofSet.domain.hash, eContentBinding);
          dg2BridgeInputs.publicInputs.dgNumber = 2;
          const { findDGEntry } = await import('./sod-parser.js');
          const dg2Offset = findDGEntry(new Uint8Array(sodWitness.econtent), 2);
          if (dg2Offset >= 0) {
            dg2BridgeInputs.privateInputs.dgOffset = dg2Offset;
            const dg2BridgeResult = await this.zkp.prove({
              circuitId: 'dg-bridge',
              privateInputs: dg2BridgeInputs.privateInputs,
              publicInputs: dg2BridgeInputs.publicInputs,
            });
            proofs.push({
              type: 'DGDisclosure',
              conditionID: cond.conditionID,
              fieldId: 'photo',
              dgNumber: 2,
              data: dg2,
              dgBridgeProof: {
                type: 'ZKPProof',
                conditionID: `${cond.conditionID}-bridge`,
                circuitId: 'dg-bridge',
                proofSystem: 'ultrahonk',
                publicInputs: dg2BridgeInputs.publicInputs,
                publicOutputs: dg2BridgeResult.publicOutputs,
                proofValue: dg2BridgeResult.proofValue,
              },
            } satisfies DGDisclosure);
          }
        }
        continue;
      }

      // DG13 field: MerkleDisclosure from cached Merkle tree
      const leafIndex = tagId - 1;
      const leafData = proofSet.merkleTree.leafData[leafIndex];
      const siblings = proofSet.merkleTree.siblings[leafIndex];
      const entropy = proofSet.merkleTree.leaves[leafIndex];
      if (!leafData || !siblings || !entropy) continue;

      const value = decodeMerkleField(leafData.data, parseInt(leafData.length, 10));

      proofs.push({
        type: 'MerkleDisclosure',
        conditionID: cond.conditionID,
        fieldId,
        tagId,
        length: leafData.length,
        data: [...leafData.data] as [string, string, string, string],
        entropy,
        siblings: [...siblings],
        value,
      } satisfies MerkleDisclosure);
    }

    return proofs;
  }

  // -------------------------------------------------------------------------
  // Verifier self-disclosure (same format as prover presentation)
  // -------------------------------------------------------------------------

  /**
   * Build a VerifierDisclosure — the verifier's own selective disclosure.
   *
   * Uses the same data structures and pipeline as the prover:
   * - Accepts `DocumentConditionNode[]` (same as VPRequest rules conditions)
   * - Derives credential via ICAO resolver (empty credentialSubject)
   * - Attaches chain ZKP proofs + MerkleDisclosure entries for each disclosed field
   * - Disclosed field values live in the proof array, not credentialSubject
   *
   * @param credential     - Verifier's raw credential (with DG blobs)
   * @param credentialId   - Storage key for proof caching
   * @param domain         - Domain for proof binding
   * @param conditions     - What to disclose (same format as DocumentRequest.conditions)
   * @param fieldTagMap    - Map of fieldId → tagId (DG13 1-based field index)
   */
  async buildVerifierDisclosure(
    credential: MatchableCredential,
    credentialId: string,
    domain: Domain,
    conditions: DocumentConditionNode[],
    fieldTagMap: Record<string, number>,
  ): Promise<VerifierDisclosure> {
    const proofSet = await this.getOrGenerateProofs(credential, credentialId, domain);




    // 1. Extract conditions — same as resolvePresentation does
    const { disclose } = extractConditions(conditions);

    // 2. Derive credential via ICAO resolver — empty credentialSubject
    const resolver = createICAOSchemaResolver();
    const derived = await resolver.deriveCredential(credential, []);

    // 3. Build proof array — same pattern as resolvePresentation
    const proofs: CredentialProof[] = [];

    // Chain proofs (always attached)
    const chains = [proofSet.sodValidate, proofSet.dgBridge, proofSet.dg13Merklelize];
    if (proofSet.didDelegate) chains.push(proofSet.didDelegate);
    for (const chain of chains) {
      proofs.push({
        type: 'ZKPProof',
        conditionID: `chain-${chain.circuitId}`,
        circuitId: chain.circuitId,
        proofSystem: 'ultrahonk',
        publicInputs: chain.publicInputs,
        publicOutputs: chain.publicOutputs,
        proofValue: chain.proofValue,
      } satisfies ZKPProof);
    }

    // 4. MerkleDisclosure for each disclosed DG13 field
    for (const cond of disclose) {
      const fieldId = cond.field;
      const tagId = fieldTagMap[fieldId];
      if (tagId === undefined) continue; // skip fields not in DG13

      // Special case: photo is in dg2, not DG13 Merkle tree
      // Use DGDisclosure — raw data + embedded dg-bridge ZKP proof
      if (fieldId === 'photo') {
        const dg2 = credential.credentialSubject['dg2'];
        if (typeof dg2 === 'string') {
          const sodBase64 = this.extractSOD(credential);
          const { witness: sodWitness } = buildSodValidateInputs(sodBase64, domain.hash);
          const eContentBinding = proofSet.sodValidate.publicOutputs['eContentBinding'] as string;
          const dg2BridgeInputs = buildDgBridgeInputs(sodWitness, domain.hash, eContentBinding);
          dg2BridgeInputs.publicInputs.dgNumber = 2;
          const { findDGEntry } = await import('./sod-parser.js');
          const dg2Offset = findDGEntry(new Uint8Array(sodWitness.econtent), 2);
          if (dg2Offset >= 0) {
            dg2BridgeInputs.privateInputs.dgOffset = dg2Offset;
            const dg2BridgeResult = await this.zkp.prove({
              circuitId: 'dg-bridge',
              privateInputs: dg2BridgeInputs.privateInputs,
              publicInputs: dg2BridgeInputs.publicInputs,
            });
            proofs.push({
              type: 'DGDisclosure',
              conditionID: cond.conditionID,
              fieldId: 'photo',
              dgNumber: 2,
              data: dg2,
              dgBridgeProof: {
                type: 'ZKPProof',
                conditionID: `${cond.conditionID}-bridge`,
                circuitId: 'dg-bridge',
                proofSystem: 'ultrahonk',
                publicInputs: dg2BridgeInputs.publicInputs,
                publicOutputs: dg2BridgeResult.publicOutputs,
                proofValue: dg2BridgeResult.proofValue,
              },
            } satisfies DGDisclosure);
          }
        }
        continue;
      }

      // DG13 field: build MerkleDisclosure from cached Merkle tree
      const leafIndex = tagId - 1;
      const leafData = proofSet.merkleTree.leafData[leafIndex];
      const siblings = proofSet.merkleTree.siblings[leafIndex];
      const entropy = proofSet.merkleTree.leaves[leafIndex];
      if (!leafData || !siblings || !entropy) continue;

      // Decode packed field data to UTF-8 value
      const value = decodeMerkleField(leafData.data, parseInt(leafData.length, 10));

      proofs.push({
        type: 'MerkleDisclosure',
        conditionID: cond.conditionID,
        fieldId,
        tagId,
        length: leafData.length,
        data: [...leafData.data] as [string, string, string, string],
        entropy,
        siblings: [...siblings],
        value,
      } satisfies MerkleDisclosure);
    }

    derived.proof = proofs;

    // Add ZKP proof context for JSON-LD expansion
    const ctx = (derived as Record<string, unknown>)['@context'];
    if (Array.isArray(ctx)) {
      ctx.push(zkpProofContext);
    }

    // 5. Build the DocumentRequest that describes this disclosure
    const request: DocumentRequest = {
      type: 'DocumentRequest',
      docRequestID: 'verifier-doc',
      docType: [...(credential.type as string[])],
      schemaType: 'ICAO9303SOD',
      conditions,
    };

    return {
      request,
      credentials: [derived],
      submission: [{ docRequestID: 'verifier-doc', credentialIndex: 0 }],
    };
  }

  /** @deprecated Use buildVerifierDisclosure instead. */
  async buildVerifierCredential(
    credential: MatchableCredential,
    credentialId: string,
    domain: Domain,
    includePhoto: boolean,
  ): Promise<PresentedCredential> {
    const conditions: DocumentConditionNode[] = [];
    if (includePhoto) {
      conditions.push({
        type: 'DocumentCondition',
        conditionID: 'v-photo',
        field: 'photo',
        operator: 'disclose',
      });
    }
    const disclosure = await this.buildVerifierDisclosure(
      credential, credentialId, domain, conditions, { photo: 0 },
    );
    return disclosure.credentials[0]!;
  }

  // -------------------------------------------------------------------------
  // Storage
  // -------------------------------------------------------------------------

  async listDomains(credentialId: string): Promise<Domain[]> {
    return this.store ? this.store.listDomains(credentialId) : [];
  }

  async deleteProofs(credentialId: string): Promise<void> {
    if (this.store) {
      await this.store.deleteAll(credentialId);
    }
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private extractSOD(credential: MatchableCredential): string {
    const proof = credential.proof as Record<string, unknown> | undefined;
    if (!proof || typeof proof['sod'] !== 'string') {
      throw new Error('Credential proof.sod (base64 SOD) is required');
    }
    return proof['sod'] as string;
  }

  private extractDG13(credential: MatchableCredential): string {
    const dg13 = credential.credentialSubject['dg13'];
    if (typeof dg13 !== 'string') {
      throw new Error('Credential credentialSubject.dg13 (base64) is required');
    }
    return dg13;
  }

  private buildMerkleTreeFromDG13(
    dg13Inputs: { privateInputs: { rawMsg: number[]; dgLen: number; fieldOffsets: number[]; fieldLengths: number[] } },
    domain: string,
  ): CachedMerkleTree {
    const { rawMsg, dgLen, fieldOffsets, fieldLengths } = dg13Inputs.privateInputs;

    // Compute DG13 SHA-256 hash halves (needed for entropy derivation)
    const dgHashHi = computeHashHalf(rawMsg, dgLen, 0);
    const dgHashLo = computeHashHalf(rawMsg, dgLen, 16);

    const fields = [];
    for (let i = 0; i < 16; i++) {
      const offset = fieldOffsets[i]!;
      const length = fieldLengths[i]!;

      const packedFields: [string, string, string, string] = ['0x0', '0x0', '0x0', '0x0'];
      for (let chunk = 0; chunk < 4; chunk++) {
        const chunkStart = chunk * 31;
        if (chunkStart < length) {
          const chunkEnd = Math.min(chunkStart + 31, length);
          const bytes = new Uint8Array(32);
          for (let b = chunkStart; b < chunkEnd; b++) {
            bytes[32 - chunkEnd + b] = rawMsg[offset + b]!;
          }
          packedFields[chunk] = '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }
      }

      fields.push({ tagId: i + 1, length, packedFields });
    }

    return buildMerkleTree(fields, domain, dgHashHi, dgHashLo);
  }

  private extractLeafData(
    proofSet: DomainProofSet,
    leafIndex: number,
  ): { length: string; data: string[] } {
    const leaf = proofSet.merkleTree.leafData[leafIndex];
    if (!leaf) {
      throw new Error(`No leaf data for leafIndex ${leafIndex}`);
    }
    return { length: leaf.length, data: [...leaf.data] };
  }
}

// ---------------------------------------------------------------------------
// SHA-256 hash half computation (matches circuit's dgHashHi / dgHashLo)
// ---------------------------------------------------------------------------

/** @internal Exported for testing only. */
export function computeHashHalf(rawMsg: number[], dgLen: number, startByte: number): string {
  // SHA-256 of raw DG13 bytes, then pack upper/lower 16 bytes as field element
  // This is computed in JS using SubtleCrypto at tree-build time
  // For now, placeholder — the actual SHA-256 is done inside the circuit.
  // The Merkle tree builder needs these for entropy derivation.
  // We compute SHA-256 synchronously via a simple implementation.
  const data = new Uint8Array(rawMsg.slice(0, dgLen));
  const hash = sha256Sync(data);
  let result = 0n;
  for (let i = startByte; i < startByte + 16; i++) {
    result = result * 256n + BigInt(hash[i]!);
  }
  return '0x' + result.toString(16);
}

/** @internal Minimal synchronous SHA-256 (pure JS, no deps). Exported for testing. */
export function sha256Sync(data: Uint8Array): Uint8Array {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;

  const len = data.length;
  const bitLen = len * 8;
  const padLen = ((len + 9 + 63) & ~63);
  const buf = new Uint8Array(padLen);
  buf.set(data);
  buf[len] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(padLen - 4, bitLen, false);

  let [h0, h1, h2, h3, h4, h5, h6, h7] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  const w = new Uint32Array(64);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15]!, 7) ^ rotr(w[i-15]!, 18) ^ (w[i-15]! >>> 3);
      const s1 = rotr(w[i-2]!, 17) ^ rotr(w[i-2]!, 19) ^ (w[i-2]! >>> 10);
      w[i] = (w[i-16]! + s0 + w[i-7]! + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = [h0!, h1!, h2!, h3!, h4!, h5!, h6!, h7!];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i]! + w[i]!) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0! + a) >>> 0; h1 = (h1! + b) >>> 0; h2 = (h2! + c) >>> 0; h3 = (h3! + d) >>> 0;
    h4 = (h4! + e) >>> 0; h5 = (h5! + f) >>> 0; h6 = (h6! + g) >>> 0; h7 = (h7! + h) >>> 0;
  }

  const result = new Uint8Array(32);
  const rv = new DataView(result.buffer);
  rv.setUint32(0, h0!, false); rv.setUint32(4, h1!, false);
  rv.setUint32(8, h2!, false); rv.setUint32(12, h3!, false);
  rv.setUint32(16, h4!, false); rv.setUint32(20, h5!, false);
  rv.setUint32(24, h6!, false); rv.setUint32(28, h7!, false);
  return result;
}

// ---------------------------------------------------------------------------
// Decode packed Merkle field data back to UTF-8 string
// ---------------------------------------------------------------------------

/**
 * Decode packed 31-byte hex chunks back to a UTF-8 string.
 *
 * Each chunk is a big-endian field element containing up to 31 bytes of data,
 * right-aligned (least significant bytes hold the actual data).
 *
 * Exported for use by frontend when reading MerkleDisclosure proof entries.
 */
export function decodeMerkleField(
  data: readonly [string, string, string, string] | readonly string[],
  totalLen: number,
): string {
  if (totalLen <= 0) return '';
  const bytes: number[] = [];
  for (let chunk = 0; chunk < 4; chunk++) {
    const chunkStart = chunk * 31;
    if (chunkStart >= totalLen) break;
    const chunkEnd = Math.min(chunkStart + 31, totalLen);
    const chunkLen = chunkEnd - chunkStart;

    // Parse hex to bigint, then extract right-aligned bytes
    const hex = BigInt(data[chunk]!);
    const buf = new Uint8Array(32);
    let val = hex;
    for (let i = 31; i >= 0; i--) {
      buf[i] = Number(val & 0xFFn);
      val >>= 8n;
    }
    // Field data is packed right-aligned in the 32-byte slot
    for (let b = 0; b < chunkLen; b++) {
      bytes.push(buf[32 - chunkLen + b]!);
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes.slice(0, totalLen)));
}

function stripJsonPathPrefix(field: string): string {
  const prefix = '$.credentialSubject.';
  if (field.startsWith(prefix)) return field.slice(prefix.length);
  const lastDot = field.lastIndexOf('.');
  return lastDot >= 0 ? field.slice(lastDot + 1) : field;
}
