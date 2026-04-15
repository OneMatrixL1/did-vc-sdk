/**
 * ICAO 9303 ZKP Proof System — orchestrates domain-scoped proof generation.
 *
 * Proof chain: sod-validate → dg-bridge → dg13-merklelize
 * Optional: did-delegate (Active Authentication delegation)
 * All proofs share the same domain hash for binding.
 */

import type {
  Domain,
  DomainProofSet,
  ChainProof,
  LeafData,
  ZKPProvider,
  Poseidon2Hasher,
  MerkleTreeBuilder,
  ProofStore,
  ProofGenPhase,
  CachedMerkleTree,
} from './types.js';
import type { MatchableCredential, ZKPProof, PresentedCredential, CredentialProof } from '../types/credential.js';
import { deriveDomain, DEFAULT_DOMAIN_NAME } from './domain.js';
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
  /** Poseidon2 hasher for domain derivation. */
  hasher: Poseidon2Hasher;
  /** Merkle tree builder for DG13 field tree. */
  merkleTreeBuilder: MerkleTreeBuilder;
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
  private readonly hasher: Poseidon2Hasher;
  private readonly merkle: MerkleTreeBuilder;
  private readonly store: ProofStore | undefined;

  constructor(config: ICAO9303ProofSystemConfig) {
    this.zkp = config.zkpProvider;
    this.hasher = config.hasher;
    this.merkle = config.merkleTreeBuilder;
    this.store = config.proofStore;
  }

  // -------------------------------------------------------------------------
  // Domain
  // -------------------------------------------------------------------------

  /** Derive a Domain from a human-readable name. */
  async deriveDomain(name: string = DEFAULT_DOMAIN_NAME): Promise<Domain> {
    return deriveDomain(name, this.hasher);
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
   * 3. Build Merkle tree from DG13 fields
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

    // Step 3: Build Merkle tree
    onProgress?.('merkle-tree');
    const dg13Inputs = buildDg13MerklelizeInputs(dg13Base64, domain.hash);
    const merkleTree = await this.buildMerkleTreeFromDG13(dg13Inputs, domain.hash);

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

    // Persist if store is configured
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
      if (cached) return cached;
    }
    return this.generateChainProofs(credential, credentialId, domain, onProgress, delegation);
  }

  // -------------------------------------------------------------------------
  // On-demand predicate proofs
  // -------------------------------------------------------------------------

  /**
   * Generate a predicate proof using cached Merkle tree data.
   *
   * @param proofSet - Cached chain proofs (contains merkle tree)
   * @param circuitId - Predicate circuit (e.g. 'date-greaterthan')
   * @param tagId - DG13 field tagId (1-based)
   * @param extra - Threshold values and optional dateBytes
   */
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
  // Verifier credential with ZKP disclosure
  // -------------------------------------------------------------------------

  /**
   * Build a PresentedCredential for the verifier with ZKP-authenticated fields.
   *
   * DG2 (photo) is included as raw base64 with a `dg-bridge` proof for DG2
   * that binds its hash to the SOD eContent, proving authenticity.
   *
   * @param credential - The verifier's stored credential
   * @param credentialId - Storage ID for proof cache lookup
   * @param domain - Domain to use for proof generation
   * @param includePhoto - Whether to include authenticated DG2 photo
   */
  async buildVerifierCredential(
    credential: MatchableCredential,
    credentialId: string,
    domain: Domain,
    includePhoto: boolean,
  ): Promise<PresentedCredential> {
    // Get or generate chain proofs
    const proofSet = await this.getOrGenerateProofs(credential, credentialId, domain);

    const proofs: CredentialProof[] = [];

    // Chain proofs — proves the credential is authentic
    const chainProofs = [proofSet.sodValidate, proofSet.dgBridge, proofSet.dg13Merklelize];
    if (proofSet.didDelegate) {
      chainProofs.push(proofSet.didDelegate);
    }
    for (const chain of chainProofs) {
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

    // Build credentialSubject — only ZKP-revealed data
    const subject: Record<string, unknown> = {};
    if (credential.credentialSubject['id'] !== undefined) {
      subject['id'] = credential.credentialSubject['id'];
    }

    // DG2 photo: include raw + dg-bridge proof for authenticity
    if (includePhoto) {
      const dg2 = credential.credentialSubject['dg2'];
      if (typeof dg2 === 'string') {
        subject['dg2'] = dg2;

        // Generate dg-bridge proof for DG2 (binds DG2 hash to SOD)
        const sodBase64 = this.extractSOD(credential);
        const { witness: sodWitness } = buildSodValidateInputs(sodBase64, domain.hash);
        const eContentBinding = proofSet.sodValidate.publicOutputs['eContentBinding'] as string;

        // Build dg-bridge inputs for DG2 instead of DG13
        const dg2BridgeInputs = buildDgBridgeInputs(sodWitness, domain.hash, eContentBinding);
        dg2BridgeInputs.publicInputs.dgNumber = 2;
        // Find DG2 offset in eContent
        const { findDGEntry } = await import('./sod-parser.js');
        const econtent = sodWitness.econtent;
        const dg2Offset = findDGEntry(new Uint8Array(econtent), 2);
        if (dg2Offset >= 0) {
          dg2BridgeInputs.privateInputs.dgOffset = dg2Offset;

          const dg2BridgeResult = await this.zkp.prove({
            circuitId: 'dg-bridge',
            privateInputs: dg2BridgeInputs.privateInputs,
            publicInputs: dg2BridgeInputs.publicInputs,
          });

          proofs.push({
            type: 'ZKPProof',
            conditionID: 'dg2-authenticity',
            circuitId: 'dg-bridge',
            proofSystem: 'ultrahonk',
            publicInputs: dg2BridgeInputs.publicInputs,
            publicOutputs: dg2BridgeResult.publicOutputs,
            proofValue: dg2BridgeResult.proofValue,
          } satisfies ZKPProof);
        }
      }
    }

    return {
      type: [...(credential.type as string[])],
      issuer: typeof credential.issuer === 'string'
        ? credential.issuer
        : { ...credential.issuer },
      credentialSubject: subject,
      proof: proofs,
    };
  }

  // -------------------------------------------------------------------------
  // Storage delegation
  // -------------------------------------------------------------------------

  /** List all domains with cached proofs for a credential. */
  async listDomains(credentialId: string): Promise<Domain[]> {
    return this.store ? this.store.listDomains(credentialId) : [];
  }

  /** Delete all cached proofs for a credential. */
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

  private async buildMerkleTreeFromDG13(
    dg13Inputs: { privateInputs: { rawMsg: number[]; dgLen: number; fieldOffsets: number[]; fieldLengths: number[] } },
    domain: string,
  ): Promise<CachedMerkleTree> {
    const { rawMsg, fieldOffsets, fieldLengths } = dg13Inputs.privateInputs;
    const fields = [];
    const leafDataArr: LeafData[] = [];

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
            bytes[32 - (chunkEnd - b) + (b - chunkStart)] = rawMsg[offset + b]!;
          }
          packedFields[chunk] = '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }
      }

      fields.push({
        tagId: i + 1,
        length,
        packedFields,
      });

      leafDataArr.push({
        length: length.toString(),
        data: packedFields,
      });
    }

    const tree = await this.merkle.build(fields, domain);

    return { ...tree, leafData: leafDataArr };
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
