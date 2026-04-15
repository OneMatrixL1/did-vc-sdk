/**
 * ICAO 9303 ZKP Proof System — orchestrates domain-scoped proof generation.
 *
 * Proof chain: sod-verify → dg-map → dg13-merklelize
 * All proofs share the same domain hash (salt) for binding.
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
  buildSodVerifyInputs,
  buildDgMapInputs,
  buildDg13MerklelizeInputs,
  buildPredicateInputs,
  buildFieldRevealInputs,
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
   * 1. Parse SOD → build sod-verify inputs → prove
   * 2. Build dg-map inputs (using econtent_binding) → prove
   * 3. Build Merkle tree from DG13 fields
   * 4. Build dg13-merklelize inputs → prove
   * 5. Assert dg_binding === dg13 binding (sanity check)
   */
  async generateChainProofs(
    credential: MatchableCredential,
    credentialId: string,
    domain: Domain,
    onProgress?: (phase: ProofGenPhase) => void,
  ): Promise<DomainProofSet> {
    const sodBase64 = this.extractSOD(credential);
    const dg13Base64 = this.extractDG13(credential);

    // Step 1: SOD verify
    onProgress?.('sod-verify');
    const { inputs: sodInputs, witness: sodWitness } = buildSodVerifyInputs(sodBase64, domain.hash);
    const sodResult = await this.zkp.prove({
      circuitId: 'sod-verify',
      privateInputs: sodInputs.privateInputs,
      publicInputs: sodInputs.publicInputs,
    });
    const econtentBinding = sodResult.publicOutputs['econtent_binding'] as string;
    const sodProof: ChainProof = {
      circuitId: 'sod-verify',
      proofValue: sodResult.proofValue,
      publicInputs: sodInputs.publicInputs,
      publicOutputs: sodResult.publicOutputs,
    };

    // Step 2: DG-map
    onProgress?.('dg-map');
    const dgMapInputs = buildDgMapInputs(sodWitness, domain.hash, econtentBinding);
    const dgMapResult = await this.zkp.prove({
      circuitId: 'dg-map',
      privateInputs: dgMapInputs.privateInputs,
      publicInputs: dgMapInputs.publicInputs,
    });
    const dgBinding = dgMapResult.publicOutputs['dg_binding'] as string;
    const dgMapProof: ChainProof = {
      circuitId: 'dg-map',
      proofValue: dgMapResult.proofValue,
      publicInputs: dgMapInputs.publicInputs,
      publicOutputs: dgMapResult.publicOutputs,
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
    const dg13Binding = dg13Result.publicOutputs['binding'] as string;
    const dg13Proof: ChainProof = {
      circuitId: 'dg13-merklelize',
      proofValue: dg13Result.proofValue,
      publicInputs: dg13Inputs.publicInputs,
      publicOutputs: dg13Result.publicOutputs,
    };

    // Sanity check: dg-map binding must match dg13-merklelize binding
    if (dgBinding !== dg13Binding) {
      throw new Error(
        `Binding mismatch: dg-map produced ${dgBinding} but dg13-merklelize produced ${dg13Binding}`,
      );
    }

    const proofSet: DomainProofSet = {
      domain,
      credentialId,
      createdAt: new Date().toISOString(),
      sodVerify: sodProof,
      dgMap: dgMapProof,
      dg13Merklelize: dg13Proof,
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
  ): Promise<DomainProofSet> {
    if (this.store) {
      const cached = await this.store.get(credentialId, domain.hash);
      if (cached) return cached;
    }
    return this.generateChainProofs(credential, credentialId, domain, onProgress);
  }

  // -------------------------------------------------------------------------
  // On-demand predicate/reveal proofs
  // -------------------------------------------------------------------------

  /**
   * Generate a predicate proof using cached Merkle tree data.
   *
   * @param proofSet - Cached chain proofs (contains merkle tree)
   * @param circuitId - Predicate circuit (e.g. 'date-greaterthan')
   * @param tagId - DG13 field index (0-based)
   * @param extra - Threshold values and optional date_bytes
   */
  async generatePredicateProof(
    proofSet: DomainProofSet,
    circuitId: string,
    tagId: number,
    extra: {
      threshold?: number;
      threshold_min?: number;
      threshold_max?: number;
      date_bytes?: number[];
    },
  ): Promise<ChainProof> {
    const commitment = proofSet.dg13Merklelize.publicOutputs['commitment'] as string;
    const salt = proofSet.domain.hash;
    const siblings = proofSet.merkleTree.siblings[tagId]!;

    // Leaf data needs to be extracted from the Merkle tree leaves
    // The caller must provide the packed leaf data
    const leafData = this.extractLeafData(proofSet, tagId);

    const inputs = buildPredicateInputs(commitment, salt, tagId, siblings, leafData, extra);
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

  /**
   * Generate a field-reveal proof.
   */
  async generateFieldRevealProof(
    proofSet: DomainProofSet,
    tagId: number,
  ): Promise<ChainProof> {
    const commitment = proofSet.dg13Merklelize.publicOutputs['commitment'] as string;
    const salt = proofSet.domain.hash;
    const siblings = proofSet.merkleTree.siblings[tagId]!;
    const leafData = this.extractLeafData(proofSet, tagId);

    const inputs = buildFieldRevealInputs(commitment, salt, tagId, siblings, leafData);
    const result = await this.zkp.prove({
      circuitId: 'dg13-field-reveal',
      privateInputs: inputs.privateInputs,
      publicInputs: inputs.publicInputs,
    });

    return {
      circuitId: 'dg13-field-reveal',
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
   * DG13 fields (e.g. fullName) are disclosed via `dg13-field-reveal` proofs —
   * the field value is in the proof's public outputs, cryptographically bound
   * to the SOD chain.
   *
   * DG2 (photo) is included as raw base64 with a `dg-map` proof for DG2
   * that binds its hash to the SOD eContent, proving authenticity.
   *
   * @param credential - The verifier's stored credential
   * @param credentialId - Storage ID for proof cache lookup
   * @param domain - Domain to use for proof generation
   * @param dg13FieldTagIds - DG13 field tag IDs to reveal (e.g. [2] for fullName)
   * @param includePhoto - Whether to include authenticated DG2 photo
   */
  async buildVerifierCredential(
    credential: MatchableCredential,
    credentialId: string,
    domain: Domain,
    dg13FieldTagIds: number[],
    includePhoto: boolean,
  ): Promise<PresentedCredential> {
    // Get or generate chain proofs
    const proofSet = await this.getOrGenerateProofs(credential, credentialId, domain);

    const proofs: CredentialProof[] = [];

    // Chain proofs — proves the credential is authentic
    for (const chain of [proofSet.sodVerify, proofSet.dgMap, proofSet.dg13Merklelize]) {
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

    // Field-reveal proofs for DG13 fields
    for (const tagId of dg13FieldTagIds) {
      const revealProof = await this.generateFieldRevealProof(proofSet, tagId);
      proofs.push({
        type: 'ZKPProof',
        conditionID: `field-reveal-${tagId}`,
        circuitId: revealProof.circuitId,
        proofSystem: 'ultrahonk',
        publicInputs: revealProof.publicInputs,
        publicOutputs: revealProof.publicOutputs,
        proofValue: revealProof.proofValue,
      } satisfies ZKPProof);
    }

    // Build credentialSubject — only ZKP-revealed data
    const subject: Record<string, unknown> = {};
    if (credential.credentialSubject['id'] !== undefined) {
      subject['id'] = credential.credentialSubject['id'];
    }

    // DG2 photo: include raw + dg-map proof for authenticity
    if (includePhoto) {
      const dg2 = credential.credentialSubject['dg2'];
      if (typeof dg2 === 'string') {
        subject['dg2'] = dg2;

        // Generate dg-map proof for DG2 (binds DG2 hash to SOD)
        const sodBase64 = this.extractSOD(credential);
        const { inputs: sodInputs, witness: sodWitness } = buildSodVerifyInputs(sodBase64, domain.hash);
        const econtentBinding = proofSet.sodVerify.publicOutputs['econtent_binding'] as string;

        // Build dg-map inputs for DG2 instead of DG13
        const dg2MapInputs = buildDgMapInputs(sodWitness, domain.hash, econtentBinding);
        // Override dg_number to 2
        dg2MapInputs.publicInputs.dg_number = 2;
        // Find DG2 offset in eContent
        const { findDGEntry } = await import('./sod-parser.js');
        const econtent = sodWitness.econtent;
        const dg2Offset = findDGEntry(new Uint8Array(econtent), 2);
        if (dg2Offset >= 0) {
          dg2MapInputs.privateInputs.dg_offset = dg2Offset;

          const dg2MapResult = await this.zkp.prove({
            circuitId: 'dg-map',
            privateInputs: dg2MapInputs.privateInputs,
            publicInputs: dg2MapInputs.publicInputs,
          });

          proofs.push({
            type: 'ZKPProof',
            conditionID: 'dg2-authenticity',
            circuitId: 'dg-map',
            proofSystem: 'ultrahonk',
            publicInputs: dg2MapInputs.publicInputs,
            publicOutputs: dg2MapResult.publicOutputs,
            proofValue: dg2MapResult.proofValue,
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
    dg13Inputs: { privateInputs: { raw_msg: number[]; dg_len: number; field_offsets: number[]; field_lengths: number[] } },
    salt: string,
  ): Promise<CachedMerkleTree> {
    const { raw_msg, field_offsets, field_lengths } = dg13Inputs.privateInputs;
    const fields = [];
    const leafDataArr: LeafData[] = [];

    for (let i = 0; i < 32; i++) {
      const offset = field_offsets[i]!;
      const length = field_lengths[i]!;

      const packedFields: [string, string, string, string] = ['0x0', '0x0', '0x0', '0x0'];
      for (let chunk = 0; chunk < 4; chunk++) {
        const chunkStart = chunk * 31;
        if (chunkStart < length) {
          const chunkEnd = Math.min(chunkStart + 31, length);
          const bytes = new Uint8Array(32);
          for (let b = chunkStart; b < chunkEnd; b++) {
            bytes[32 - (chunkEnd - b) + (b - chunkStart)] = raw_msg[offset + b]!;
          }
          packedFields[chunk] = '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }
      }

      fields.push({
        tagId: i + 1,
        length,
        packedFields,
        packedHash: '0x0',
      });

      leafDataArr.push({
        length: length.toString(),
        data: packedFields,
        packedHash: '0x0', // Will be set by the native builder
      });
    }

    const tree = await this.merkle.build(fields, salt);

    // Merge leaf data with the tree (packedHash comes from the builder)
    return { ...tree, leafData: leafDataArr };
  }

  private extractLeafData(
    proofSet: DomainProofSet,
    tagId: number,
  ): { length: string; data: string[]; packedHash: string } {
    const leaf = proofSet.merkleTree.leafData[tagId];
    if (!leaf) {
      throw new Error(`No leaf data for tagId ${tagId}`);
    }
    return { length: leaf.length, data: [...leaf.data], packedHash: leaf.packedHash };
  }
}
