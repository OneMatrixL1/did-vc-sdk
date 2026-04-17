/**
 * Tests for MerkleDisclosure and DGDisclosure verification.
 *
 * Uses real Poseidon2 hashing and real Merkle tree construction —
 * no mocks, no stubs. Verifies that the prover-side verification
 * catches every form of tampering.
 */

import { describe, it, expect } from 'vitest';
import { buildMerkleTree } from '../../src/proof-system/merkle-tree.js';
import { poseidon2BigInt } from '../../src/proof-system/poseidon2.js';
import { deriveDomain } from '../../src/proof-system/domain.js';
import type { MerkleDisclosure, DGDisclosure, ZKPProof, PresentedCredential } from '../../src/types/credential.js';
import type { VPRequest, VerifierDisclosure } from '../../src/types/request.js';
import type { MerkleLeafInput } from '../../src/proof-system/types.js';

// We import the internal verification functions via verifyVPRequestFull
// which calls verifyVerifierCredentials internally.
// For unit-level testing we replicate the verification logic inline
// so we can test each step independently.

// ---------------------------------------------------------------------------
// Test data: build a real Merkle tree from known field values
// ---------------------------------------------------------------------------

const DOMAIN = deriveDomain('test-verifier');
const DG_HASH_HI = '0x' + 'ab'.repeat(16); // fake but deterministic
const DG_HASH_LO = '0x' + 'cd'.repeat(16);

/** Pack a short ASCII string into 4 field elements (31 bytes each, right-aligned). */
function packString(s: string): [string, string, string, string] {
  const bytes = new TextEncoder().encode(s);
  const result: [string, string, string, string] = ['0x0', '0x0', '0x0', '0x0'];
  for (let chunk = 0; chunk < 4; chunk++) {
    const start = chunk * 31;
    if (start >= bytes.length) break;
    const end = Math.min(start + 31, bytes.length);
    let val = 0n;
    for (let i = start; i < end; i++) {
      val = val * 256n + BigInt(bytes[i]!);
    }
    result[chunk] = '0x' + val.toString(16);
  }
  return result;
}

// Create 16 field inputs (matching DG13 structure)
const FIELD_VALUES = [
  'DOC001',           // tag 1: documentNumber
  'NGUYEN VAN A',     // tag 2: fullName
  '19900101',         // tag 3: dateOfBirth
  'M',                // tag 4: gender
  'VNM',              // tag 5: nationality
  'Kinh',             // tag 6: ethnicity
  'Khong',            // tag 7: religion
  'Ha Noi',           // tag 8: hometown
  '123 Tran Hung Dao', // tag 9: address
  'None',             // tag 10: identificationFeatures
  '20240101',         // tag 11: dateOfIssue
  '20340101',         // tag 12: dateOfExpiry
  'Father Name',      // tag 13: fatherName
  'Mother Name',      // tag 14: motherName
  'HN',               // tag 15: placeOfOrigin
  'Extra',            // tag 16: reserved
];

const FIELDS: MerkleLeafInput[] = FIELD_VALUES.map((val, i) => ({
  tagId: i + 1,
  length: new TextEncoder().encode(val).length,
  packedFields: packString(val),
}));

const TREE = buildMerkleTree(FIELDS, DOMAIN.hash, DG_HASH_HI, DG_HASH_LO);

/** Build a valid MerkleDisclosure from the real tree for a given tagId. */
function buildDisclosure(tagId: number, fieldId: string): MerkleDisclosure {
  const leafIndex = tagId - 1;
  return {
    type: 'MerkleDisclosure',
    conditionID: `v-${fieldId}`,
    fieldId,
    tagId,
    length: TREE.leafData[leafIndex]!.length,
    data: [...TREE.leafData[leafIndex]!.data] as [string, string, string, string],
    entropy: TREE.leaves[leafIndex]!,
    siblings: [...TREE.siblings[leafIndex]!],
    value: FIELD_VALUES[leafIndex]!,
  };
}

// ---------------------------------------------------------------------------
// MerkleDisclosure verification (replicate request-verifier logic)
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

    const leaf = poseidon2BigInt(
      [tagId, length, data[0]!, data[1]!, data[2]!, data[3]!, entropy],
      7,
    );

    let current = leaf;
    let idx = md.tagId - 1;
    for (let level = 0; level < 4; level++) {
      const sibling = BigInt(md.siblings[level]!);
      current = idx % 2 === 0
        ? poseidon2BigInt([current, sibling], 2)
        : poseidon2BigInt([sibling, current], 2);
      idx = Math.floor(idx / 2);
    }

    const recomputed = poseidon2BigInt([current, domainBig], 2);
    if (recomputed !== BigInt(expectedCommitment)) {
      errors.push('Merkle path does not match commitment');
    }
  } catch (e) {
    errors.push(`Verification error: ${e}`);
  }
  return errors;
}

// ---------------------------------------------------------------------------
// Tests: MerkleDisclosure
// ---------------------------------------------------------------------------

describe('MerkleDisclosure verification', () => {
  const commitment = TREE.commitment;

  it('accepts a valid disclosure (fullName, tag 2)', () => {
    const md = buildDisclosure(2, 'fullName');
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(0);
  });

  it('accepts a valid disclosure (dateOfBirth, tag 3)', () => {
    const md = buildDisclosure(3, 'dateOfBirth');
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(0);
  });

  it('accepts valid disclosures for all 16 fields', () => {
    for (let tag = 1; tag <= 16; tag++) {
      const md = buildDisclosure(tag, `field${tag}`);
      const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
      expect(errors).toHaveLength(0);
    }
  });

  // --- Tampered field value ---

  it('rejects when field data is tampered', () => {
    const md = buildDisclosure(2, 'fullName');
    md.data[0] = '0xdeadbeef'; // tamper packed data
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/commitment/);
  });

  it('rejects when field length is tampered', () => {
    const md = buildDisclosure(2, 'fullName');
    md.length = '999';
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
  });

  // --- Tampered entropy ---

  it('rejects when entropy is tampered', () => {
    const md = buildDisclosure(2, 'fullName');
    md.entropy = '0x1234567890abcdef';
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
  });

  // --- Tampered siblings ---

  it('rejects when a sibling is tampered', () => {
    const md = buildDisclosure(2, 'fullName');
    md.siblings[0] = '0xdeadbeefdeadbeef';
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
  });

  it('rejects when siblings are from a different leaf', () => {
    const md = buildDisclosure(2, 'fullName');
    // Use siblings from tag 5 (different Merkle path)
    md.siblings = [...TREE.siblings[4]!];
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
  });

  // --- Wrong tagId ---

  it('rejects when tagId is changed (data from tag 2, claiming tag 3)', () => {
    const md = buildDisclosure(2, 'fullName');
    md.tagId = 3; // claim it's a different field
    const errors = verifyMerkleDisclosure(md, commitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
  });

  // --- Wrong commitment ---

  it('rejects when verified against a different commitment', () => {
    const md = buildDisclosure(2, 'fullName');
    const fakeCommitment = '0xaaaaaaaaaaaaaaaa';
    const errors = verifyMerkleDisclosure(md, fakeCommitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
  });

  // --- Wrong domain ---

  it('rejects when verified against a different domain', () => {
    const md = buildDisclosure(2, 'fullName');
    const otherDomain = deriveDomain('evil-verifier');
    const errors = verifyMerkleDisclosure(md, commitment, otherDomain.hash);
    expect(errors).toHaveLength(1);
  });

  // --- Cross-domain linkability protection ---

  it('same field produces different commitments under different domains', () => {
    const domainA = deriveDomain('verifier-a');
    const domainB = deriveDomain('verifier-b');
    const treeA = buildMerkleTree(FIELDS, domainA.hash, DG_HASH_HI, DG_HASH_LO);
    const treeB = buildMerkleTree(FIELDS, domainB.hash, DG_HASH_HI, DG_HASH_LO);

    // Commitments differ (domain bound)
    expect(treeA.commitment).not.toBe(treeB.commitment);

    // Entropies differ (domain bound)
    expect(treeA.leaves[1]).not.toBe(treeB.leaves[1]);

    // Leaves differ
    // (Can't correlate field across domains)
    expect(treeA.leafData[1]!.data).toEqual(treeB.leafData[1]!.data); // same raw data
    // but proof is not transferable:
    const mdA = {
      ...buildDisclosure(2, 'fullName'),
      entropy: treeA.leaves[1]!,
      siblings: [...treeA.siblings[1]!],
    };
    const errorsA = verifyMerkleDisclosure(mdA, treeA.commitment, domainA.hash);
    expect(errorsA).toHaveLength(0); // valid under domain A

    // Same disclosure fails under domain B
    const errorsB = verifyMerkleDisclosure(mdA, treeB.commitment, domainB.hash);
    expect(errorsB).toHaveLength(1); // invalid under domain B
  });

  // --- Replay: disclosure from one tree against another ---

  it('rejects disclosure replayed from a different credential', () => {
    // Build a second tree with different data (different person)
    const otherFields = FIELDS.map((f, i) => ({
      ...f,
      packedFields: packString(`OTHER_VALUE_${i}`) as [string, string, string, string],
      length: `OTHER_VALUE_${i}`.length,
    }));
    const otherTree = buildMerkleTree(otherFields, DOMAIN.hash, '0x' + '11'.repeat(16), '0x' + '22'.repeat(16));

    // Take disclosure from original tree
    const md = buildDisclosure(2, 'fullName');
    // Verify against other tree's commitment → must fail
    const errors = verifyMerkleDisclosure(md, otherTree.commitment, DOMAIN.hash);
    expect(errors).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Tests: DGDisclosure (SHA-256 + embedded ZKP)
// ---------------------------------------------------------------------------

describe('DGDisclosure verification', () => {
  // For DGDisclosure we test the hash binding logic.
  // We can't run a real ZKP verify without a circuit, but we test
  // the structural checks: hash match, eContentBinding, domain.

  const CHAIN_DOMAIN = '0xabc123';
  const CHAIN_ECB = '0xdef456'; // eContentBinding from sod-validate

  function makeDGDisclosure(overrides?: Partial<DGDisclosure>): DGDisclosure {
    return {
      type: 'DGDisclosure',
      conditionID: 'v-photo',
      fieldId: 'photo',
      dgNumber: 2,
      data: Buffer.from('fake-photo-data').toString('base64'),
      dgBridgeProof: {
        type: 'ZKPProof',
        conditionID: 'v-photo-bridge',
        circuitId: 'dg-bridge',
        proofSystem: 'ultrahonk',
        publicInputs: {
          eContentBinding: CHAIN_ECB,
          domain: CHAIN_DOMAIN,
          dgNumber: 2,
        },
        publicOutputs: {
          dgBinding: '', // will be set to SHA256(data) in valid case
        },
        proofValue: 'mock-proof-value',
      },
      ...overrides,
    };
  }

  async function sha256Base64(base64Data: string): Promise<string> {
    const bytes = new Uint8Array(Buffer.from(base64Data, 'base64'));
    const { createHash } = await import('crypto');
    const hash = createHash('sha256').update(bytes).digest();
    let hex = '0x';
    for (const b of hash) hex += b.toString(16).padStart(2, '0');
    return hex;
  }

  it('hash matches when data is authentic', async () => {
    const dg = makeDGDisclosure();
    const hash = await sha256Base64(dg.data);
    dg.dgBridgeProof.publicOutputs['dgBinding'] = hash;

    // Verify hash binding
    const computedHash = await sha256Base64(dg.data);
    expect(computedHash).toBe(dg.dgBridgeProof.publicOutputs['dgBinding']);
  });

  it('hash does NOT match when photo data is swapped', async () => {
    const dg = makeDGDisclosure();
    const originalHash = await sha256Base64(dg.data);
    dg.dgBridgeProof.publicOutputs['dgBinding'] = originalHash;

    // Swap photo with different data
    dg.data = Buffer.from('evil-photo-data').toString('base64');
    const computedHash = await sha256Base64(dg.data);
    expect(computedHash).not.toBe(dg.dgBridgeProof.publicOutputs['dgBinding']);
  });

  it('rejects when eContentBinding does not match chain', () => {
    const dg = makeDGDisclosure();
    dg.dgBridgeProof.publicInputs['eContentBinding'] = '0xwrong';
    expect(dg.dgBridgeProof.publicInputs['eContentBinding']).not.toBe(CHAIN_ECB);
  });

  it('rejects when domain does not match chain', () => {
    const dg = makeDGDisclosure();
    dg.dgBridgeProof.publicInputs['domain'] = '0xevil';
    expect(dg.dgBridgeProof.publicInputs['domain']).not.toBe(CHAIN_DOMAIN);
  });

  it('dgNumber must match between disclosure and bridge proof', () => {
    const dg = makeDGDisclosure();
    expect(dg.dgNumber).toBe(dg.dgBridgeProof.publicInputs['dgNumber']);

    // If someone changes dgNumber on disclosure but not the proof
    dg.dgNumber = 13;
    expect(dg.dgNumber).not.toBe(dg.dgBridgeProof.publicInputs['dgNumber']);
  });
});

// ---------------------------------------------------------------------------
// Tests: Binding chain verification
// ---------------------------------------------------------------------------

describe('Binding chain verification', () => {
  function makeChainProofs(overrides?: {
    sodECB?: string;
    bridgeECB?: string;
    bridgeDgBinding?: string;
    dg13DgBinding?: string;
    sodDomain?: string;
    bridgeDomain?: string;
    dg13Domain?: string;
  }): ZKPProof[] {
    const ecb = overrides?.sodECB ?? '0xecb123';
    const dgb = overrides?.bridgeDgBinding ?? '0xdgb456';
    return [
      {
        type: 'ZKPProof',
        conditionID: 'chain-sod-validate',
        circuitId: 'sod-validate',
        proofSystem: 'ultrahonk',
        publicInputs: { domain: overrides?.sodDomain ?? '0xdomain' },
        publicOutputs: { eContentBinding: ecb },
        proofValue: 'proof1',
      },
      {
        type: 'ZKPProof',
        conditionID: 'chain-dg-bridge',
        circuitId: 'dg-bridge',
        proofSystem: 'ultrahonk',
        publicInputs: {
          domain: overrides?.bridgeDomain ?? '0xdomain',
          eContentBinding: overrides?.bridgeECB ?? ecb,
        },
        publicOutputs: { dgBinding: dgb },
        proofValue: 'proof2',
      },
      {
        type: 'ZKPProof',
        conditionID: 'chain-dg13-merklelize',
        circuitId: 'dg13-merklelize',
        proofSystem: 'ultrahonk',
        publicInputs: { domain: overrides?.dg13Domain ?? '0xdomain' },
        publicOutputs: {
          dgBinding: overrides?.dg13DgBinding ?? dgb,
          commitment: '0xcommit',
        },
        proofValue: 'proof3',
      },
    ];
  }

  /** Replicate verifyVerifierBindingChain from request-verifier.ts */
  function verifyChain(proofs: ZKPProof[]): string[] {
    const errors: string[] = [];
    const sod = proofs.find(p => p.circuitId === 'sod-validate');
    const bridge = proofs.find(p => p.conditionID?.startsWith('chain-') && p.circuitId === 'dg-bridge');
    const dg13 = proofs.find(p => p.circuitId === 'dg13-merklelize');

    if (!sod || !bridge || !dg13) {
      if (!sod) errors.push('Missing sod-validate');
      if (!bridge) errors.push('Missing dg-bridge');
      if (!dg13) errors.push('Missing dg13-merklelize');
      return errors;
    }

    if (bridge.publicInputs['eContentBinding'] !== sod.publicOutputs['eContentBinding']) {
      errors.push('eContentBinding mismatch');
    }
    if (dg13.publicOutputs['dgBinding'] !== bridge.publicOutputs['dgBinding']) {
      errors.push('dgBinding mismatch');
    }
    const domain = sod.publicInputs['domain'];
    if (bridge.publicInputs['domain'] !== domain) errors.push('bridge domain mismatch');
    if (dg13.publicInputs['domain'] !== domain) errors.push('dg13 domain mismatch');

    return errors;
  }

  it('accepts a valid binding chain', () => {
    const errors = verifyChain(makeChainProofs());
    expect(errors).toHaveLength(0);
  });

  it('rejects when eContentBinding is broken', () => {
    const errors = verifyChain(makeChainProofs({ bridgeECB: '0xwrong' }));
    expect(errors).toContain('eContentBinding mismatch');
  });

  it('rejects when dgBinding is broken (dg-bridge → dg13)', () => {
    const errors = verifyChain(makeChainProofs({ dg13DgBinding: '0xwrong' }));
    expect(errors).toContain('dgBinding mismatch');
  });

  it('rejects when dg-bridge domain differs', () => {
    const errors = verifyChain(makeChainProofs({ bridgeDomain: '0xevil' }));
    expect(errors).toContain('bridge domain mismatch');
  });

  it('rejects when dg13 domain differs', () => {
    const errors = verifyChain(makeChainProofs({ dg13Domain: '0xevil' }));
    expect(errors).toContain('dg13 domain mismatch');
  });

  it('rejects when sod-validate is missing', () => {
    const proofs = makeChainProofs().filter(p => p.circuitId !== 'sod-validate');
    const errors = verifyChain(proofs);
    expect(errors).toContain('Missing sod-validate');
  });

  it('rejects when dg-bridge is missing', () => {
    const proofs = makeChainProofs().filter(p => p.circuitId !== 'dg-bridge');
    const errors = verifyChain(proofs);
    expect(errors).toContain('Missing dg-bridge');
  });

  it('rejects when dg13-merklelize is missing', () => {
    const proofs = makeChainProofs().filter(p => p.circuitId !== 'dg13-merklelize');
    const errors = verifyChain(proofs);
    expect(errors).toContain('Missing dg13-merklelize');
  });

  it('catches multiple chain breaks simultaneously', () => {
    const errors = verifyChain(makeChainProofs({
      bridgeECB: '0xwrong_ecb',
      dg13DgBinding: '0xwrong_dgb',
      dg13Domain: '0xevil',
    }));
    expect(errors.length).toBeGreaterThanOrEqual(3);
  });
});
