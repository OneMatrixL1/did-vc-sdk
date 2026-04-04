/**
 * End-to-end test: ZKP Merkle selective disclosure.
 *
 * Uses synthetic DG13 bytes (no real PII) that follow the exact same
 * ASN.1 BER structure as a Vietnamese CCCD:
 *   0x6D → 0x30 → { 0x02 0x01 version, 0x06 OID, 0x31 SET { fields } }
 *
 * Tests: provisioning → field mapping → Merkle construction
 *        → proof build → verify → tamper rejection.
 */

import { describe, it, expect } from 'vitest';

import { extractConditions } from '../../src/resolver/field-extractor.js';
import { fieldIdToLeafIndex, extractSiblingsForLeaf, isDg13Field } from '../../src/resolvers/zkp-field-mapping.js';
import { isZKPResolver, createZKPICAOSchemaResolver } from '../../src/resolvers/zkp-icao-schema-resolver.js';
import { verifyMerkleInclusion, verifyZKPProofs } from '../../src/verifier/zkp-verifier.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';

import type { MerkleWitnessData, MerkleFieldData } from '../../src/types/merkle.js';
import type { MerkleDisclosureProof } from '../../src/types/merkle.js';
import type { ZKPProof } from '../../src/types/credential.js';
import type { Poseidon2Hasher, ZKPProvider, ZKPVerifyParams } from '../../src/types/zkp-provider.js';
import type { VerifiablePresentation, PresentedCredential } from '../../src/types/response.js';
import type { VPRequest } from '../../src/types/request.js';

// ---------------------------------------------------------------------------
// Synthetic DG13 builder — constructs valid ASN.1 BER with fake identity
// ---------------------------------------------------------------------------

function buildField(tagId: number, value: string, stringTag: number = 0x0c): number[] {
  const valBytes = Array.from(Buffer.from(value, 'utf-8'));

  const inner = [0x02, 0x01, tagId, stringTag, valBytes.length, ...valBytes];

  return [0x30, inner.length, ...inner];
}

function buildSyntheticDG13(): Uint8Array {
  const fields = [
    buildField(1, '000000000001', 0x13),
    buildField(2, 'Test User A'),
    buildField(3, '15/06/1995', 0x13),
    buildField(4, 'Nam'),
    buildField(5, 'Viet Nam'),
    buildField(6, 'Kinh'),
    buildField(7, 'Khong'),
    buildField(8, 'Ha Noi'),
    buildField(9, '123 Test Street'),
    buildField(10, ''),
    buildField(11, '01/01/2024', 0x13),
    buildField(12, '01/01/2034'),
    buildField(13, 'Father / Mother'),
    buildField(14, ''),
    buildField(15, '999888777', 0x13),
    buildField(16, 'AABB00001111', 0x13),
  ];

  const allFields = fields.flat();

  const setBytes = [0x31, 0x82, (allFields.length >> 8) & 0xff, allFields.length & 0xff, ...allFields];

  const versionBytes = [0x02, 0x01, 0x01];

  const oidBytes = [0x06, 0x06, 0x28, 0xd3, 0x16, 0x01, 0x00, 0x08];

  const seqContent = [...versionBytes, ...oidBytes, ...setBytes];

  const seqBytes = [0x30, 0x82, (seqContent.length >> 8) & 0xff, seqContent.length & 0xff, ...seqContent];

  const rootContent = seqBytes;

  const rootBytes = [0x6d, 0x82, (rootContent.length >> 8) & 0xff, rootContent.length & 0xff, ...rootContent];

  return new Uint8Array(rootBytes);
}

const SYNTHETIC_DG13 = buildSyntheticDG13();

// ---------------------------------------------------------------------------
// TLV parser (mirrors zkp-provisioning.service.ts exactly)
// ---------------------------------------------------------------------------

const NUM_FIELDS = 32;

const RAW_MSG_SIZE = 700;

interface ParsedField { index: number; tagValue: number; offset: number; length: number }

interface TLV { tag: number; length: number; valueOffset: number; totalLength: number }

function parseTLV(buf: Uint8Array, offset: number, limit: number): TLV | null {
  if (offset >= limit) return null;

  const tag = buf[offset]!;

  let lenOffset = offset + 1;

  if (lenOffset >= limit) return null;

  const first = buf[lenOffset]!;

  let length: number;

  if (first < 0x80) {
    length = first;

    lenOffset += 1;
  } else {
    const n = first & 0x7f;

    if (lenOffset + 1 + n > limit) return null;

    length = 0;

    for (let i = 0; i < n; i++) {
      length = (length << 8) | buf[lenOffset + 1 + i]!;
    }

    lenOffset += 1 + n;
  }

  return { tag, length, valueOffset: lenOffset, totalLength: lenOffset - offset + length };
}

function parseDG13(dg13: Uint8Array) {
  const dgLen = dg13.length;

  const rawMsg = new Uint8Array(RAW_MSG_SIZE);

  rawMsg.set(dg13);

  const fieldOffsets = new Array<number>(NUM_FIELDS).fill(0);

  const fieldLengths = new Array<number>(NUM_FIELDS).fill(0);

  let pos = 0;

  const outer = parseTLV(rawMsg, pos, dgLen)!;

  pos = outer.valueOffset;

  const innerEnd = outer.valueOffset + outer.length;

  const innerSeq = parseTLV(rawMsg, pos, innerEnd)!;

  pos = innerSeq.valueOffset;

  const ver = parseTLV(rawMsg, pos, innerEnd)!;

  pos = ver.valueOffset + ver.length;

  const oid = parseTLV(rawMsg, pos, innerEnd)!;

  pos = oid.valueOffset + oid.length;

  const set = parseTLV(rawMsg, pos, innerEnd)!;

  pos = set.valueOffset;

  const setEnd = set.valueOffset + set.length;

  const fields: ParsedField[] = [];

  let idx = 0;

  while (pos < setEnd && idx < NUM_FIELDS) {
    const seq = parseTLV(rawMsg, pos, setEnd);

    if (!seq) break;

    let ip = seq.valueOffset;

    const seqEnd = seq.valueOffset + seq.length;

    const ti = parseTLV(rawMsg, ip, seqEnd);

    if (!ti) break;

    const tagValue = rawMsg[ti.valueOffset]!;

    ip = ti.valueOffset + ti.length;

    let vo: number, vl: number;

    if (ip >= seqEnd) {
      vo = ip + 2;

      vl = 0;
    } else {
      const vt = parseTLV(rawMsg, ip, seqEnd);

      if (!vt) break;

      vo = vt.valueOffset;

      vl = seqEnd - vt.valueOffset;
    }

    fields.push({ index: idx, tagValue, offset: vo, length: vl });

    idx++;

    pos += seq.totalLength;
  }

  for (const f of fields) {
    fieldOffsets[f.index] = f.offset;

    fieldLengths[f.index] = f.length;
  }

  let stubPos = dgLen;

  for (let i = fields.length; i < NUM_FIELDS; i++) {
    if (stubPos + 7 > RAW_MSG_SIZE) break;

    rawMsg[stubPos] = 0x30;
    rawMsg[stubPos + 1] = 0x05;
    rawMsg[stubPos + 2] = 0x02;
    rawMsg[stubPos + 3] = 0x01;
    rawMsg[stubPos + 4] = i + 1;
    rawMsg[stubPos + 5] = 0x0c;
    rawMsg[stubPos + 6] = 0x00;

    fieldOffsets[i] = stubPos + 7;

    fieldLengths[i] = 0;

    stubPos += 7;
  }

  return { rawMsg: Array.from(rawMsg), dgLen, fieldOffsets, fieldLengths, fields };
}

// ---------------------------------------------------------------------------
// Test Poseidon2 stub (deterministic, NOT cryptographic — structure test only)
// ---------------------------------------------------------------------------

const testPoseidon2: Poseidon2Hasher = {
  hash(inputs: bigint[], len: number): bigint {
    let acc = 0n;

    for (let i = 0; i < len && i < inputs.length; i++) {
      acc = (acc * 31n + inputs[i]! + 1n) % (2n ** 248n);
    }

    return acc;
  },
};

// ---------------------------------------------------------------------------
// Build MerkleWitnessData from parsed witness
// ---------------------------------------------------------------------------

function buildMerkleWitness(
  w: ReturnType<typeof parseDG13>,
  salt: string,
): MerkleWitnessData {
  const fieldData: MerkleFieldData[] = [];

  for (let i = 0; i < NUM_FIELDS; i++) {
    const offset = w.fieldOffsets[i]!;

    const length = w.fieldLengths[i]!;

    const rawBytes: number[] = [];

    for (let b = 0; b < length; b++) rawBytes.push(w.rawMsg[offset + b]!);

    const packedFields: string[] = [];

    for (let f = 0; f < 4; f++) {
      let felt = 0n;

      for (let b = 0; b < 31; b++) {
        const idx = f * 31 + b;

        if (idx < length) felt = felt * 256n + BigInt(w.rawMsg[offset + idx]!);
      }

      packedFields.push('0x' + felt.toString(16));
    }

    fieldData.push({ tagId: i + 1, length, packedFields, rawBytes });
  }

  const saltBig = BigInt(salt);

  const packedHash = testPoseidon2.hash(
    [0, 2, 5, 7, 12].flatMap(i => fieldData[i]!.packedFields.map(BigInt)),
    20,
  );

  const leaves = fieldData.map(fd =>
    '0x' + testPoseidon2.hash([BigInt(fd.tagId), BigInt(fd.length), ...fd.packedFields.map(BigInt), saltBig, packedHash], 8).toString(16),
  );

  const mkLevel = (prev: string[]) => {
    const out: string[] = [];

    for (let i = 0; i < prev.length; i += 2) {
      out.push('0x' + testPoseidon2.hash([BigInt(prev[i]!), BigInt(prev[i + 1]!)], 2).toString(16));
    }

    return out;
  };

  const l4 = mkLevel(leaves);

  const l3 = mkLevel(l4);

  const l2 = mkLevel(l3);

  const l1 = mkLevel(l2);

  const merkleRoot = '0x' + testPoseidon2.hash([BigInt(l1[0]!), BigInt(l1[1]!)], 2).toString(16);

  const commitment = '0x' + testPoseidon2.hash([BigInt(merkleRoot), saltBig], 2).toString(16);

  return { salt, packedHash: '0x' + packedHash.toString(16), leaves, levels: [l4, l3, l2, l1], merkleRoot, commitment, fieldData };
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('ZKP Selective Disclosure', () => {
  const witness = parseDG13(SYNTHETIC_DG13);

  const SALT = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd';

  const mw = buildMerkleWitness(witness, SALT);

  describe('1. DG13 Provisioning', () => {
    it('parses all 16 synthetic fields', () => {
      expect(witness.fields.length).toBe(16);
    });

    it('field[0] = tag 1, value "000000000001"', () => {
      const f = witness.fields[0]!;

      expect(f.tagValue).toBe(1);

      expect(Buffer.from(witness.rawMsg.slice(f.offset, f.offset + f.length)).toString()).toBe('000000000001');
    });

    it('field[1] = tag 2, value "Test User A"', () => {
      const f = witness.fields[1]!;

      expect(f.tagValue).toBe(2);

      expect(Buffer.from(witness.rawMsg.slice(f.offset, f.offset + f.length)).toString()).toBe('Test User A');
    });

    it('field[2] = tag 3, DOB "15/06/1995"', () => {
      const f = witness.fields[2]!;

      expect(f.tagValue).toBe(3);

      expect(Buffer.from(witness.rawMsg.slice(f.offset, f.offset + f.length)).toString()).toBe('15/06/1995');
    });

    it('pads to 32 fields', () => {
      for (let i = 16; i < 32; i++) expect(witness.fieldLengths[i]).toBe(0);
    });
  });

  describe('2. Field Mapping', () => {
    it('maps all field IDs correctly', () => {
      expect(fieldIdToLeafIndex('documentNumber')).toBe(0);

      expect(fieldIdToLeafIndex('fullName')).toBe(1);

      expect(fieldIdToLeafIndex('dateOfBirth')).toBe(2);

      expect(fieldIdToLeafIndex('gender')).toBe(3);

      expect(fieldIdToLeafIndex('nationality')).toBe(4);

      expect(fieldIdToLeafIndex('ethnicity')).toBe(5);

      expect(fieldIdToLeafIndex('religion')).toBe(6);

      expect(fieldIdToLeafIndex('hometown')).toBe(7);

      expect(fieldIdToLeafIndex('permanentAddress')).toBe(8);

      expect(fieldIdToLeafIndex('identifyingMarks')).toBe(9);

      expect(fieldIdToLeafIndex('issueDate')).toBe(10);

      expect(fieldIdToLeafIndex('expiryDate')).toBe(11);

      expect(fieldIdToLeafIndex('parentsInfo')).toBe(12);

      expect(fieldIdToLeafIndex('spouse')).toBe(13);

      expect(fieldIdToLeafIndex('oldIdNumber')).toBe(14);

      expect(fieldIdToLeafIndex('personalIdCode')).toBe(15);
    });

    it('aliases resolve to same index', () => {
      expect(fieldIdToLeafIndex('idNumber')).toBe(0);

      expect(fieldIdToLeafIndex('address')).toBe(8);
    });

    it('rejects removed aliases that would leak data', () => {
      expect(() => fieldIdToLeafIndex('age')).toThrow();

      expect(() => fieldIdToLeafIndex('fatherName')).toThrow();

      expect(() => fieldIdToLeafIndex('motherName')).toThrow();
    });

    it('rejects unknown fields', () => {
      expect(() => fieldIdToLeafIndex('photo')).toThrow();
    });

    it('isDg13Field works', () => {
      expect(isDg13Field('fullName')).toBe(true);

      expect(isDg13Field('photo')).toBe(false);
    });
  });

  describe('3. Merkle Witness', () => {
    it('32 leaves', () => {
      expect(mw.leaves.length).toBe(32);
    });

    it('levels: 16, 8, 4, 2', () => {
      expect(mw.levels.map(l => l.length)).toEqual([16, 8, 4, 2]);
    });

    it('fieldData[1] = fullName bytes', () => {
      expect(new TextDecoder().decode(new Uint8Array(mw.fieldData[1]!.rawBytes))).toBe('Test User A');
    });

    it('fieldData[2] = DOB bytes', () => {
      expect(new TextDecoder().decode(new Uint8Array(mw.fieldData[2]!.rawBytes))).toBe('15/06/1995');
    });

    it('extracts 5 siblings', () => {
      expect(extractSiblingsForLeaf(1, mw).length).toBe(5);
    });
  });

  describe('4. Merkle Disclosure Round-Trip', () => {
    function buildProof(fieldId: string, overrides?: Partial<MerkleDisclosureProof>): MerkleDisclosureProof {
      const li = fieldIdToLeafIndex(fieldId);

      const fd = mw.fieldData[li]!;

      return {
        type: 'MerkleDisclosureProof',
        conditionID: `cond-${fieldId}`,
        fieldIndex: li,
        fieldValue: new TextDecoder().decode(new Uint8Array(fd.rawBytes)),
        leafPreimage: { tagId: fd.tagId, length: fd.length, data: fd.packedFields, salt: mw.salt, packedHash: mw.packedHash },
        siblings: extractSiblingsForLeaf(li, mw),
        commitment: mw.commitment,
        ...overrides,
      };
    }

    it('verifies fullName', () => {
      expect(verifyMerkleInclusion(buildProof('fullName'), testPoseidon2)).toBe(true);
    });

    it('verifies dateOfBirth', () => {
      expect(verifyMerkleInclusion(buildProof('dateOfBirth'), testPoseidon2)).toBe(true);
    });

    it('verifies nationality', () => {
      expect(verifyMerkleInclusion(buildProof('nationality'), testPoseidon2)).toBe(true);
    });

    it('verifies documentNumber', () => {
      expect(verifyMerkleInclusion(buildProof('documentNumber'), testPoseidon2)).toBe(true);
    });

    it('REJECTS tampered data', () => {
      const p = buildProof('fullName');

      p.leafPreimage.data = ['0xdeadbeef', '0x0', '0x0', '0x0'];

      expect(verifyMerkleInclusion(p, testPoseidon2)).toBe(false);
    });

    it('REJECTS wrong commitment', () => {
      expect(verifyMerkleInclusion(buildProof('fullName', { commitment: '0xdeadbeef' }), testPoseidon2)).toBe(false);
    });

    it('REJECTS wrong sibling count', () => {
      expect(verifyMerkleInclusion(buildProof('fullName', { siblings: ['0x1', '0x2'] }), testPoseidon2)).toBe(false);
    });

    it('REJECTS malformed BigInt', () => {
      const p = buildProof('fullName');

      p.leafPreimage.data = ['not_a_number', '0x0', '0x0', '0x0'];

      expect(verifyMerkleInclusion(p, testPoseidon2)).toBe(false);
    });

    it('REJECTS fieldIndex out of range', () => {
      expect(verifyMerkleInclusion(buildProof('fullName', { fieldIndex: 99 }), testPoseidon2)).toBe(false);
    });
  });

  describe('5. Builder', () => {
    it('merkleDisclose builds correct condition', () => {
      const b = new DocumentRequestBuilder('doc', ['CCCDCredential']);

      b.setSchemaType('ICAO9303SOD-ZKP').setDisclosureMode('selective');

      b.zkp('c-chain', { circuitId: 'sod-dg13-chain', proofSystem: 'ultra_honk', publicInputs: {} });

      b.merkleDisclose('c-name', 'fullName', 'c-chain');

      const req = b.build();

      const { disclose, zkp } = extractConditions(req.conditions);

      expect(zkp[0]!.circuitId).toBe('sod-dg13-chain');

      expect(disclose[0]!.field).toBe('fullName');

      expect(disclose[0]!.merkleDisclosure).toEqual({ commitmentRef: 'c-chain' });
    });

    it('zkp-only has zero disclose', () => {
      const b = new DocumentRequestBuilder('doc', ['CCCDCredential']);

      b.setSchemaType('ICAO9303SOD-ZKP').setDisclosureMode('zkp-only');

      b.zkp('c-chain', { circuitId: 'sod-dg13-chain', proofSystem: 'ultra_honk', publicInputs: {} });

      b.zkp('c-age', { circuitId: 'date-lessthanorequal', proofSystem: 'ultra_honk', publicInputs: { threshold: 20080330 }, dependsOn: { commitment: 'c-chain' } });

      const { disclose, zkp } = extractConditions(b.build().conditions);

      expect(disclose.length).toBe(0);

      expect(zkp.length).toBe(2);
    });
  });

  describe('6. Resolver', () => {
    it('isZKPResolver = true', () => {
      expect(isZKPResolver(createZKPICAOSchemaResolver())).toBe(true);
    });

    it('type = ICAO9303SOD-ZKP', () => {
      expect(createZKPICAOSchemaResolver().type).toBe('ICAO9303SOD-ZKP');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // verifyZKPProofs integration tests
  // ═══════════════════════════════════════════════════════════════════════════

  function mockZKPProvider(verifyFn?: (p: ZKPVerifyParams) => boolean): ZKPProvider {
    return {
      prove: async () => ({ proofValue: 'mock-proof', publicOutputs: {} }),
      verify: async (params) => (verifyFn ?? (() => true))(params),
    };
  }

  const stubRequest = { id: 'stub', nonce: 'n', version: '1.0', name: 'x', verifier: 'did:x', verifierName: 'x', verifierUrl: 'https://x', createdAt: '2026-01-01T00:00:00Z', expiresAt: '2099-01-01T00:00:00Z', type: ['VerifiablePresentationRequest'] as ['VerifiablePresentationRequest'], '@context': [], rules: { type: 'DocumentRequest' as const, docRequestID: 'd', docType: ['X'], schemaType: 's', conditions: [] } } satisfies VPRequest;

  function stubVP(credentials: PresentedCredential[]): VerifiablePresentation {
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      holder: 'did:x',
      verifier: 'did:y',
      requestId: 'stub',
      requestNonce: 'n',
      verifiableCredential: credentials,
      presentationSubmission: [],
      proof: { type: 'mock', verificationMethod: 'did:x#k', proofPurpose: 'authentication' as const, challenge: 'n', domain: 'x' },
    };
  }

  function stubCred(proofs: (ZKPProof | MerkleDisclosureProof)[]): PresentedCredential {
    return {
      type: ['VerifiableCredential'],
      issuer: 'did:issuer',
      credentialSubject: {},
      proof: proofs,
    };
  }

  function zkpProof(overrides?: Partial<ZKPProof>): ZKPProof {
    return {
      type: 'ZKPProof',
      conditionID: 'c-test',
      circuitId: 'test-circuit',
      proofSystem: 'ultra_honk',
      publicInputs: {},
      publicOutputs: {},
      proofValue: 'mock-proof-value',
      ...overrides,
    };
  }

  function merkleProof(fieldId: string, overrides?: Partial<MerkleDisclosureProof>): MerkleDisclosureProof {
    const li = fieldIdToLeafIndex(fieldId);

    const fd = mw.fieldData[li]!;

    return {
      type: 'MerkleDisclosureProof',
      conditionID: `cond-${fieldId}`,
      fieldIndex: li,
      fieldValue: new TextDecoder().decode(new Uint8Array(fd.rawBytes)),
      leafPreimage: { tagId: fd.tagId, length: fd.length, data: fd.packedFields, salt: mw.salt, packedHash: mw.packedHash },
      siblings: extractSiblingsForLeaf(li, mw),
      commitment: mw.commitment,
      ...overrides,
    };
  }

  // -------------------------------------------------------------------------
  // 7. verifyZKPProofs — Normal Cases
  // -------------------------------------------------------------------------

  describe('7. verifyZKPProofs — Normal Cases', () => {
    it('passes with empty credentials array', async () => {
      const r = await verifyZKPProofs(stubRequest, stubVP([]), testPoseidon2);

      expect(r.verified).toBe(true);

      expect(r.proofResults).toHaveLength(0);
    });

    it('passes with credential that has no proof', async () => {
      const cred: PresentedCredential = { type: ['VC'], issuer: 'did:x', credentialSubject: {} };

      const r = await verifyZKPProofs(stubRequest, stubVP([cred]), testPoseidon2);

      expect(r.verified).toBe(true);

      expect(r.proofResults).toHaveLength(0);
    });

    it('passes with a single valid ZKPProof', async () => {
      const provider = mockZKPProvider();

      const proof = zkpProof({ conditionID: 'c-sod' });

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);

      expect(r.proofResults).toHaveLength(1);

      expect(r.proofResults[0]!.conditionID).toBe('c-sod');
    });

    it('passes with a single valid MerkleDisclosureProof', async () => {
      const proof = merkleProof('fullName');

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2);

      expect(r.verified).toBe(true);

      expect(r.proofResults[0]!.type).toBe('MerkleDisclosureProof');
    });

    it('passes with ZKP chain → MerkleDisclosure via dependsOn', async () => {
      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: mw.commitment } });

      const disclosure = merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([chain, disclosure])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);

      expect(r.proofResults).toHaveLength(2);
    });

    it('passes with multiple MerkleDisclosures sharing one ZKP commitment', async () => {
      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: mw.commitment } });

      const d1 = merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } });

      const d2 = merkleProof('dateOfBirth', { dependsOn: { commitment: 'c-chain' } });

      const d3 = merkleProof('nationality', { dependsOn: { commitment: 'c-chain' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([chain, d1, d2, d3])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);

      expect(r.proofResults).toHaveLength(4);
    });

    it('stores publicOutputs only after successful verification', async () => {
      const first = zkpProof({ conditionID: 'c-first', publicOutputs: { binding: '0xaaa' } });

      const second = zkpProof({
        conditionID: 'c-second',
        publicInputs: { binding: '0xaaa' },
        publicOutputs: { commitment: '0xbbb' },
        dependsOn: { binding: 'c-first' },
      });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([first, second])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);

      expect(r.proofResults.every(p => p.verified)).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // 8. checkDependsOn — Dependency Validation
  // -------------------------------------------------------------------------

  describe('8. checkDependsOn — Dependency Validation', () => {
    it('passes when dependsOn is undefined', async () => {
      const proof = zkpProof({ conditionID: 'c-root' });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);
    });

    it('fails when dependsOn references non-existent conditionID', async () => {
      const proof = zkpProof({ conditionID: 'c-orphan', dependsOn: { commitment: 'does-not-exist' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[0]!.error).toContain('not found or not verified');
    });

    it('fails when referenced proof has no matching output key', async () => {
      const first = zkpProof({ conditionID: 'c-first', publicOutputs: { otherKey: '0x1' } });

      const second = zkpProof({ conditionID: 'c-second', dependsOn: { commitment: 'c-first' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([first, second])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('has no output "commitment"');
    });

    it('fails when this proof has no input/output matching dependency key', async () => {
      const first = zkpProof({ conditionID: 'c-first', publicOutputs: { commitment: '0xabc' } });

      const second = zkpProof({ conditionID: 'c-second', publicInputs: {}, publicOutputs: {}, dependsOn: { commitment: 'c-first' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([first, second])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('has no input/output "commitment"');
    });

    it('fails when dependency values do not match', async () => {
      const first = zkpProof({ conditionID: 'c-first', publicOutputs: { commitment: '0xabc' } });

      const second = zkpProof({ conditionID: 'c-second', publicInputs: { commitment: '0xdifferent' }, dependsOn: { commitment: 'c-first' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([first, second])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('Dependency mismatch');
    });

    it('String coercion — numeric and string of same value match', async () => {
      const first = zkpProof({ conditionID: 'c-first', publicOutputs: { val: 123 as unknown } });

      const second = zkpProof({ conditionID: 'c-second', publicInputs: { val: '123' }, dependsOn: { val: 'c-first' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([first, second])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);
    });

    it('checks publicOutputs as fallback when key not in publicInputs', async () => {
      const first = zkpProof({ conditionID: 'c-first', publicOutputs: { binding: '0xaaa' } });

      const second = zkpProof({ conditionID: 'c-second', publicInputs: {}, publicOutputs: { binding: '0xaaa' }, dependsOn: { binding: 'c-first' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([first, second])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // 9. verifyZKPProofSingle — Provider Failures
  // -------------------------------------------------------------------------

  describe('9. verifyZKPProofSingle — Provider Failures', () => {
    it('fails when no ZKPProvider is supplied', async () => {
      const proof = zkpProof();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2, undefined);

      expect(r.verified).toBe(false);

      expect(r.proofResults[0]!.error).toBe('No ZKPProvider available');
    });

    it('fails when provider.verify returns false', async () => {
      const provider = mockZKPProvider(() => false);

      const proof = zkpProof({ circuitId: 'bad-circuit' });

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[0]!.error).toContain('ZKP proof verification failed');
    });

    it('does not store outputs for a failed ZKPProof', async () => {
      const provider = mockZKPProvider((p) => p.circuitId !== 'fail-circuit');

      const first = zkpProof({ conditionID: 'c-fail', circuitId: 'fail-circuit', publicOutputs: { commitment: '0x1' } });

      const second = zkpProof({ conditionID: 'c-depend', dependsOn: { commitment: 'c-fail' } });

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([first, second])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[0]!.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('not found or not verified');
    });

    it('provider.verify receives correct params', async () => {
      let captured: ZKPVerifyParams | undefined;

      const provider = mockZKPProvider((p) => { captured = p; return true; });

      const proof = zkpProof({
        circuitId: 'my-circuit',
        proofValue: 'my-proof',
        publicInputs: { salt: '0x1' },
        publicOutputs: { binding: '0x2' },
      });

      await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2, provider);

      expect(captured!.circuitId).toBe('my-circuit');

      expect(captured!.proofValue).toBe('my-proof');

      expect(captured!.publicInputs).toEqual({ salt: '0x1' });

      expect(captured!.publicOutputs).toEqual({ binding: '0x2' });
    });
  });

  // -------------------------------------------------------------------------
  // 10. verifyMerkleProofSingle — Dependency Chain
  // -------------------------------------------------------------------------

  describe('10. verifyMerkleProofSingle — Dependency Chain', () => {
    it('passes Merkle proof with valid dependsOn', async () => {
      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: mw.commitment } });

      const disclosure = merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([chain, disclosure])]), testPoseidon2, provider);

      expect(r.proofResults[1]!.verified).toBe(true);
    });

    it('fails Merkle proof when dependsOn commitment mismatches', async () => {
      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: '0xwrong' } });

      const disclosure = merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([chain, disclosure])]), testPoseidon2, provider);

      expect(r.proofResults[1]!.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('Dependency mismatch');
    });

    it('fails Merkle proof when tree inclusion is invalid', async () => {
      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: '0xdeadbeef' } });

      const disclosure = merkleProof('fullName', { commitment: '0xdeadbeef', dependsOn: { commitment: 'c-chain' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([chain, disclosure])]), testPoseidon2, provider);

      expect(r.proofResults[1]!.verified).toBe(false);

      expect(r.proofResults[1]!.error).toBe('Merkle inclusion proof invalid');
    });
  });

  // -------------------------------------------------------------------------
  // 11. Cross-Credential Isolation
  // -------------------------------------------------------------------------

  describe('11. Cross-Credential Isolation', () => {
    it('resets outputsMap per credential — cross-credential dependsOn fails', async () => {
      const cred0 = stubCred([zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: mw.commitment } })]);

      const cred1 = stubCred([merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } })]);

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([cred0, cred1]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('not found or not verified');
    });

    it('allows same conditionID in different credentials without collision', async () => {
      const cred0 = stubCred([zkpProof({ conditionID: 'c-chain', publicOutputs: { val: '0x1' } })]);

      const cred1 = stubCred([zkpProof({ conditionID: 'c-chain', publicOutputs: { val: '0x2' } })]);

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([cred0, cred1]), testPoseidon2, provider);

      expect(r.verified).toBe(true);

      expect(r.proofResults).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // 12. Proof Ordering
  // -------------------------------------------------------------------------

  describe('12. Proof Ordering', () => {
    it('fails when dependent proof appears before its dependency', async () => {
      const disclosure = merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } });

      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: mw.commitment } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([disclosure, chain])]), testPoseidon2, provider);

      expect(r.proofResults[0]!.verified).toBe(false);

      expect(r.proofResults[0]!.error).toContain('not found or not verified');
    });

    it('passes when proofs are in correct dependency order', async () => {
      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { commitment: mw.commitment } });

      const disclosure = merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([chain, disclosure])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // 13. Attack Vectors — Security Cases
  // -------------------------------------------------------------------------

  describe('13. Attack Vectors — Security Cases', () => {
    it('LIMITATION: Merkle proof without dependsOn passes tree-math check (verifier must enforce chain)', async () => {
      const proof = merkleProof('fullName');

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2);

      expect(r.verified).toBe(true);
    });

    it('delegates circuit validation to provider — SDK does not enforce circuitId match against request', async () => {
      const provider = mockZKPProvider(() => true);

      const proof = zkpProof({ circuitId: 'trivial-always-true' });

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2, provider);

      expect(r.verified).toBe(true);
    });

    it('REJECTS fieldValue that does not match leafPreimage.data', async () => {
      const proof = merkleProof('fullName', { fieldValue: 'COMPLETELY FAKE NAME' });

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([proof])]), testPoseidon2);

      expect(r.verified).toBe(false);

      expect(r.proofResults[0]!.error).toContain('fieldValue does not match');
    });

    it('REJECTS dependsOn pointing to an unverified (failed) proof', async () => {
      const provider = mockZKPProvider(() => false);

      const failed = zkpProof({ conditionID: 'c-bad', publicOutputs: { commitment: mw.commitment } });

      const disclosure = merkleProof('fullName', { dependsOn: { commitment: 'c-bad' } });

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([failed, disclosure])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('not found or not verified');
    });

    it('REJECTS Merkle dependsOn binding to wrong output key name', async () => {
      const chain = zkpProof({ conditionID: 'c-chain', publicOutputs: { merkleRoot: '0xaaa' } });

      const disclosure = merkleProof('fullName', { dependsOn: { commitment: 'c-chain' } });

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([chain, disclosure])]), testPoseidon2, provider);

      expect(r.verified).toBe(false);

      expect(r.proofResults[1]!.error).toContain('has no output "commitment"');
    });
  });

  // -------------------------------------------------------------------------
  // 14. normalizeProofs Edge Cases
  // -------------------------------------------------------------------------

  describe('14. normalizeProofs Edge Cases', () => {
    it('handles proof as a single object (not array)', async () => {
      const cred: PresentedCredential = {
        type: ['VC'],
        issuer: 'did:x',
        credentialSubject: {},
        proof: zkpProof({ conditionID: 'c-single' }),
      };

      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([cred]), testPoseidon2, provider);

      expect(r.proofResults).toHaveLength(1);

      expect(r.proofResults[0]!.conditionID).toBe('c-single');
    });

    it('handles proof as an array', async () => {
      const provider = mockZKPProvider();

      const r = await verifyZKPProofs(stubRequest, stubVP([stubCred([zkpProof({ conditionID: 'a' }), zkpProof({ conditionID: 'b' })])]), testPoseidon2, provider);

      expect(r.proofResults).toHaveLength(2);
    });

    it('handles credential with proof = undefined', async () => {
      const cred: PresentedCredential = { type: ['VC'], issuer: 'did:x', credentialSubject: {} };

      const r = await verifyZKPProofs(stubRequest, stubVP([cred]), testPoseidon2);

      expect(r.verified).toBe(true);

      expect(r.proofResults).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // 15. deriveCredentialWithZKP — Proof Construction
  // -------------------------------------------------------------------------

  describe('15. deriveCredentialWithZKP — Proof Construction', () => {
    it('throws when no ZKPProvider is available', async () => {
      const resolver = createZKPICAOSchemaResolver();

      const cred = { type: ['VC'] as string[], issuer: 'did:x', credentialSubject: {} };

      const zkpConds = [{ type: 'DocumentCondition' as const, conditionID: 'c-sod', operator: 'zkp' as const, circuitId: 'sod-validate', proofSystem: 'ultra_honk' as const }];

      await expect(resolver.deriveCredentialWithZKP(cred, [], zkpConds, mw, { nonce: 'n' })).rejects.toThrow('ZKPProvider required');
    });

    it('wraps prove result into ZKPProof with dependsOn from condition', async () => {
      const provider: ZKPProvider = {
        prove: async () => ({ proofValue: 'proof-data', publicOutputs: { binding: '0x1' } }),
        verify: async () => true,
      };

      const resolver = createZKPICAOSchemaResolver(provider);

      const cred = { type: ['VC'] as string[], issuer: 'did:x', credentialSubject: {} };

      const zkpConds = [{
        type: 'DocumentCondition' as const,
        conditionID: 'c-dg13',
        operator: 'zkp' as const,
        circuitId: 'dg13-merklelize',
        proofSystem: 'ultra_honk' as const,
        dependsOn: { binding: 'c-sod' },
      }];

      const result = await resolver.deriveCredentialWithZKP(cred, [], zkpConds, mw, { nonce: 'n', zkpProvider: provider });

      const proofs = result.proof as ZKPProof[];

      expect(proofs[0]!.type).toBe('ZKPProof');

      expect(proofs[0]!.conditionID).toBe('c-dg13');

      expect(proofs[0]!.circuitId).toBe('dg13-merklelize');

      expect(proofs[0]!.proofValue).toBe('proof-data');

      expect(proofs[0]!.dependsOn).toEqual({ binding: 'c-sod' });
    });

    it('populates credentialSubject.dg13 with Merkle-disclosed fields', async () => {
      const provider: ZKPProvider = {
        prove: async () => ({ proofValue: 'p', publicOutputs: {} }),
        verify: async () => true,
      };

      const resolver = createZKPICAOSchemaResolver(provider);

      const cred = { type: ['VC'] as string[], issuer: 'did:x', credentialSubject: {} };

      const disclose = [
        { type: 'DocumentCondition' as const, conditionID: 'c-name', field: 'fullName', operator: 'disclose' as const, merkleDisclosure: { commitmentRef: 'c-chain' } },
        { type: 'DocumentCondition' as const, conditionID: 'c-dob', field: 'dateOfBirth', operator: 'disclose' as const, merkleDisclosure: { commitmentRef: 'c-chain' } },
      ];

      const result = await resolver.deriveCredentialWithZKP(cred, disclose, [], mw, { nonce: 'n', zkpProvider: provider });

      const dg13 = result.credentialSubject.dg13 as Record<string, string>;

      expect(dg13.fullName).toBe('Test User A');

      expect(dg13.dateOfBirth).toBe('15/06/1995');
    });
  });

  // -------------------------------------------------------------------------
  // 16. deriveCredentialWithZKP — Mixed Mode Validation
  // -------------------------------------------------------------------------

  describe('16. deriveCredentialWithZKP — Mixed Mode Validation', () => {
    it('throws when mixing Merkle and non-Merkle disclosure for DG13', async () => {
      const provider: ZKPProvider = {
        prove: async () => ({ proofValue: 'p', publicOutputs: {} }),
        verify: async () => true,
      };

      const resolver = createZKPICAOSchemaResolver(provider);

      const cred = { type: ['VC'] as string[], issuer: 'did:x', credentialSubject: { dg13: 'blob' } };

      const disclose = [
        { type: 'DocumentCondition' as const, conditionID: 'c1', field: 'fullName', operator: 'disclose' as const, merkleDisclosure: { commitmentRef: 'c-chain' } },
        { type: 'DocumentCondition' as const, conditionID: 'c2', field: 'dateOfBirth', operator: 'disclose' as const },
      ];

      await expect(resolver.deriveCredentialWithZKP(cred, disclose, [], mw, { nonce: 'n', zkpProvider: provider })).rejects.toThrow('Cannot mix Merkle and non-Merkle');
    });

    it('throws when merkleDisclosure references a non-DG13 field', async () => {
      const provider: ZKPProvider = {
        prove: async () => ({ proofValue: 'p', publicOutputs: {} }),
        verify: async () => true,
      };

      const resolver = createZKPICAOSchemaResolver(provider);

      const cred = { type: ['VC'] as string[], issuer: 'did:x', credentialSubject: {} };

      const disclose = [
        { type: 'DocumentCondition' as const, conditionID: 'c1', field: 'photo', operator: 'disclose' as const, merkleDisclosure: { commitmentRef: 'c-chain' } },
      ];

      await expect(resolver.deriveCredentialWithZKP(cred, disclose, [], mw, { nonce: 'n', zkpProvider: provider })).rejects.toThrow('not a DG13 field');
    });

    it('builds MerkleDisclosureProof with dependsOn from commitmentRef', async () => {
      const provider: ZKPProvider = {
        prove: async () => ({ proofValue: 'p', publicOutputs: {} }),
        verify: async () => true,
      };

      const resolver = createZKPICAOSchemaResolver(provider);

      const cred = { type: ['VC'] as string[], issuer: 'did:x', credentialSubject: {} };

      const disclose = [
        { type: 'DocumentCondition' as const, conditionID: 'c-name', field: 'fullName', operator: 'disclose' as const, merkleDisclosure: { commitmentRef: 'c-dg13' } },
      ];

      const result = await resolver.deriveCredentialWithZKP(cred, disclose, [], mw, { nonce: 'n', zkpProvider: provider });

      const proofs = result.proof as MerkleDisclosureProof[];

      const mp = proofs.find(p => p.type === 'MerkleDisclosureProof')!;

      expect(mp.dependsOn).toEqual({ commitment: 'c-dg13' });
    });
  });
});
