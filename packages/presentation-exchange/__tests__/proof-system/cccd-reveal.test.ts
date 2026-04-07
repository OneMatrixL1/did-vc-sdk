import { describe, it, expect, beforeAll } from 'vitest';
import { Buffer } from 'buffer';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { matchCredentials } from '../../src/resolver/matcher.js';
import { createICAO9303ProofSystem } from '../../src/proof-system/icao9303-proof-system.js';
import { createWasmZKPProvider, createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { Poseidon2Hasher } from '@1matrix/zkp-provider';
import type { MatchableCredential } from '../../src/types/credential.js';
import type { ICAO9303ZKPProofBundle } from '../../src/types/icao-proof-bundle.js';
import type { DocumentRequestMatch } from '../../src/types/matching.js';
import type { ZKPProvider } from '../../src/types/zkp-provider.js';
import { fieldIdToTagId } from '../../src/resolvers/zkp-field-mapping.js';

// ---------------------------------------------------------------------------
// Build real DG13 TLV bytes (Vietnamese CCCD format)
// Pattern: 0x30 [seqLen] 0x02 0x01 [tagNum] 0x0C [strLen] [UTF-8 value]
// ---------------------------------------------------------------------------

function encodeDG13Field(tagNum: number, value: string): Buffer {
  const strBuf = Buffer.from(value, 'utf-8');
  const intTag = Buffer.from([0x02, 0x01, tagNum]);
  const strTag = Buffer.from([0x0C, strBuf.length]);
  const inner = Buffer.concat([intTag, strTag, strBuf]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

const DG13_FIELDS: Record<number, string> = {
  1: '012345678901',     // documentNumber
  2: 'Nguyen Thi B',     // fullName
  3: '15/03/1995',        // dateOfBirth
  4: 'Nu',                // gender
  5: 'Viet Nam',          // nationality
  6: 'Kinh',              // ethnicity
  7: 'Khong',             // religion
  8: 'Ha Noi',            // hometown
  9: '123 Duong Lang',    // permanentAddress
  10: 'Khong',            // identifyingMarks
  11: '01/01/2024',       // issueDate
  12: '01/01/2034',       // expiryDate
  13: 'Nguyen Van A',     // parentsInfo
};

function buildDG13Bytes(): Uint8Array {
  const parts = Object.entries(DG13_FIELDS)
    .sort(([a], [b]) => Number(a) - Number(b))
    .map(([tag, val]) => encodeDG13Field(Number(tag), val));
  return new Uint8Array(Buffer.concat(parts));
}

// ---------------------------------------------------------------------------
// Real crypto objects — initialized once
// ---------------------------------------------------------------------------

let poseidon2: Poseidon2Hasher;
let zkpProvider: ZKPProvider & { destroy(): void };

beforeAll(async () => {
  poseidon2 = await createPoseidon2Hasher();
  zkpProvider = await createWasmZKPProvider();
}, 60000);

// ---------------------------------------------------------------------------
// Tests — REAL Poseidon2, REAL Merkle tree, REAL circuit proving
// ---------------------------------------------------------------------------

describe('CCCD field reveal — real ZKP', () => {
  it('builds real Merkle tree from DG13 bytes with Poseidon2', () => {
    const dg13Bytes = buildDG13Bytes();

    // Pack fields same way the circuit does
    const fields = Array.from({ length: 32 }, (_, i) => {
      const tagId = i + 1;
      const value = DG13_FIELDS[tagId];
      const valueBytes = value ? Buffer.from(value, 'utf-8') : Buffer.alloc(0);

      // Pack into 4 field elements of 31 bytes each
      const packedFields: bigint[] = [];
      for (let f = 0; f < 4; f++) {
        let felt = 0n;
        for (let b = 0; b < 31; b++) {
          const byteIdx = f * 31 + b;
          if (byteIdx < valueBytes.length) {
            felt = felt * 256n + BigInt(valueBytes[byteIdx]!);
          }
        }
        packedFields.push(felt);
      }

      return { tagId, length: valueBytes.length, packedFields, packedHash: 0n };
    });

    // Compute packed_hash from immutable fields (indices 0, 2, 5, 7, 12)
    const immutableIndices = [0, 2, 5, 7, 12];
    const immutablePacked: bigint[] = [];
    for (const idx of immutableIndices) {
      immutablePacked.push(...fields[idx]!.packedFields);
    }
    const packedHash = poseidon2.hash(immutablePacked, 20);
    for (const f of fields) f.packedHash = packedHash;

    const salt = 42n;
    const tree = buildMerkleTree(fields, salt, poseidon2);

    // Tree is real
    expect(tree.root).not.toBe(0n);
    expect(tree.commitment).not.toBe(0n);
    expect(tree.leaves).toHaveLength(32);

    // Siblings are real Poseidon2 hashes
    const siblings = tree.getSiblings(3); // gender (tag 4, index 3)
    expect(siblings).toHaveLength(5);
    for (const s of siblings) {
      expect(typeof s).toBe('bigint');
    }
  });

  it('proves and verifies dg13-field-reveal circuit for gender field', async () => {
    const tagId = fieldIdToTagId('gender'); // 4
    const leafIndex = tagId - 1; // 3

    // 1. Build all 32 fields — same packing as the circuit
    const fields = Array.from({ length: 32 }, (_, i) => {
      const tid = i + 1;
      const value = DG13_FIELDS[tid];
      const valueBytes = value ? Buffer.from(value, 'utf-8') : Buffer.alloc(0);
      const pf: bigint[] = [];
      for (let f = 0; f < 4; f++) {
        let felt = 0n;
        for (let b = 0; b < 31; b++) {
          const byteIdx = f * 31 + b;
          if (byteIdx < valueBytes.length) {
            felt = felt * 256n + BigInt(valueBytes[byteIdx]!);
          }
        }
        pf.push(felt);
      }
      return { tagId: tid, length: valueBytes.length, packedFields: pf, packedHash: 0n };
    });

    // 2. Compute packed_hash from immutable fields
    const immutableIndices = [0, 2, 5, 7, 12];
    const immutablePacked: bigint[] = [];
    for (const idx of immutableIndices) {
      immutablePacked.push(...fields[idx]!.packedFields);
    }
    const packedHash = poseidon2.hash(immutablePacked, 20);
    for (const f of fields) f.packedHash = packedHash;

    // 3. Build real Merkle tree
    const salt = 12345n;
    const tree = buildMerkleTree(fields, salt, poseidon2);
    const commitment = tree.commitment;
    const siblings = tree.getSiblings(leafIndex);

    // 4. Get the EXACT field data that the tree used for this leaf
    const genderField = fields[leafIndex]!;

    // 5. REAL circuit prove — inputs match exactly what the tree used
    const toHex = (v: bigint) => '0x' + v.toString(16);

    const proveResult = await zkpProvider.prove({
      circuitId: 'dg13-field-reveal',
      privateInputs: {
        siblings: siblings.map(toHex),
        length: toHex(BigInt(genderField.length)),
        data: genderField.packedFields.map(toHex),
        packed_hash: toHex(packedHash),
      },
      publicInputs: {
        commitment: toHex(commitment),
        salt: toHex(salt),
        tag_id: toHex(BigInt(tagId)),
      },
    });

    expect(proveResult.proofValue).toBeTruthy();
    expect(proveResult.proofValue.length).toBeGreaterThan(10);

    // 5. REAL circuit verify
    const verifyResult = await zkpProvider.verify({
      circuitId: 'dg13-field-reveal',
      proofValue: proveResult.proofValue,
      publicInputs: {
        commitment: toHex(commitment),
        salt: toHex(salt),
        tag_id: toHex(BigInt(tagId)),
      },
      publicOutputs: proveResult.publicOutputs,
    });

    expect(verifyResult).toBe(true);

    // 6. Read the revealed field value from public outputs
    // Circuit returns [length, data[0], data[1], data[2], data[3]]
    const outputs = proveResult.publicOutputs;
    expect(outputs).toBeDefined();
  }, 120000);

  it('rejects proof with wrong commitment', async () => {
    const genderBytes = Buffer.from('Nu', 'utf-8');
    const tagId = fieldIdToTagId('gender');

    const packedFields: bigint[] = [];
    for (let f = 0; f < 4; f++) {
      let felt = 0n;
      for (let b = 0; b < 31; b++) {
        const byteIdx = f * 31 + b;
        if (byteIdx < genderBytes.length) {
          felt = felt * 256n + BigInt(genderBytes[byteIdx]!);
        }
      }
      packedFields.push(felt);
    }

    const fields = Array.from({ length: 32 }, (_, i) => {
      const tid = i + 1;
      const value = DG13_FIELDS[tid];
      const valueBytes = value ? Buffer.from(value, 'utf-8') : Buffer.alloc(0);
      const pf: bigint[] = [];
      for (let f = 0; f < 4; f++) {
        let felt = 0n;
        for (let b = 0; b < 31; b++) {
          const byteIdx = f * 31 + b;
          if (byteIdx < valueBytes.length) felt = felt * 256n + BigInt(valueBytes[byteIdx]!);
        }
        pf.push(felt);
      }
      return { tagId: tid, length: valueBytes.length, packedFields: pf, packedHash: 0n };
    });

    const immutablePacked: bigint[] = [];
    for (const idx of [0, 2, 5, 7, 12]) immutablePacked.push(...fields[idx]!.packedFields);
    const packedHash = poseidon2.hash(immutablePacked, 20);
    for (const f of fields) f.packedHash = packedHash;

    const salt = 99999n;
    const tree = buildMerkleTree(fields, salt, poseidon2);
    const siblings = tree.getSiblings(tagId - 1);

    // Try to prove with WRONG commitment — circuit should reject
    const toHex = (v: bigint) => '0x' + v.toString(16);
    const fakeCommitment = 123456789n;

    await expect(
      zkpProvider.prove({
        circuitId: 'dg13-field-reveal',
        privateInputs: {
          siblings: siblings.map(toHex),
          length: toHex(BigInt(genderBytes.length)),
          data: packedFields.map(toHex),
          packed_hash: toHex(packedHash),
        },
        publicInputs: {
          commitment: toHex(fakeCommitment),
          salt: toHex(salt),
          tag_id: toHex(BigInt(tagId)),
        },
      })
    ).rejects.toThrow();
  }, 120000);
});

describe('CCCD matcher — real proof system', () => {
  it('matches with real ICAO proof system', () => {
    const proofSystem = createICAO9303ProofSystem({ poseidon2, buildMerkleTree });

    const cccdCredential: MatchableCredential = {
      type: ['VerifiableCredential', 'CCCDCredential'],
      issuer: 'did:web:cccd.gov.vn',
      credentialSubject: {
        dg13: Buffer.from(buildDG13Bytes()).toString('base64'),
      },
      proof: { dgProfile: 'VN-CCCD-2024' },
    };

    const request = new VPRequestBuilder('kyc', 'nonce')
      .setVerifier({ id: 'did:web:bank.vn', name: 'Bank', url: 'https://bank.vn' })
      .addDocumentRequest(
        new DocumentRequestBuilder('cccd', 'CCCDCredential')
          .setSchemaType('ICAO9303SOD')
          .disclose('c1', 'gender')
          .disclose('c2', 'fullName')
          .build()
      )
      .build();

    const match = matchCredentials(request.rules, [cccdCredential], {
      'ICAO9303SOD': proofSystem,
    });

    expect(match.satisfied).toBe(true);
    const docMatch = match as DocumentRequestMatch;
    expect(docMatch.candidates[0].fullyQualified).toBe(true);
    expect(docMatch.candidates[0].disclosedFields).toContain('gender');
    expect(docMatch.candidates[0].disclosedFields).toContain('fullName');
  });
});
