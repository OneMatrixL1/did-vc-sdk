import { describe, it, expect, beforeAll } from 'vitest';
import { Buffer } from 'buffer';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { matchCredentials } from '../../src/resolver/matcher.js';
import { createICAO9303ProofSystem } from '../../src/proof-system/icao9303-proof-system.js';
import { createWasmZKPProvider, createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { Poseidon2Hasher } from '@1matrix/zkp-provider';
import type { DocumentRequestMatch } from '../../src/types/matching.js';
import type { ZKPProvider } from '../../src/types/zkp-provider.js';
import { fieldIdToTagId } from '../../src/resolvers/zkp-field-mapping.js';
import {
  motherCCCD,
  MOTHER_DG13_FIELDS,
  buildMerkleLeaves,
} from '../fixtures/cccd-factory.js';

let poseidon2: Poseidon2Hasher;
let zkpProvider: ZKPProvider & { destroy(): void };

beforeAll(async () => {
  poseidon2 = await createPoseidon2Hasher();
  zkpProvider = await createWasmZKPProvider();
}, 60000);

describe('CCCD field reveal - real ZKP', () => {
  it('builds real Merkle tree from DG13 bytes with Poseidon2', () => {
    const fields = buildMerkleLeaves(MOTHER_DG13_FIELDS, poseidon2.hash);
    const salt = 42n;
    const tree = buildMerkleTree(fields, salt, poseidon2);

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
    const fields = buildMerkleLeaves(MOTHER_DG13_FIELDS, poseidon2.hash);
    const tagId = fieldIdToTagId('gender'); // 4
    const leafIndex = tagId - 1; // 3

    const salt = 12345n;
    const tree = buildMerkleTree(fields, salt, poseidon2);
    const commitment = tree.commitment;
    const siblings = tree.getSiblings(leafIndex);
    const genderField = fields[leafIndex]!;
    const packedHash = genderField.packedHash;

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

    const outputs = proveResult.publicOutputs;
    expect(outputs).toBeDefined();
  }, 120000);

  it('rejects proof with wrong commitment', async () => {
    const fields = buildMerkleLeaves(MOTHER_DG13_FIELDS, poseidon2.hash);
    const tagId = fieldIdToTagId('gender');
    const leafIndex = tagId - 1;

    const salt = 99999n;
    const tree = buildMerkleTree(fields, salt, poseidon2);
    const siblings = tree.getSiblings(leafIndex);
    const genderField = fields[leafIndex]!;

    const toHex = (v: bigint) => '0x' + v.toString(16);
    const fakeCommitment = 123456789n;

    await expect(
      zkpProvider.prove({
        circuitId: 'dg13-field-reveal',
        privateInputs: {
          siblings: siblings.map(toHex),
          length: toHex(BigInt(genderField.length)),
          data: genderField.packedFields.map(toHex),
          packed_hash: toHex(genderField.packedHash),
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

describe('CCCD matcher - real proof system', () => {
  it('matches with real ICAO proof system', () => {
    const proofSystem = createICAO9303ProofSystem({ poseidon2, buildMerkleTree });

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

    const match = matchCredentials(request.rules, [motherCCCD.credential], {
      'ICAO9303SOD': proofSystem,
    });

    expect(match.satisfied).toBe(true);
    const docMatch = match as DocumentRequestMatch;
    expect(docMatch.candidates[0].fullyQualified).toBe(true);
    expect(docMatch.candidates[0].disclosedFields).toContain('gender');
    expect(docMatch.candidates[0].disclosedFields).toContain('fullName');
  });
});
