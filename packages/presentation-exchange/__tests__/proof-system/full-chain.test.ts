/**
 * Full proof chain test: sod-verify -> dg-map -> dg13-merklelize -> dg13-field-reveal
 *
 * Uses real:
 *   - ECDSA brainpoolP384r1 signature (self-signed)
 *   - SHA-256 hashing
 *   - Poseidon2 Merkle tree
 *   - Noir circuit proving + verification
 *
 * No mocks. Every proof is generated and verified by real circuits.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { createWasmZKPProvider, createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { Poseidon2Hasher, ZKPProvider } from '@1matrix/zkp-provider';
import { motherCCCD, buildMerkleLeaves } from '../fixtures/cccd-factory.js';
import { fieldIdToTagId } from '../../src/resolvers/zkp-field-mapping.js';

let poseidon2: Poseidon2Hasher;
let zkpProvider: ZKPProvider & { destroy(): void };

beforeAll(async () => {
  poseidon2 = await createPoseidon2Hasher();
  zkpProvider = await createWasmZKPProvider();
}, 60000);

const toHex = (v: bigint | number) => '0x' + BigInt(v).toString(16);
const toHexArr = (arr: number[]) => arr.map(v => String(v));

describe('Full proof chain: sod-verify -> dg-map -> dg13-merklelize -> field-reveal', () => {
  it('proves and verifies the entire chain with self-signed CCCD', async () => {
    const cccd = motherCCCD;
    const sod = cccd.sodInputs;
    const dg13 = cccd.dg13CircuitInputs;
    const salt = cccd.salt;

    // ---------------------------------------------------------------
    // Step 1: sod-verify — verify ECDSA signature, output econtent_binding
    // ---------------------------------------------------------------
    const sodResult = await zkpProvider.prove({
      circuitId: 'sod-verify',
      publicInputs: {
        pubkey_x: toHexArr(sod.pubkeyX),
        pubkey_y: toHexArr(sod.pubkeyY),
        salt: toHex(salt),
      },
      privateInputs: {
        econtent: toHexArr(sod.econtent),
        econtent_len: String(sod.econtentLen),
        signed_attrs: toHexArr(sod.signedAttrs),
        signed_attrs_len: String(sod.signedAttrsLen),
        digest_offset: String(sod.digestOffset),
        signature_r: toHexArr(sod.signatureR),
        signature_s: toHexArr(sod.signatureS),
      },
    });

    expect(sodResult.proofValue.length).toBeGreaterThan(100);
    const econtentBinding = sodResult.publicOutputs.output_0 as string;
    expect(econtentBinding).toBeDefined();

    // Verify sod-verify proof
    const sodValid = await zkpProvider.verify({
      circuitId: 'sod-verify',
      proofValue: sodResult.proofValue,
      publicInputs: {
        pubkey_x: toHexArr(sod.pubkeyX),
        pubkey_y: toHexArr(sod.pubkeyY),
        salt: toHex(salt),
      },
      publicOutputs: sodResult.publicOutputs,
    });
    expect(sodValid).toBe(true);

    // ---------------------------------------------------------------
    // Step 2: dg-map — extract DG13 hash, chain to sod-verify
    // ---------------------------------------------------------------
    const dgMapResult = await zkpProvider.prove({
      circuitId: 'dg-map',
      publicInputs: {
        salt: toHex(salt),
        econtent_binding: econtentBinding,
        dg_number: String(13),
      },
      privateInputs: {
        econtent: toHexArr(sod.econtent),
        econtent_len: String(sod.econtentLen),
        dg_offset: String(sod.dgOffset),
      },
    });

    expect(dgMapResult.proofValue.length).toBeGreaterThan(100);
    const dgBinding = dgMapResult.publicOutputs.output_0 as string;
    expect(dgBinding).toBeDefined();

    // Verify dg-map proof
    const dgMapValid = await zkpProvider.verify({
      circuitId: 'dg-map',
      proofValue: dgMapResult.proofValue,
      publicInputs: {
        salt: toHex(salt),
        econtent_binding: econtentBinding,
        dg_number: String(13),
      },
      publicOutputs: dgMapResult.publicOutputs,
    });
    expect(dgMapValid).toBe(true);

    // ---------------------------------------------------------------
    // Step 3: dg13-merklelize — build tree, chain to dg-map via binding
    // ---------------------------------------------------------------
    const dg13Result = await zkpProvider.prove({
      circuitId: 'dg13-merklelize',
      publicInputs: {
        salt: toHex(salt),
      },
      privateInputs: {
        raw_msg: toHexArr(dg13.rawMsg),
        dg_len: String(dg13.dgLen),
        field_offsets: dg13.fieldOffsets.map(String),
        field_lengths: dg13.fieldLengths.map(String),
      },
    });

    expect(dg13Result.proofValue.length).toBeGreaterThan(100);

    // outputs: [binding, identity, commitment]
    const dg13Binding = dg13Result.publicOutputs.output_0 as string;
    const commitment = dg13Result.publicOutputs.output_2 as string;
    expect(dg13Binding).toBeDefined();
    expect(commitment).toBeDefined();

    // Chain check: dg13.binding must equal dg-map.dg_binding
    expect(dg13Binding).toBe(dgBinding);

    // Verify dg13-merklelize proof
    const dg13Valid = await zkpProvider.verify({
      circuitId: 'dg13-merklelize',
      proofValue: dg13Result.proofValue,
      publicInputs: {
        salt: toHex(salt),
      },
      publicOutputs: dg13Result.publicOutputs,
    });
    expect(dg13Valid).toBe(true);

    // ---------------------------------------------------------------
    // Step 4: dg13-field-reveal — reveal gender, chain to commitment
    // ---------------------------------------------------------------
    const fields = buildMerkleLeaves(cccd.dg13Fields, poseidon2.hash);
    const tagId = fieldIdToTagId('gender'); // 4
    const leafIndex = tagId - 1;
    const tree = buildMerkleTree(fields, salt, poseidon2);
    const genderField = fields[leafIndex]!;

    // Verify our JS Merkle tree commitment matches the circuit's commitment
    expect(toHex(tree.commitment)).toBe(commitment);

    const revealResult = await zkpProvider.prove({
      circuitId: 'dg13-field-reveal',
      publicInputs: {
        commitment: toHex(tree.commitment),
        salt: toHex(salt),
        tag_id: toHex(BigInt(tagId)),
      },
      privateInputs: {
        siblings: tree.getSiblings(leafIndex).map(toHex),
        length: toHex(BigInt(genderField.length)),
        data: genderField.packedFields.map(toHex),
        packed_hash: toHex(genderField.packedHash),
      },
    });

    expect(revealResult.proofValue.length).toBeGreaterThan(100);

    // Verify field-reveal proof
    const revealValid = await zkpProvider.verify({
      circuitId: 'dg13-field-reveal',
      proofValue: revealResult.proofValue,
      publicInputs: {
        commitment: toHex(tree.commitment),
        salt: toHex(salt),
        tag_id: toHex(BigInt(tagId)),
      },
      publicOutputs: revealResult.publicOutputs,
    });
    expect(revealValid).toBe(true);

    // ---------------------------------------------------------------
    // Summary: all 4 proofs verified, bindings chain correctly
    // ---------------------------------------------------------------
    // sod-verify  →  econtent_binding
    //                      ↓
    // dg-map      →  dg_binding (chained via econtent_binding)
    //                      ↓
    // dg13-merklelize → binding == dg_binding ✓, commitment
    //                                              ↓
    // dg13-field-reveal → uses commitment, reveals gender
  }, 600000);

  it('rejects dg-map with wrong econtent_binding', async () => {
    const cccd = motherCCCD;
    const sod = cccd.sodInputs;
    const fakeBinding = '0x1234567890abcdef';

    await expect(
      zkpProvider.prove({
        circuitId: 'dg-map',
        publicInputs: {
          salt: toHex(cccd.salt),
          econtent_binding: fakeBinding,
          dg_number: String(13),
        },
        privateInputs: {
          econtent: toHexArr(sod.econtent),
          econtent_len: String(sod.econtentLen),
          dg_offset: String(sod.dgOffset),
        },
      }),
    ).rejects.toThrow();
  }, 120000);
});
