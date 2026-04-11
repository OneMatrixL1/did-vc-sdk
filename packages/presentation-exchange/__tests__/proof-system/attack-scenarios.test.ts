/**
 * Attack scenario tests — adversarial inputs that circuits MUST reject.
 *
 * Every test here attempts a specific attack. The circuit must either:
 *   - Refuse to generate a proof (assertion failure during proving)
 *   - Generate a proof that fails verification
 *
 * All crypto is real. No mocks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'crypto';
import { createWasmZKPProvider, createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { Poseidon2Hasher, ZKPProvider } from '@1matrix/zkp-provider';
import {
  motherCCCD,
  parentCCCD,
  createSelfSignedCCCD,
  MOTHER_DG13_FIELDS,
  buildMerkleLeaves,
} from '../fixtures/cccd-factory.js';
import { fieldIdToTagId } from '../../src/resolvers/zkp-field-mapping.js';
import { createICAO9303ProofSystem } from '../../src/proof-system/icao9303-proof-system.js';
import type { ICAO9303ZKPProofBundle, ZKPProofEntry } from '../../src/types/icao-proof-bundle.js';
import type { SchemaProofSystem } from '../../src/types/proof-system.js';

let poseidon2: Poseidon2Hasher;
let zkpProvider: ZKPProvider & { destroy(): void };
let proofSystem: SchemaProofSystem;

beforeAll(async () => {
  poseidon2 = await createPoseidon2Hasher();
  zkpProvider = await createWasmZKPProvider();
  proofSystem = createICAO9303ProofSystem({ poseidon2, buildMerkleTree });
}, 60000);

const toHex = (v: bigint | number) => '0x' + BigInt(v).toString(16);
const toHexArr = (arr: number[]) => arr.map(v => String(v));

// -----------------------------------------------------------------------
// Attack 1: Tampered DG13 — modify a field value after SOD was signed
// -----------------------------------------------------------------------
describe('Attack: tampered DG13 data', () => {
  it('rejects dg13-merklelize when DG13 bytes differ from SOD hash', async () => {
    const cccd = motherCCCD;

    // Tamper: change fullName in the raw DG13 bytes
    const tamperedFields = { ...MOTHER_DG13_FIELDS, 2: 'FAKE NAME' };
    const tampered = createSelfSignedCCCD(tamperedFields);

    // Use the ORIGINAL SOD (signed over original DG13)
    // but provide TAMPERED dg13 circuit inputs
    // The dg13-merklelize circuit hashes raw_msg[0..dg_len]
    // and produces binding = Poseidon2([hash_hi, hash_lo, salt], 3)
    // This binding will NOT match the dg-map output (which has original DG13 hash)

    // First prove dg-map with original SOD to get correct dg_binding
    const sod = cccd.sodInputs;
    const sodResult = await zkpProvider.prove({
      circuitId: 'sod-verify',
      publicInputs: {
        pubkey_x: toHexArr(sod.pubkeyX),
        pubkey_y: toHexArr(sod.pubkeyY),
        salt: toHex(cccd.salt),
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
    const econtentBinding = sodResult.publicOutputs.econtent_binding as string;

    const dgMapResult = await zkpProvider.prove({
      circuitId: 'dg-map',
      publicInputs: {
        salt: toHex(cccd.salt),
        econtent_binding: econtentBinding,
        dg_number: String(13),
      },
      privateInputs: {
        econtent: toHexArr(sod.econtent),
        econtent_len: String(sod.econtentLen),
        dg_offset: String(sod.dgOffset),
      },
    });
    const dgBinding = dgMapResult.publicOutputs.dg_binding as string;

    // Now prove dg13-merklelize with TAMPERED data
    const tamperedDg13 = tampered.dg13CircuitInputs;
    const dg13Result = await zkpProvider.prove({
      circuitId: 'dg13-merklelize',
      publicInputs: { salt: toHex(cccd.salt) },
      privateInputs: {
        raw_msg: toHexArr(tamperedDg13.rawMsg),
        dg_len: String(tamperedDg13.dgLen),
        field_offsets: tamperedDg13.fieldOffsets.map(String),
        field_lengths: tamperedDg13.fieldLengths.map(String),
      },
    });

    // Binding mismatch: tampered DG13 hash != original DG13 hash
    const tamperedBinding = dg13Result.publicOutputs.binding as string;
    expect(tamperedBinding).not.toBe(dgBinding);
  }, 120000);
});

// -----------------------------------------------------------------------
// Attack 2: Wrong public key — verify SOD with attacker's key
// -----------------------------------------------------------------------
describe('Attack: wrong public key', () => {
  it('rejects sod-verify with a different keypair', async () => {
    const cccd = motherCCCD;
    const sod = cccd.sodInputs;

    // Generate attacker's keypair
    const attackerKey = crypto.generateKeyPairSync('ec', { namedCurve: 'brainpoolP384r1' });
    const attackerSpki = attackerKey.publicKey.export({ type: 'spki', format: 'der' });

    // Parse attacker's public key (proper TLV parsing)
    function parseTLV(buf: Buffer, offset: number) {
      const tag = buf[offset]!;
      let lenOff = offset + 1;
      let length: number;
      if (buf[lenOff]! < 0x80) { length = buf[lenOff]!; lenOff += 1; }
      else { const n = buf[lenOff]! & 0x7f; length = 0; for (let i = 0; i < n; i++) length = (length << 8) | buf[lenOff + 1 + i]!; lenOff += 1 + n; }
      return { tag, length, valueOffset: lenOff, totalLength: lenOff - offset + length };
    }
    const outer = parseTLV(attackerSpki, 0);
    let pos = outer.valueOffset;
    const algId = parseTLV(attackerSpki, pos);
    pos += algId.totalLength;
    const bitStr = parseTLV(attackerSpki, pos);
    const ecPoint = attackerSpki.slice(bitStr.valueOffset + 1, bitStr.valueOffset + bitStr.length);
    const attackerX = Array.from(ecPoint.slice(1, 49));
    const attackerY = Array.from(ecPoint.slice(49, 97));

    // Try to prove with attacker's public key but original signature
    await expect(
      zkpProvider.prove({
        circuitId: 'sod-verify',
        publicInputs: {
          pubkey_x: toHexArr(attackerX),
          pubkey_y: toHexArr(attackerY),
          salt: toHex(cccd.salt),
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
      }),
    ).rejects.toThrow();
  }, 120000);
});

// -----------------------------------------------------------------------
// Attack 3: Flipped signature bit — tamper with signature bytes
// -----------------------------------------------------------------------
describe('Attack: tampered signature', () => {
  it('rejects sod-verify when signature r is flipped', async () => {
    const cccd = motherCCCD;
    const sod = cccd.sodInputs;

    // Flip one bit in signature_r
    const flippedR = [...sod.signatureR];
    flippedR[10] = flippedR[10]! ^ 0x01;

    await expect(
      zkpProvider.prove({
        circuitId: 'sod-verify',
        publicInputs: {
          pubkey_x: toHexArr(sod.pubkeyX),
          pubkey_y: toHexArr(sod.pubkeyY),
          salt: toHex(cccd.salt),
        },
        privateInputs: {
          econtent: toHexArr(sod.econtent),
          econtent_len: String(sod.econtentLen),
          signed_attrs: toHexArr(sod.signedAttrs),
          signed_attrs_len: String(sod.signedAttrsLen),
          digest_offset: String(sod.digestOffset),
          signature_r: toHexArr(flippedR),
          signature_s: toHexArr(sod.signatureS),
        },
      }),
    ).rejects.toThrow();
  }, 120000);
});

// -----------------------------------------------------------------------
// Attack 4: Field substitution — claim gender reveal is fullName
// -----------------------------------------------------------------------
describe('Attack: field substitution', () => {
  it('rejects field-reveal when tag_id does not match actual leaf', async () => {
    const fields = buildMerkleLeaves(MOTHER_DG13_FIELDS, poseidon2.hash);
    const salt = 42n;
    const tree = buildMerkleTree(fields, salt, poseidon2);

    // Get gender field data (tag 4, index 3)
    const genderIndex = fieldIdToTagId('gender') - 1;
    const genderField = fields[genderIndex]!;

    // Try to prove with gender data but claim tag_id = 2 (fullName)
    const fakeTagId = fieldIdToTagId('fullName');

    await expect(
      zkpProvider.prove({
        circuitId: 'dg13-field-reveal',
        publicInputs: {
          commitment: toHex(tree.commitment),
          salt: toHex(salt),
          tag_id: toHex(BigInt(fakeTagId)), // claiming fullName
        },
        privateInputs: {
          siblings: tree.getSiblings(genderIndex).map(toHex), // gender siblings
          length: toHex(BigInt(genderField.length)),           // gender length
          data: genderField.packedFields.map(toHex),           // gender data
          packed_hash: toHex(genderField.packedHash),
        },
      }),
    ).rejects.toThrow();
  }, 120000);
});

// -----------------------------------------------------------------------
// Attack 5: Cross-credential forgery — siblings from one, data from another
// -----------------------------------------------------------------------
describe('Attack: cross-credential forgery', () => {
  it('rejects field-reveal with mismatched tree and field data', async () => {
    const motherFields = buildMerkleLeaves(MOTHER_DG13_FIELDS, poseidon2.hash);
    const salt = 42n;
    const motherTree = buildMerkleTree(motherFields, salt, poseidon2);

    // Get father's fullName data
    const fatherCCCD = parentCCCD;
    const fatherFields = buildMerkleLeaves(fatherCCCD.dg13Fields, poseidon2.hash);
    const fullNameIndex = fieldIdToTagId('fullName') - 1;
    const fatherFullName = fatherFields[fullNameIndex]!;

    // Try: mother's tree + father's fullName data
    await expect(
      zkpProvider.prove({
        circuitId: 'dg13-field-reveal',
        publicInputs: {
          commitment: toHex(motherTree.commitment),  // mother's commitment
          salt: toHex(salt),
          tag_id: toHex(BigInt(fieldIdToTagId('fullName'))),
        },
        privateInputs: {
          siblings: motherTree.getSiblings(fullNameIndex).map(toHex),  // mother's siblings
          length: toHex(BigInt(fatherFullName.length)),                  // father's data
          data: fatherFullName.packedFields.map(toHex),                  // father's data
          packed_hash: toHex(fatherFullName.packedHash),                 // father's packed_hash
        },
      }),
    ).rejects.toThrow();
  }, 120000);
});

// -----------------------------------------------------------------------
// Attack 6: Replay with different salt
// -----------------------------------------------------------------------
describe('Attack: salt replay', () => {
  it('proof verified under salt A fails verification under salt B', async () => {
    const fields = buildMerkleLeaves(MOTHER_DG13_FIELDS, poseidon2.hash);
    const saltA = 111n;
    const saltB = 222n;
    const treeA = buildMerkleTree(fields, saltA, poseidon2);

    const tagId = fieldIdToTagId('gender');
    const leafIndex = tagId - 1;
    const genderField = fields[leafIndex]!;

    // Prove with salt A
    const result = await zkpProvider.prove({
      circuitId: 'dg13-field-reveal',
      publicInputs: {
        commitment: toHex(treeA.commitment),
        salt: toHex(saltA),
        tag_id: toHex(BigInt(tagId)),
      },
      privateInputs: {
        siblings: treeA.getSiblings(leafIndex).map(toHex),
        length: toHex(BigInt(genderField.length)),
        data: genderField.packedFields.map(toHex),
        packed_hash: toHex(genderField.packedHash),
      },
    });

    // Verify with salt B (different commitment) — must fail
    const treeB = buildMerkleTree(fields, saltB, poseidon2);
    const replayValid = await zkpProvider.verify({
      circuitId: 'dg13-field-reveal',
      proofValue: result.proofValue,
      publicInputs: {
        commitment: toHex(treeB.commitment), // different commitment
        salt: toHex(saltB),                    // different salt
        tag_id: toHex(BigInt(tagId)),
      },
      publicOutputs: result.publicOutputs,
    });

    expect(replayValid).toBe(false);
  }, 120000);
});

// -----------------------------------------------------------------------
// Attack 7: Tampered eContent — modify DG hash in LDS Security Object
// -----------------------------------------------------------------------
describe('Attack: tampered eContent', () => {
  it('rejects sod-verify when eContent hash does not match messageDigest', async () => {
    const cccd = motherCCCD;
    const sod = cccd.sodInputs;

    // Tamper: flip a byte in eContent (the DG13 hash region)
    const tamperedEcontent = [...sod.econtent];
    const dgHashStart = sod.dgOffset + 7; // DG hash starts 7 bytes after entry
    tamperedEcontent[dgHashStart] = tamperedEcontent[dgHashStart]! ^ 0xff;

    // SHA-256(tampered eContent) != messageDigest in signedAttrs
    await expect(
      zkpProvider.prove({
        circuitId: 'sod-verify',
        publicInputs: {
          pubkey_x: toHexArr(sod.pubkeyX),
          pubkey_y: toHexArr(sod.pubkeyY),
          salt: toHex(cccd.salt),
        },
        privateInputs: {
          econtent: toHexArr(tamperedEcontent),
          econtent_len: String(sod.econtentLen),
          signed_attrs: toHexArr(sod.signedAttrs),
          signed_attrs_len: String(sod.signedAttrsLen),
          digest_offset: String(sod.digestOffset),
          signature_r: toHexArr(sod.signatureR),
          signature_s: toHexArr(sod.signatureS),
        },
      }),
    ).rejects.toThrow();
  }, 120000);
});

// -----------------------------------------------------------------------
// Verifier-level attacks: parameter forgery on valid ZKP proofs
// These test the verifier's input validation, not the circuit math.
// -----------------------------------------------------------------------

/**
 * Helper: build a real VP credential through the ICAO pipeline, then
 * tamper with the bundle before verification to test the verifier's checks.
 */
const TEST_NONCE = 'attack-test-nonce';
const TEST_HOLDER = 'did:key:z6MkAttackTest';

async function buildRealBundle() {
  const cccd = motherCCCD;
  const conditions = {
    disclose: [
      { type: 'DocumentCondition' as const, conditionID: 'c1', field: 'fullName', operator: 'disclose' as const },
      { type: 'DocumentCondition' as const, conditionID: 'c2', field: 'gender', operator: 'disclose' as const },
    ],
    predicates: [] as Array<{ type: 'DocumentCondition'; conditionID: string; field: string; operator: string; params: Record<string, unknown>; optional?: boolean }>,
  };
  const cred = await proofSystem.prove(cccd.credential, conditions, {
    zkpProvider,
    nonce: TEST_NONCE,
    holder: TEST_HOLDER,
    credentialData: {
      sodInputs: cccd.sodInputs,
      dg13Inputs: cccd.dg13CircuitInputs,
    },
  });
  const bundle = cred.proof as ICAO9303ZKPProofBundle;
  return { bundle, conditions };
}

describe('Attack: parameter forgery at verifier level', () => {
  it('rejects tag_id substitution in disclosure — wrong field revealed', async () => {
    const { bundle, conditions } = await buildRealBundle();

    // Tamper: swap tag_id of fullName disclosure to gender's tag_id
    const tampered = structuredClone(bundle);
    const disc = tampered.disclosures!.find((d: { conditionID: string }) => d.conditionID === 'c1')!;
    disc.tagId = '0x' + BigInt(fieldIdToTagId('gender')).toString(16);

    const result = await proofSystem.verify(
      { type: ['VerifiableCredential', 'CCCDCredential'], issuer: 'did:web:cccd.gov.vn', credentialSubject: {}, proof: tampered },
      conditions,
      { zkpProvider, nonce: TEST_NONCE, holder: TEST_HOLDER },
    );
    expect(result.verified).toBe(false);
    expect(result.errors.some(e => e.includes('tag_id mismatch'))).toBe(true);
  }, 120000);

  it('rejects tampered disclosure data — Merkle proof fails', async () => {
    const { bundle, conditions } = await buildRealBundle();

    // Tamper: change the disclosed data
    const tampered = structuredClone(bundle);
    const disc = tampered.disclosures!.find((d: { conditionID: string }) => d.conditionID === 'c1')!;
    disc.data[0] = '0xdeadbeef';

    const result = await proofSystem.verify(
      { type: ['VerifiableCredential', 'CCCDCredential'], issuer: 'did:web:cccd.gov.vn', credentialSubject: {}, proof: tampered },
      conditions,
      { zkpProvider, nonce: TEST_NONCE, holder: TEST_HOLDER },
    );
    expect(result.verified).toBe(false);
    expect(result.errors.some(e => e.includes('Merkle proof invalid'))).toBe(true);
  }, 120000);

  it('rejects unrecognized conditionID in disclosure', async () => {
    const { bundle, conditions } = await buildRealBundle();

    // Tamper: add a fake disclosure with unknown conditionID
    const tampered = structuredClone(bundle);
    tampered.disclosures!.push({
      ...tampered.disclosures![0],
      conditionID: 'fake-condition',
    });

    const result = await proofSystem.verify(
      { type: ['VerifiableCredential', 'CCCDCredential'], issuer: 'did:web:cccd.gov.vn', credentialSubject: {}, proof: tampered },
      conditions,
      { zkpProvider, nonce: TEST_NONCE, holder: TEST_HOLDER },
    );
    expect(result.verified).toBe(false);
    expect(result.errors.some(e => e.includes('does not match any requested condition'))).toBe(true);
  }, 120000);

  it('rejects relay — valid proofs presented with different holder', async () => {
    const { bundle, conditions } = await buildRealBundle();

    // Attacker takes victim's bundle and presents with their own DID
    const result = await proofSystem.verify(
      { type: ['VerifiableCredential', 'CCCDCredential'], issuer: 'did:web:cccd.gov.vn', credentialSubject: {}, proof: bundle },
      conditions,
      { zkpProvider, nonce: TEST_NONCE, holder: 'did:key:z6MkAttacker' },
    );
    expect(result.verified).toBe(false);
    expect(result.errors.some(e => e.includes('Salt mismatch'))).toBe(true);
  }, 120000);

  it('rejects replay — valid proofs replayed with different nonce', async () => {
    const { bundle, conditions } = await buildRealBundle();

    // Attacker replays proofs to a different verifier session
    const result = await proofSystem.verify(
      { type: ['VerifiableCredential', 'CCCDCredential'], issuer: 'did:web:cccd.gov.vn', credentialSubject: {}, proof: bundle },
      conditions,
      { zkpProvider, nonce: 'different-nonce', holder: TEST_HOLDER },
    );
    expect(result.verified).toBe(false);
    expect(result.errors.some(e => e.includes('Salt mismatch'))).toBe(true);
  }, 120000);
});
