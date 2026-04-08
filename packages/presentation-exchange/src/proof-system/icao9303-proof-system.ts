/**
 * ICAO 9303 ZKP Proof System.
 *
 * Implements SchemaProofSystem for ICAO credentials (CCCD, Passport).
 * Internally uses a pipeline to orchestrate:
 *   sod-verify → dg-map → dg13-merklelize → field-reveals → predicates
 *
 * Developers never see circuits, Merkle trees, or proof chaining.
 */

import type { MatchableCredential, PresentedCredential } from '../types/credential.js';
import type { DiscloseCondition } from '../types/request.js';
import type { PredicateCondition } from '../types/condition.js';
import type { SchemaProofSystem, ProveContext, VerifyContext, ProofVerificationResult, DSCVerificationResult } from '../types/proof-system.js';
import type { ICAO9303ZKPProofBundle, ZKPProofEntry } from '../types/icao-proof-bundle.js';
import { isICAOProofBundle } from '../types/icao-proof-bundle.js';
import type { ZKPProvider } from '../types/zkp-provider.js';
import type { Poseidon2Hasher } from '../types/zkp-provider.js';
import type { PipelineState, PipelineStep } from './pipeline.js';
import { executePipeline } from './pipeline.js';
import {
  getProfile,
  getProfileByDocType,
  resolveField as resolveProfileField,
} from '@1matrix/credential-sdk/icao-profile';
import { fieldIdToLeafIndex, fieldIdToTagId, isDg13Field } from '../resolvers/zkp-field-mapping.js';

// ---------------------------------------------------------------------------
// Circuit ID mapping — condition operator → circuit
// ---------------------------------------------------------------------------

const PREDICATE_CIRCUIT_MAP: Record<string, string> = {
  greaterThan: 'date-greaterthan',
  lessThan: 'date-lessthan',
  greaterThanOrEqual: 'date-greaterthanorequal',
  lessThanOrEqual: 'date-lessthanorequal',
  inRange: 'date-inrange',
  equals: 'field-equals',
};

// ---------------------------------------------------------------------------
// ICAO credential data (provided by holder)
// ---------------------------------------------------------------------------

export interface SODCircuitInputs {
  econtent: number[];        // [u8; 320] padded
  econtentLen: number;
  signedAttrs: number[];     // [u8; 200] padded
  signedAttrsLen: number;
  dgOffset: number;
  digestOffset: number;
  signatureR: number[];      // [u8; 48]
  signatureS: number[];      // [u8; 48] canonical
  pubkeyX: number[];         // [u8; 48]
  pubkeyY: number[];         // [u8; 48]
}

export interface DG13CircuitInputs {
  rawMsg: number[];           // [u8; 700] padded
  dgLen: number;
  fieldOffsets: number[];     // [u32; 32]
  fieldLengths: number[];     // [u32; 32]
}

export interface ICAOCredentialData {
  sodInputs: SODCircuitInputs;
  dg13Inputs: DG13CircuitInputs;
  salt: bigint;
  /** DSC certificate in base64 DER. Included in the proof bundle for CSCA trust verification. */
  dscCertificate?: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export type MerkleTreeBuilder = (
  fields: Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }>,
  salt: bigint,
  hasher: Poseidon2Hasher,
) => { root: bigint; commitment: bigint; leaves: bigint[]; getSiblings(i: number): bigint[] };

export interface ICAO9303ProofSystemOptions {
  poseidon2?: Poseidon2Hasher;
  buildMerkleTree?: MerkleTreeBuilder;
}

export function createICAO9303ProofSystem(
  opts?: ICAO9303ProofSystemOptions,
): SchemaProofSystem {
  return {
    schemaType: 'ICAO9303SOD',

    resolveField(credential, field) {
      // Try ICAO profile resolution first (reads from encoded DG blobs)
      const profile = detectProfile(credential);
      if (profile) {
        const rawDGs = extractRawDGs(credential);
        const value = resolveProfileField(profile, field, rawDGs);
        if (value !== undefined) return { found: true, value };
      }

      // Fallback: direct credentialSubject field lookup
      const direct = credential.credentialSubject[field];
      if (direct !== undefined) return { found: true, value: direct };

      return { found: false, value: undefined };
    },

    async prove(credential, conditions, context) {
      const data = context.credentialData as ICAOCredentialData;
      if (!data?.sodInputs || !data?.dg13Inputs) {
        throw new Error('ICAO proof system requires credentialData with sodInputs and dg13Inputs');
      }

      const poseidon2 = opts?.poseidon2;
      if (!poseidon2) {
        throw new Error('ICAO proof system requires poseidon2 hasher for proving');
      }

      const treeBuild = opts?.buildMerkleTree;
      if (!treeBuild) {
        throw new Error('ICAO proof system requires buildMerkleTree for proving');
      }

      const pipeline = buildICAOPipeline(conditions, poseidon2, treeBuild);

      const state = await executePipeline(pipeline, {
        sodInputs: data.sodInputs,
        dg13Inputs: data.dg13Inputs,
        salt: data.salt,
      }, context.zkpProvider);

      return packageAsCredential(credential, state, conditions, data.dscCertificate);
    },

    async verify(credential, conditions, context) {
      const proof = Array.isArray(credential.proof) ? credential.proof[0] : credential.proof;
      if (!isICAOProofBundle(proof)) {
        return { verified: false, disclosedFields: {}, errors: ['Expected ICAO9303ZKPProofBundle'] };
      }

      return verifyICAOBundle(proof, conditions, context.zkpProvider, context.verifyDSC);
    },
  };
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

const toHex = (v: bigint | number) => '0x' + BigInt(v).toString(16);
const toHexArr = (arr: number[]) => arr.map(v => String(v));

// ---------------------------------------------------------------------------
// Pipeline construction
// ---------------------------------------------------------------------------

function buildICAOPipeline(
  conditions: { disclose: DiscloseCondition[]; predicates: PredicateCondition[] },
  poseidon2: Poseidon2Hasher,
  treeBuild: MerkleTreeBuilder,
): PipelineStep[] {
  const steps: PipelineStep[] = [
    // Step 1: Parse DG13 fields + build Merkle tree
    {
      kind: 'compute',
      label: 'parse-and-merklelize',
      async run(state) {
        const dg13 = state.bag.get('dg13Inputs') as DG13CircuitInputs;
        const salt = state.bag.get('salt') as bigint;

        // Build Merkle leaves from raw_msg using field_offsets/field_lengths
        const fields = buildFieldsFromRawMsg(dg13, poseidon2);
        const tree = treeBuild(fields, salt, poseidon2);

        state.bag.set('fields', fields);
        state.bag.set('tree', tree);
      },
    },

    // Step 2: sod-verify — ECDSA brainpoolP384r1 signature verification
    {
      kind: 'prove',
      label: 'sod-verify',
      circuitId: 'sod-verify',
      buildInputs(state) {
        const sod = state.bag.get('sodInputs') as SODCircuitInputs;
        const salt = state.bag.get('salt') as bigint;
        return {
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
        };
      },
      processOutputs(state, result) {
        state.bag.set('econtentBinding', result.publicOutputs.econtent_binding);
      },
      satisfies: [],
    },

    // Step 3: dg-map — extract DG13 hash from signed eContent
    {
      kind: 'prove',
      label: 'dg-map',
      circuitId: 'dg-map',
      buildInputs(state) {
        const sod = state.bag.get('sodInputs') as SODCircuitInputs;
        const salt = state.bag.get('salt') as bigint;
        return {
          publicInputs: {
            salt: toHex(salt),
            econtent_binding: state.bag.get('econtentBinding'),
            dg_number: String(13),
          },
          privateInputs: {
            econtent: toHexArr(sod.econtent),
            econtent_len: String(sod.econtentLen),
            dg_offset: String(sod.dgOffset),
          },
        };
      },
      processOutputs(state, result) {
        state.bag.set('dgBinding', result.publicOutputs.dg_binding);
      },
      satisfies: [],
    },

    // Step 4: dg13-merklelize — build Merkle tree, verify binding
    {
      kind: 'prove',
      label: 'dg13-merklelize',
      circuitId: 'dg13-merklelize',
      buildInputs(state) {
        const dg13 = state.bag.get('dg13Inputs') as DG13CircuitInputs;
        const salt = state.bag.get('salt') as bigint;
        return {
          publicInputs: {
            salt: toHex(salt),
          },
          privateInputs: {
            raw_msg: toHexArr(dg13.rawMsg),
            dg_len: String(dg13.dgLen),
            field_offsets: dg13.fieldOffsets.map(String),
            field_lengths: dg13.fieldLengths.map(String),
          },
        };
      },
      processOutputs(state, result) {
        state.bag.set('binding', result.publicOutputs.binding);
        state.bag.set('identity', result.publicOutputs.identity);
        state.bag.set('commitment', result.publicOutputs.commitment);
      },
      satisfies: [],
    },
  ];

  // Step 5+: Field reveals
  for (const d of conditions.disclose) {
    if (!isDg13Field(d.field)) continue;

    steps.push({
      kind: 'prove',
      label: `reveal-${d.field}`,
      circuitId: 'dg13-field-reveal',
      buildInputs(state) {
        const tree = state.bag.get('tree') as { getSiblings(i: number): bigint[] };
        const fields = state.bag.get('fields') as Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }>;
        const salt = state.bag.get('salt') as bigint;
        const leafIndex = fieldIdToLeafIndex(d.field);
        const field = fields[leafIndex]!;

        return {
          privateInputs: {
            siblings: tree.getSiblings(leafIndex).map(toHex),
            length: toHex(BigInt(field.length)),
            data: field.packedFields.map(toHex),
            packed_hash: toHex(field.packedHash),
          },
          publicInputs: {
            commitment: state.bag.get('commitment'),
            salt: toHex(salt),
            tag_id: toHex(BigInt(fieldIdToTagId(d.field))),
          },
        };
      },
      processOutputs() {},
      satisfies: [d.conditionID],
    });
  }

  // Step N+: Predicate proofs
  for (const p of conditions.predicates) {
    if (p.operator === 'equals' && 'ref' in p.params) continue;

    const circuitId = PREDICATE_CIRCUIT_MAP[p.operator];
    if (!circuitId) throw new Error(`No circuit for predicate operator "${p.operator}"`);

    steps.push({
      kind: 'prove',
      label: `predicate-${p.conditionID}`,
      circuitId,
      buildInputs(state) {
        const tree = state.bag.get('tree') as { getSiblings(i: number): bigint[] };
        const fields = state.bag.get('fields') as Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }>;
        const salt = state.bag.get('salt') as bigint;
        const leafIndex = fieldIdToLeafIndex(p.field);
        const field = fields[leafIndex]!;

        return {
          privateInputs: {
            siblings: tree.getSiblings(leafIndex).map(toHex),
            length: toHex(BigInt(field.length)),
            data: field.packedFields.map(toHex),
            packed_hash: toHex(field.packedHash),
          },
          publicInputs: {
            commitment: state.bag.get('commitment'),
            salt: toHex(salt),
            tag_id: toHex(BigInt(fieldIdToTagId(p.field))),
            ...flattenPredicateParams(p),
          },
        };
      },
      processOutputs() {},
      satisfies: [p.conditionID],
    });
  }

  return steps;
}

// ---------------------------------------------------------------------------
// Build Merkle leaf fields from raw_msg (matches circuit packing exactly)
// ---------------------------------------------------------------------------

function buildFieldsFromRawMsg(
  dg13: DG13CircuitInputs,
  poseidon2: Poseidon2Hasher,
): Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }> {
  const fields: Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }> = [];

  for (let i = 0; i < 32; i++) {
    const tagId = i + 1;
    const offset = dg13.fieldOffsets[i]!;
    const length = dg13.fieldLengths[i]!;

    const packedFields: bigint[] = [];
    for (let f = 0; f < 4; f++) {
      let felt = 0n;
      for (let b = 0; b < 31; b++) {
        const byteIdx = f * 31 + b;
        if (byteIdx < length) {
          felt = felt * 256n + BigInt(dg13.rawMsg[offset + byteIdx]!);
        }
      }
      packedFields.push(felt);
    }

    fields.push({ tagId, length, packedFields, packedHash: 0n });
  }

  // Compute packed_hash from immutable fields (indices 0, 2, 5, 7, 12)
  const immutablePacked: bigint[] = [];
  for (const idx of [0, 2, 5, 7, 12]) {
    immutablePacked.push(...fields[idx]!.packedFields);
  }
  const packedHash = poseidon2.hash(immutablePacked, 20);
  for (const f of fields) f.packedHash = packedHash;

  return fields;
}

// ---------------------------------------------------------------------------
// Package pipeline results into PresentedCredential
// ---------------------------------------------------------------------------

function packageAsCredential(
  credential: MatchableCredential,
  state: PipelineState,
  conditions: { disclose: DiscloseCondition[]; predicates: PredicateCondition[] },
  dscCertificate?: string,
): PresentedCredential {
  const proofs: ZKPProofEntry[] = [];
  const subject: Record<string, unknown> = {};  // intentionally empty — values come from verified proofs

  // Pipeline chain proofs (sod-verify, dg-map, dg13-merklelize)
  for (const label of ['sod-verify', 'dg-map', 'dg13-merklelize']) {
    const p = state.proofs.find((pr) => pr.label === label)!;
    proofs.push({
      circuitId: p.circuitId!,
      proofValue: p.proofValue,
      publicInputs: p.publicInputs,
      publicOutputs: p.publicOutputs,
    });
  }

  // Field reveals
  for (const d of conditions.disclose) {
    const p = state.proofs.find((pr) => pr.satisfies.includes(d.conditionID));
    if (!p) continue;

    proofs.push({
      circuitId: 'dg13-field-reveal',
      proofValue: p.proofValue,
      publicInputs: p.publicInputs,
      publicOutputs: p.publicOutputs,
      conditionID: d.conditionID,
    });
  }

  // Predicates
  for (const p of conditions.predicates) {
    const proof = state.proofs.find((pr) => pr.satisfies.includes(p.conditionID));
    if (!proof) continue;

    proofs.push({
      circuitId: PREDICATE_CIRCUIT_MAP[p.operator]!,
      proofValue: proof.proofValue,
      publicInputs: proof.publicInputs,
      publicOutputs: proof.publicOutputs,
      conditionID: p.conditionID,
    });
  }

  const bundle: ICAO9303ZKPProofBundle = {
    type: 'ICAO9303ZKPProofBundle',
    proofs,
    ...(dscCertificate ? { dscCertificate } : {}),
  };

  if (credential.credentialSubject.id !== undefined) {
    subject.id = credential.credentialSubject.id;
  }

  const types = [...(credential.type as readonly string[])];
  const issuer = typeof credential.issuer === 'string' ? credential.issuer : { ...credential.issuer };

  const presented: PresentedCredential = {
    type: types,
    issuer,
    credentialSubject: subject,
    proof: bundle,
  };

  if (credential['@context']) presented['@context'] = [...(credential['@context'] as string[])];
  if (credential.issuanceDate !== undefined) presented.issuanceDate = credential.issuanceDate as string;
  if (credential.id !== undefined) presented.id = credential.id as string;

  return presented;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

async function verifyICAOBundle(
  bundle: ICAO9303ZKPProofBundle,
  conditions: { disclose: DiscloseCondition[]; predicates: PredicateCondition[] },
  zkpProvider: ZKPProvider,
  verifyDSC?: (dscCertificate: string) => Promise<DSCVerificationResult>,
): Promise<ProofVerificationResult> {
  const errors: string[] = [];
  const disclosedFields: Record<string, string> = {};
  const { proofs } = bundle;

  // --- 1. Verify every proof individually (zkp-provider level) ---
  for (const entry of proofs) {
    const valid = await zkpProvider.verify({
      circuitId: entry.circuitId,
      proofValue: entry.proofValue,
      publicInputs: entry.publicInputs,
      publicOutputs: entry.publicOutputs,
    });
    if (!valid) {
      const label = entry.conditionID ? `${entry.circuitId}[${entry.conditionID}]` : entry.circuitId;
      errors.push(`Proof invalid: ${label}`);
    }
  }

  // --- 2. Verify binding chain (presentation-exchange level) ---
  const sodVerify = proofs.find((p) => p.circuitId === 'sod-verify');
  const dgMap = proofs.find((p) => p.circuitId === 'dg-map');
  const dg13 = proofs.find((p) => p.circuitId === 'dg13-merklelize');

  if (!sodVerify) errors.push('Missing sod-verify proof');
  if (!dgMap) errors.push('Missing dg-map proof');
  if (!dg13) errors.push('Missing dg13-merklelize proof');

  // If any chain proof is missing, the entire chain is unanchored — nothing can be trusted
  if (!sodVerify || !dgMap || !dg13) {
    return { verified: false, disclosedFields: {}, errors };
  }

  // --- 2b. Verify DSC trust anchor (CSCA → DSC → pubkey match) ---
  if (verifyDSC) {
    if (!bundle.dscCertificate) {
      errors.push('Missing dscCertificate in proof bundle');
    } else {
      const dscResult = await verifyDSC(bundle.dscCertificate);
      if (!dscResult.trusted) {
        errors.push('DSC certificate is not signed by a trusted CSCA');
      }
      // Compare DSC pubkey with sod-verify publicInputs
      const sodPubX = sodVerify.publicInputs.pubkey_x as string[];
      const sodPubY = sodVerify.publicInputs.pubkey_y as string[];
      if (!arraysEqual(dscResult.publicKey.x, sodPubX.map(Number))
        || !arraysEqual(dscResult.publicKey.y, sodPubY.map(Number))) {
        errors.push('DSC public key does not match sod-verify pubkey_x/pubkey_y');
      }
    }
  }

  // dg-map must reference sod-verify's output
  if (dgMap.publicInputs.econtent_binding !== sodVerify.publicOutputs.econtent_binding) {
    errors.push('dg-map econtent_binding does not match sod-verify output');
  }

  // dg13 binding must equal dg-map output (same DG13 hash)
  if (dg13.publicOutputs.binding !== dgMap.publicOutputs.dg_binding) {
    errors.push('dg13 binding does not match dg-map output');
  }

  const commitment = dg13.publicOutputs.commitment;

  // Build conditionID lookup maps
  const discloseByID = new Map(conditions.disclose.map((d) => [d.conditionID, d]));
  const predicateByID = new Map(conditions.predicates.map((p) => [p.conditionID, p]));

  // --- 3. Verify condition-linked proofs: commitment, circuitId, tag_id, params ---
  const conditionProofs = proofs.filter((p) => p.conditionID !== undefined);
  for (const entry of conditionProofs) {
    const cid = entry.conditionID!;

    // 3a. Commitment must match dg13-merklelize output
    if (commitment !== undefined && entry.publicInputs.commitment !== commitment) {
      errors.push(`Proof "${cid}" commitment mismatch`);
      continue;
    }

    const disclose = discloseByID.get(cid);
    const predicate = predicateByID.get(cid);

    if (disclose) {
      // 3b. Circuit must be dg13-field-reveal
      if (entry.circuitId !== 'dg13-field-reveal') {
        errors.push(`Proof "${cid}" expected circuitId "dg13-field-reveal", got "${entry.circuitId}"`);
        continue;
      }
      // 3c. tag_id must match the requested field
      const expectedTagId = toHex(BigInt(fieldIdToTagId(disclose.field)));
      if (entry.publicInputs.tag_id !== expectedTagId) {
        errors.push(`Proof "${cid}" tag_id mismatch: expected ${expectedTagId} for field "${disclose.field}", got ${entry.publicInputs.tag_id}`);
        continue;
      }
      disclosedFields[disclose.field] = decodeFieldRevealOutputs(entry.publicOutputs);
    } else if (predicate) {
      // 3b. Circuit must match the operator
      const expectedCircuit = PREDICATE_CIRCUIT_MAP[predicate.operator];
      if (entry.circuitId !== expectedCircuit) {
        errors.push(`Proof "${cid}" expected circuitId "${expectedCircuit}", got "${entry.circuitId}"`);
        continue;
      }
      // 3c. tag_id must match the requested field
      const expectedTagId = toHex(BigInt(fieldIdToTagId(predicate.field)));
      if (entry.publicInputs.tag_id !== expectedTagId) {
        errors.push(`Proof "${cid}" tag_id mismatch: expected ${expectedTagId} for field "${predicate.field}", got ${entry.publicInputs.tag_id}`);
        continue;
      }
      // 3d. Predicate params must match the request
      const expectedParams = flattenPredicateParams(predicate);
      for (const [key, value] of Object.entries(expectedParams)) {
        if (String(entry.publicInputs[key]) !== String(value)) {
          errors.push(`Proof "${cid}" param "${key}" mismatch: expected ${value}, got ${entry.publicInputs[key]}`);
        }
      }
    } else {
      errors.push(`Proof "${cid}" does not match any requested condition`);
    }
  }

  // --- 4. Check all required conditions are covered ---
  for (const d of conditions.disclose) {
    if (!conditionProofs.some((p) => p.conditionID === d.conditionID)) {
      if (!d.optional) errors.push(`Missing proof for "${d.conditionID}"`);
    }
  }

  for (const p of conditions.predicates) {
    if (p.operator === 'equals' && 'ref' in (p.params as Record<string, unknown>)) continue;
    if (!conditionProofs.some((pr) => pr.conditionID === p.conditionID)) {
      if (!p.optional) errors.push(`Missing proof for "${p.conditionID}"`);
    }
  }

  return { verified: errors.length === 0, disclosedFields, errors };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function detectProfile(credential: MatchableCredential) {
  const proof = credential.proof as Record<string, unknown> | undefined;
  if (proof && typeof proof.dgProfile === 'string') {
    const profile = getProfile(proof.dgProfile);
    if (profile) return profile;
  }
  const credTypes = credential.type as readonly string[];
  for (const t of credTypes) {
    const profile = getProfileByDocType(t);
    if (profile) return profile;
  }
  return undefined;
}

function extractRawDGs(credential: MatchableCredential): Record<string, string> {
  const rawDGs: Record<string, string> = {};
  for (const [key, value] of Object.entries(credential.credentialSubject)) {
    if (key.startsWith('dg') && typeof value === 'string') {
      rawDGs[key] = value;
    }
  }
  return rawDGs;
}

/**
 * Decode dg13-field-reveal publicOutputs (length + data_0..data_3) into a UTF-8 string.
 * Each data_N is a hex-encoded packed chunk. `length` is the total byte count.
 */
function decodeFieldRevealOutputs(outputs: Record<string, unknown>): string {
  const length = Number(outputs.length);
  if (!length || length <= 0) return '';

  const chunks = [outputs.data_0, outputs.data_1, outputs.data_2, outputs.data_3]
    .map((v) => String(v ?? '0x00'));

  const bytes: number[] = [];
  for (const chunk of chunks) {
    const hex = chunk.startsWith('0x') ? chunk.slice(2) : chunk;
    if (hex === '00' || hex === '0') continue;
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.slice(i, i + 2), 16));
    }
  }

  return new TextDecoder().decode(new Uint8Array(bytes.slice(0, length)));
}

function arraysEqual(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function flattenPredicateParams(p: PredicateCondition): Record<string, unknown> {
  const params = p.params as Record<string, unknown>;
  if (p.operator === 'inRange') {
    return { lower_bound: params.gte, upper_bound: params.lte };
  }
  if ('value' in params) {
    return { threshold: params.value };
  }
  return {};
}
