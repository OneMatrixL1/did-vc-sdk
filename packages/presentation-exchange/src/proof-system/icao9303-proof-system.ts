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
import type { SchemaProofSystem, ProveContext, VerifyContext, ProofVerificationResult } from '../types/proof-system.js';
import type { ICAO9303ZKPProofBundle, ICAOFieldReveal, ICAOPredicateProof } from '../types/icao-proof-bundle.js';
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

      return packageAsCredential(credential, state, conditions);
    },

    async verify(credential, conditions, context) {
      const proof = Array.isArray(credential.proof) ? credential.proof[0] : credential.proof;
      if (!isICAOProofBundle(proof)) {
        return { verified: false, disclosedFields: {}, errors: ['Expected ICAO9303ZKPProofBundle'] };
      }

      return verifyICAOBundle(proof, conditions, context.zkpProvider);
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
        state.bag.set('econtentBinding', result.publicOutputs.output_0);
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
        state.bag.set('dgBinding', result.publicOutputs.output_0);
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
        state.bag.set('binding', result.publicOutputs.output_0);
        state.bag.set('identity', result.publicOutputs.output_1);
        state.bag.set('commitment', result.publicOutputs.output_2);
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
): PresentedCredential {
  const sodVerifyProof = state.proofs.find((p) => p.label === 'sod-verify')!;
  const dgMapProof = state.proofs.find((p) => p.label === 'dg-map')!;
  const dg13Proof = state.proofs.find((p) => p.label === 'dg13-merklelize')!;

  const fieldReveals: ICAOFieldReveal[] = [];
  const subject: Record<string, unknown> = {};

  for (const d of conditions.disclose) {
    const proof = state.proofs.find((p) => p.satisfies.includes(d.conditionID));
    if (!proof) continue;

    // Circuit returns [length, data[0..3]] — field value is in the public outputs
    const fieldValue = String(proof.publicOutputs.output_0 ?? '');
    fieldReveals.push({
      conditionID: d.conditionID,
      field: d.field,
      fieldValue,
      proofValue: proof.proofValue,
      publicInputs: proof.publicInputs,
      publicOutputs: proof.publicOutputs,
    });
    subject[d.field] = fieldValue;
  }

  const predicates: ICAOPredicateProof[] = [];
  for (const p of conditions.predicates) {
    const proof = state.proofs.find((pr) => pr.satisfies.includes(p.conditionID));
    if (!proof) continue;

    predicates.push({
      conditionID: p.conditionID,
      operator: p.operator,
      field: p.field,
      params: p.params as Record<string, unknown>,
      result: proof.publicOutputs.result ?? true,
      proofValue: proof.proofValue,
      publicInputs: proof.publicInputs,
      publicOutputs: proof.publicOutputs,
    });
  }

  const bundle: ICAO9303ZKPProofBundle = {
    type: 'ICAO9303ZKPProofBundle',
    sodVerify: { proofValue: sodVerifyProof.proofValue, publicInputs: sodVerifyProof.publicInputs, publicOutputs: sodVerifyProof.publicOutputs },
    dgMap: { proofValue: dgMapProof.proofValue, publicInputs: dgMapProof.publicInputs, publicOutputs: dgMapProof.publicOutputs },
    dg13: { proofValue: dg13Proof.proofValue, publicInputs: dg13Proof.publicInputs, publicOutputs: dg13Proof.publicOutputs },
    fieldReveals,
    predicates,
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
): Promise<ProofVerificationResult> {
  const errors: string[] = [];
  const disclosedFields: Record<string, string> = {};

  // 1. Verify SOD signature
  const sodValid = await zkpProvider.verify({
    circuitId: 'sod-verify',
    proofValue: bundle.sodVerify.proofValue,
    publicInputs: bundle.sodVerify.publicInputs,
    publicOutputs: bundle.sodVerify.publicOutputs,
  });
  if (!sodValid) errors.push('SOD verify proof invalid');

  // 2. Verify DG map + chain to SOD
  const dgMapValid = await zkpProvider.verify({
    circuitId: 'dg-map',
    proofValue: bundle.dgMap.proofValue,
    publicInputs: bundle.dgMap.publicInputs,
    publicOutputs: bundle.dgMap.publicOutputs,
  });
  if (!dgMapValid) errors.push('DG map proof invalid');

  // 3. Verify DG13 merklelize
  const dg13Valid = await zkpProvider.verify({
    circuitId: 'dg13-merklelize',
    proofValue: bundle.dg13.proofValue,
    publicInputs: bundle.dg13.publicInputs,
    publicOutputs: bundle.dg13.publicOutputs,
  });
  if (!dg13Valid) errors.push('DG13 merklelize proof invalid');

  // Chain: dg13.output_0 (binding) must equal dgMap.output_0 (dg_binding)
  if (bundle.dg13.publicOutputs.output_0 !== bundle.dgMap.publicOutputs.output_0) {
    errors.push('DG13 binding does not match DG map output');
  }

  const commitment = bundle.dg13.publicOutputs.output_2;

  // 4. Verify field reveals + chain to commitment
  for (const fr of bundle.fieldReveals) {
    if (fr.publicInputs.commitment !== commitment) {
      errors.push(`Field reveal "${fr.field}" commitment mismatch`);
      continue;
    }

    const valid = await zkpProvider.verify({
      circuitId: 'dg13-field-reveal',
      proofValue: fr.proofValue,
      publicInputs: fr.publicInputs,
      publicOutputs: fr.publicOutputs,
    });

    if (!valid) {
      errors.push(`Field reveal "${fr.field}" proof invalid`);
    } else {
      disclosedFields[fr.field] = fr.fieldValue;
    }
  }

  // 5. Verify predicates + chain to commitment
  for (const pred of bundle.predicates) {
    if (pred.publicInputs.commitment !== commitment) {
      errors.push(`Predicate "${pred.conditionID}" commitment mismatch`);
      continue;
    }

    const circuitId = PREDICATE_CIRCUIT_MAP[pred.operator];
    if (!circuitId) {
      errors.push(`Unknown predicate operator "${pred.operator}"`);
      continue;
    }

    const valid = await zkpProvider.verify({
      circuitId,
      proofValue: pred.proofValue,
      publicInputs: pred.publicInputs,
      publicOutputs: pred.publicOutputs,
    });

    if (!valid) {
      errors.push(`Predicate "${pred.conditionID}" proof invalid`);
    }
  }

  // 6. Check all required conditions are covered
  for (const d of conditions.disclose) {
    if (!bundle.fieldReveals.some((fr) => fr.conditionID === d.conditionID)) {
      if (!d.optional) errors.push(`Missing field reveal for "${d.conditionID}"`);
    }
  }

  for (const p of conditions.predicates) {
    if (p.operator === 'equals' && 'ref' in (p.params as Record<string, unknown>)) continue;
    if (!bundle.predicates.some((pr) => pr.conditionID === p.conditionID)) {
      if (!p.optional) errors.push(`Missing predicate proof for "${p.conditionID}"`);
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
