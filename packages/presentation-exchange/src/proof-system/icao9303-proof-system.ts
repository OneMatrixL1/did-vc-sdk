/**
 * ICAO 9303 ZKP Proof System.
 *
 * Implements SchemaProofSystem for ICAO credentials (CCCD, Passport).
 * Internally uses a pipeline to orchestrate:
 *   parse DG13 → build Merkle tree → prove SOD → prove DG13 → field-reveals → predicates
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

export interface ICAOCredentialData {
  sodBytes: Uint8Array;
  dg13Bytes: Uint8Array;
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
      if (!data?.sodBytes || !data?.dg13Bytes) {
        throw new Error('ICAO proof system requires credentialData with sodBytes and dg13Bytes');
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
        sodBytes: data.sodBytes,
        dg13Bytes: data.dg13Bytes,
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
// Pipeline construction
// ---------------------------------------------------------------------------

function buildICAOPipeline(
  conditions: { disclose: DiscloseCondition[]; predicates: PredicateCondition[] },
  poseidon2: Poseidon2Hasher,
  treeBuild: MerkleTreeBuilder,
): PipelineStep[] {
  const steps: PipelineStep[] = [
    // Step 1: Parse DG13 + build Merkle tree
    {
      kind: 'compute',
      label: 'parse-and-merklelize',
      async run(state) {
        const dg13Bytes = state.bag.get('dg13Bytes') as Uint8Array;
        const { fields, salt } = parseDG13Fields(dg13Bytes);

        // Compute packed_hash from immutable fields using poseidon2
        const immutableIndices = [0, 2, 5, 7, 12];
        const immutablePacked: bigint[] = [];
        for (const idx of immutableIndices) {
          const f = fields[idx]!;
          immutablePacked.push(...f.packedFields);
        }
        const packedHash = poseidon2.hash(immutablePacked, 20);

        // Set packedHash on all fields
        for (const f of fields) {
          f.packedHash = packedHash;
        }

        const tree = treeBuild(fields, salt, poseidon2);

        state.bag.set('fields', fields);
        state.bag.set('salt', salt);
        state.bag.set('tree', tree);
      },
    },

    // Step 2: Prove SOD signature (pure ECDSA verify)
    {
      kind: 'prove',
      label: 'sod-verify',
      circuitId: 'sod-verify',
      buildInputs(state) {
        return {
          privateInputs: { sodBytes: state.bag.get('sodBytes') },
          publicInputs: {},
        };
      },
      processOutputs(state, result) {
        state.bag.set('econtentBinding', result.publicOutputs.econtent_binding);
      },
      satisfies: [],
    },

    // Step 3: Extract DG13 hash from signed eContent
    {
      kind: 'prove',
      label: 'dg-map',
      circuitId: 'dg-map',
      buildInputs(state) {
        return {
          privateInputs: { sodBytes: state.bag.get('sodBytes') },
          publicInputs: {
            econtent_binding: state.bag.get('econtentBinding'),
            dg_number: 13,
          },
        };
      },
      processOutputs(state, result) {
        state.bag.set('dgBinding', result.publicOutputs.dg_binding);
      },
      satisfies: [],
    },

    // Step 4: Prove DG13 merklelization
    {
      kind: 'prove',
      label: 'dg13-merklelize',
      circuitId: 'dg13-merklelize',
      buildInputs(state) {
        return {
          privateInputs: {
            fields: state.bag.get('fields'),
            salt: state.bag.get('salt'),
          },
          publicInputs: {
            salt: state.bag.get('salt'),
          },
        };
      },
      processOutputs(state, result) {
        // dg13-merklelize outputs [binding, identity, commitment]
        state.bag.set('binding', result.publicOutputs.binding);
        state.bag.set('identity', result.publicOutputs.identity);
        state.bag.set('commitment', result.publicOutputs.commitment);
      },
      satisfies: [],
    },
  ];

  // Step 4+: Field reveals
  for (const d of conditions.disclose) {
    if (!isDg13Field(d.field)) continue;

    steps.push({
      kind: 'prove',
      label: `reveal-${d.field}`,
      circuitId: 'dg13-field-reveal',
      buildInputs(state) {
        const tree = state.bag.get('tree') as { getSiblings(i: number): bigint[] };
        const fields = state.bag.get('fields') as Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }>;
        const leafIndex = fieldIdToLeafIndex(d.field);
        const field = fields[leafIndex]!;

        return {
          privateInputs: {
            siblings: tree.getSiblings(leafIndex),
            length: field.length,
            data: field.packedFields,
            packed_hash: field.packedHash,
          },
          publicInputs: {
            commitment: state.bag.get('commitment'),
            salt: state.bag.get('salt'),
            tag_id: fieldIdToTagId(d.field),
          },
        };
      },
      processOutputs() {},
      satisfies: [d.conditionID],
    });
  }

  // Step N+: Predicate proofs
  for (const p of conditions.predicates) {
    if (p.operator === 'equals' && 'ref' in p.params) {
      // Cross-doc equals — handled separately at VP level
      continue;
    }

    const circuitId = PREDICATE_CIRCUIT_MAP[p.operator];
    if (!circuitId) {
      throw new Error(`No circuit for predicate operator "${p.operator}"`);
    }

    steps.push({
      kind: 'prove',
      label: `predicate-${p.conditionID}`,
      circuitId,
      buildInputs(state) {
        const tree = state.bag.get('tree') as { getSiblings(i: number): bigint[] };
        const fields = state.bag.get('fields') as Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }>;
        const leafIndex = fieldIdToLeafIndex(p.field);
        const field = fields[leafIndex]!;

        return {
          privateInputs: {
            siblings: tree.getSiblings(leafIndex),
            length: field.length,
            data: field.packedFields,
            packed_hash: field.packedHash,
          },
          publicInputs: {
            commitment: state.bag.get('commitment'),
            salt: state.bag.get('salt'),
            tag_id: fieldIdToTagId(p.field),
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

    const fieldValue = String(proof.publicOutputs.field_value ?? proof.publicOutputs.data ?? '');
    fieldReveals.push({
      conditionID: d.conditionID,
      field: d.field,
      fieldValue,
      proofValue: proof.proofValue,
      publicInputs: proof.publicInputs as ICAOFieldReveal['publicInputs'],
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
    sodVerify: { proofValue: sodVerifyProof.proofValue, publicOutputs: sodVerifyProof.publicOutputs as ICAO9303ZKPProofBundle['sodVerify']['publicOutputs'] },
    dgMap: { proofValue: dgMapProof.proofValue, publicOutputs: dgMapProof.publicOutputs as ICAO9303ZKPProofBundle['dgMap']['publicOutputs'] },
    dg13: { proofValue: dg13Proof.proofValue, publicOutputs: dg13Proof.publicOutputs as ICAO9303ZKPProofBundle['dg13']['publicOutputs'] },
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
    publicInputs: {},
    publicOutputs: bundle.sodVerify.publicOutputs,
  });
  if (!sodValid) errors.push('SOD verify proof invalid');

  // 2. Verify DG map + chain to SOD
  const dgMapValid = await zkpProvider.verify({
    circuitId: 'dg-map',
    proofValue: bundle.dgMap.proofValue,
    publicInputs: { econtent_binding: bundle.sodVerify.publicOutputs.econtent_binding },
    publicOutputs: bundle.dgMap.publicOutputs,
  });
  if (!dgMapValid) errors.push('DG map proof invalid');

  // 3. Verify DG13 merklelize + chain to DG map
  const dg13Valid = await zkpProvider.verify({
    circuitId: 'dg13-merklelize',
    proofValue: bundle.dg13.proofValue,
    publicInputs: {},
    publicOutputs: bundle.dg13.publicOutputs,
  });
  if (!dg13Valid) errors.push('DG13 merklelize proof invalid');

  // Chain: dg13.binding must equal dgMap.dg_binding
  if (bundle.dg13.publicOutputs.binding !== bundle.dgMap.publicOutputs.dg_binding) {
    errors.push('DG13 binding does not match DG map output');
  }

  const commitment = bundle.dg13.publicOutputs.commitment;

  // 3. Verify field reveals + chain to commitment
  for (const fr of bundle.fieldReveals) {
    if (fr.publicInputs.commitment !== commitment) {
      errors.push(`Field reveal "${fr.field}" commitment mismatch`);
      continue;
    }

    const valid = await zkpProvider.verify({
      circuitId: 'dg13-field-reveal',
      proofValue: fr.proofValue,
      publicInputs: fr.publicInputs,
      publicOutputs: { data: fr.fieldValue },
    });

    if (!valid) {
      errors.push(`Field reveal "${fr.field}" proof invalid`);
    } else {
      disclosedFields[fr.field] = fr.fieldValue;
    }
  }

  // 4. Verify predicates + chain to commitment
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

  // 5. Check all required conditions are covered
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

/**
 * Parse DG13 TLV bytes into Merkle leaf inputs.
 *
 * DG13 structure: repeating [0x02 0x01 tagNum] [valueTag valueLen value...]
 * Each field becomes a leaf with 4 packed field elements (31 bytes each).
 * Matches the packing logic in dg13-merklelize circuit exactly.
 */
function parseDG13Fields(dg13Bytes: Uint8Array): {
  fields: Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }>;
  salt: bigint;
} {
  // Parse TLV fields from raw DG13 bytes
  const rawFields = new Map<number, { offset: number; length: number }>();
  let offset = 0;

  while (offset < dg13Bytes.length - 3) {
    if (dg13Bytes[offset] === 0x02 && dg13Bytes[offset + 1] === 0x01) {
      const tagNum = dg13Bytes[offset + 2]!;
      const nextOffset = offset + 3;

      if (nextOffset < dg13Bytes.length) {
        let valueLen = dg13Bytes[nextOffset + 1]!;
        let headerSize = 2;

        if (valueLen & 0x80) {
          const lenBytes = valueLen & 0x7F;
          valueLen = 0;
          for (let i = 0; i < lenBytes; i++) {
            valueLen = (valueLen << 8) | dg13Bytes[nextOffset + 2 + i]!;
          }
          headerSize = 2 + lenBytes;
        }

        rawFields.set(tagNum, {
          offset: nextOffset + headerSize,
          length: valueLen,
        });

        offset = nextOffset + headerSize + valueLen;
        continue;
      }
    }
    offset++;
  }

  // Generate random salt
  const saltBytes = new Uint8Array(31);
  crypto.getRandomValues(saltBytes);
  let salt = 0n;
  for (const b of saltBytes) salt = salt * 256n + BigInt(b);

  // Build 32 leaf inputs (matching circuit's 32-leaf tree)
  const fields: Array<{ tagId: number; length: number; packedFields: bigint[]; packedHash: bigint }> = [];

  // Immutable field indices for packed_hash (matching circuit: indices 0, 2, 5, 7, 12)
  const immutableIndices = [0, 2, 5, 7, 12];
  const immutablePacked: bigint[] = [];

  for (let i = 0; i < 32; i++) {
    const tagId = i + 1;
    const raw = rawFields.get(tagId);
    const dataBytes = raw
      ? dg13Bytes.slice(raw.offset, raw.offset + raw.length)
      : new Uint8Array(0);
    const length = dataBytes.length;

    // Pack into 4 field elements of up to 31 bytes each
    const packedFields: bigint[] = [];
    for (let f = 0; f < 4; f++) {
      let felt = 0n;
      for (let b = 0; b < 31; b++) {
        const byteIdx = f * 31 + b;
        if (byteIdx < length) {
          felt = felt * 256n + BigInt(dataBytes[byteIdx]!);
        }
      }
      packedFields.push(felt);
    }

    // Collect immutable field packed values
    if (immutableIndices.includes(i)) {
      immutablePacked.push(...packedFields);
    }

    fields.push({ tagId, length, packedFields, packedHash: 0n }); // packedHash filled below
  }

  // Compute packed_hash = Poseidon2(immutablePacked, 20)
  // This requires the Poseidon2 hasher — we'll compute it in the compute step instead
  // For now, set packedHash to 0 and let the compute step fill it
  // (The compute step has access to poseidon2)

  return { fields, salt };
}

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
