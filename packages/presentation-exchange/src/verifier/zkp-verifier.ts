/**
 * Generic ZKP and Merkle disclosure verification.
 *
 * Every ZKPProof is verified with bb.verify.
 * Every MerkleDisclosureProof is verified with Poseidon2 tree walk.
 * Dependencies between proofs are checked via dependsOn:
 *   dependsOn: { "outputKey": "conditionID" }
 *   -> proof.publicInputs[outputKey] or proof.commitment
 *      must == referenced proof's publicOutputs[outputKey]
 */

import type { VPRequest, DocumentRequestNode, ZKPCondition } from '../types/request.js';
import type { VerifiablePresentation, PresentedCredential } from '../types/response.js';
import type { ZKPProof, CredentialProof } from '../types/credential.js';
import type { MerkleDisclosureProof } from '../types/merkle.js';
import type { ZKPProvider, Poseidon2Hasher } from '../types/zkp-provider.js';
import { extractConditions } from '../resolver/field-extractor.js';

const MERKLE_DEPTH = 5;

export interface ZKPProofResult {
  conditionID: string;

  type: 'ZKPProof' | 'MerkleDisclosureProof';

  verified: boolean;

  error?: string;
}

export interface ZKPVerificationResult {
  verified: boolean;

  proofResults: ZKPProofResult[];
}

export async function verifyZKPProofs(
  request: VPRequest,
  presentation: VerifiablePresentation,
  poseidon2: Poseidon2Hasher,
  zkpProvider?: ZKPProvider,
): Promise<ZKPVerificationResult> {
  const results: ZKPProofResult[] = [];

  const requestedConditions = collectRequestedConditions(request.rules);

  for (const cred of presentation.verifiableCredential) {
    const proofs = normalizeProofs(cred);

    const outputsMap = new Map<string, Record<string, unknown>>();

    for (const proof of proofs) {
      if (proof.type === 'ZKPProof') {
        const zkp = proof as ZKPProof;

        const result = await verifyZKPProofSingle(zkp, outputsMap, requestedConditions, zkpProvider);

        results.push(result);

        if (result.verified) {
          outputsMap.set(zkp.conditionID, zkp.publicOutputs);
        }

        continue;
      }

      if (proof.type === 'MerkleDisclosureProof') {
        const merkle = proof as MerkleDisclosureProof;

        const result = verifyMerkleProofSingle(merkle, outputsMap, poseidon2);

        results.push(result);
      }
    }
  }

  return {
    verified: results.every((r) => r.verified),
    proofResults: results,
  };
}

async function verifyZKPProofSingle(
  proof: ZKPProof,
  outputsMap: Map<string, Record<string, unknown>>,
  requestedConditions: Map<string, ZKPCondition>,
  zkpProvider?: ZKPProvider,
): Promise<ZKPProofResult> {
  if (!zkpProvider) {
    return {
      conditionID: proof.conditionID,
      type: 'ZKPProof',
      verified: false,
      error: 'No ZKPProvider available',
    };
  }

  const requested = requestedConditions.get(proof.conditionID);

  if (requested && requested.circuitId !== proof.circuitId) {
    return {
      conditionID: proof.conditionID,
      type: 'ZKPProof',
      verified: false,
      error: `Circuit mismatch: request requires "${requested.circuitId}" but proof uses "${proof.circuitId}"`,
    };
  }

  let proofValid: boolean;

  try {
    proofValid = await zkpProvider.verify({
      circuitId: proof.circuitId,
      proofValue: proof.proofValue,
      publicInputs: proof.publicInputs,
      publicOutputs: proof.publicOutputs,
    });
  } catch (err) {
    return {
      conditionID: proof.conditionID,
      type: 'ZKPProof',
      verified: false,
      error: `ZKP provider threw: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (!proofValid) {
    return {
      conditionID: proof.conditionID,
      type: 'ZKPProof',
      verified: false,
      error: `ZKP proof verification failed for circuit "${proof.circuitId}"`,
    };
  }

  const depError = checkDependsOn(proof.dependsOn, proof.publicInputs, proof.publicOutputs, outputsMap);

  if (depError) {
    return {
      conditionID: proof.conditionID,
      type: 'ZKPProof',
      verified: false,
      error: depError,
    };
  }

  return {
    conditionID: proof.conditionID,
    type: 'ZKPProof',
    verified: true,
  };
}

function verifyMerkleProofSingle(
  proof: MerkleDisclosureProof,
  outputsMap: Map<string, Record<string, unknown>>,
  poseidon2: Poseidon2Hasher,
): ZKPProofResult {
  const valid = verifyMerkleInclusion(proof, poseidon2);

  if (!valid) {
    return {
      conditionID: proof.conditionID,
      type: 'MerkleDisclosureProof',
      verified: false,
      error: 'Merkle inclusion proof invalid',
    };
  }

  if (!verifyFieldValue(proof)) {
    return {
      conditionID: proof.conditionID,
      type: 'MerkleDisclosureProof',
      verified: false,
      error: 'fieldValue does not match leafPreimage.data',
    };
  }

  const depError = checkDependsOn(
    proof.dependsOn,
    { commitment: proof.commitment },
    {},
    outputsMap,
  );

  if (depError) {
    return {
      conditionID: proof.conditionID,
      type: 'MerkleDisclosureProof',
      verified: false,
      error: depError,
    };
  }

  return {
    conditionID: proof.conditionID,
    type: 'MerkleDisclosureProof',
    verified: true,
  };
}

function checkDependsOn(
  dependsOn: Record<string, string> | undefined,
  myInputs: Record<string, unknown>,
  myOutputs: Record<string, unknown>,
  outputsMap: Map<string, Record<string, unknown>>,
): string | undefined {
  if (!dependsOn) return undefined;

  for (const [key, refConditionID] of Object.entries(dependsOn)) {
    const refOutputs = outputsMap.get(refConditionID);

    if (!refOutputs) {
      return `Dependency "${refConditionID}" not found or not verified`;
    }

    const refValue = refOutputs[key];

    if (refValue === undefined) {
      return `Dependency "${refConditionID}" has no output "${key}"`;
    }

    const myValue = myInputs[key] ?? myOutputs[key];

    if (myValue === undefined) {
      return `This proof has no input/output "${key}" to match against dependency`;
    }

    if (String(myValue) !== String(refValue)) {
      return `Dependency mismatch: ${key}="${myValue}" != "${refConditionID}".${key}="${refValue}"`;
    }
  }

  return undefined;
}

export function verifyMerkleInclusion(
  proof: MerkleDisclosureProof,
  poseidon2: Poseidon2Hasher,
): boolean {
  try {
    return verifyMerkleInclusionInner(proof, poseidon2);
  } catch {
    return false;
  }
}

function verifyMerkleInclusionInner(
  proof: MerkleDisclosureProof,
  poseidon2: Poseidon2Hasher,
): boolean {
  const { tagId, length, data, salt, packedHash } = proof.leafPreimage;

  if (proof.siblings.length !== MERKLE_DEPTH) return false;

  if (proof.fieldIndex < 0 || proof.fieldIndex >= 32) return false;

  if (data.length !== 4) return false;

  const leafInputs: bigint[] = [
    BigInt(tagId),
    BigInt(length),
    BigInt(data[0]!),
    BigInt(data[1]!),
    BigInt(data[2]!),
    BigInt(data[3]!),
    BigInt(salt),
    BigInt(packedHash),
  ];

  let current = poseidon2.hash(leafInputs, 8);

  let idx = proof.fieldIndex;

  for (let level = 0; level < MERKLE_DEPTH; level++) {
    const sibling = BigInt(proof.siblings[level]!);

    const bit = (idx >> level) & 1;

    const pair: [bigint, bigint] = bit === 0
      ? [current, sibling]
      : [sibling, current];

    current = poseidon2.hash([pair[0], pair[1]], 2);
  }

  const reconstructedCommitment = poseidon2.hash([current, BigInt(salt)], 2);

  const expectedCommitment = BigInt(proof.commitment);

  return reconstructedCommitment === expectedCommitment;
}

function verifyFieldValue(proof: MerkleDisclosureProof): boolean {
  try {
    const { data, length } = proof.leafPreimage;

    const rawBytes: number[] = [];

    for (const packed of data) {
      const val = BigInt(packed);

      const bytes: number[] = [];

      let v = val;

      while (v > 0n) {
        bytes.unshift(Number(v & 0xFFn));

        v >>= 8n;
      }

      rawBytes.push(...bytes);
    }

    const decoded = new TextDecoder().decode(new Uint8Array(rawBytes.slice(0, length)));

    return decoded === proof.fieldValue;
  } catch {
    return false;
  }
}

function collectRequestedConditions(node: DocumentRequestNode): Map<string, ZKPCondition> {
  const map = new Map<string, ZKPCondition>();

  function walk(n: DocumentRequestNode): void {
    if (n.type === 'Logical') {
      for (const child of n.values) walk(child);

      return;
    }

    const { zkp } = extractConditions(n.conditions);

    for (const cond of zkp) {
      map.set(cond.conditionID, cond);
    }
  }

  walk(node);

  return map;
}

function normalizeProofs(cred: PresentedCredential): CredentialProof[] {
  if (!cred.proof) return [];

  return Array.isArray(cred.proof) ? cred.proof : [cred.proof];
}
