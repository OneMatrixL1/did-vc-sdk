/**
 * Maps DID SDK field IDs (from ICAO profile) to Merkle tree leaf indices.
 *
 * The dg13-merklelize-circuit assigns leaf index = (tag_id - 1) where tag_id
 * is the DG13 TLV INTEGER tag value. The VN-CCCD-2024 profile's `at` property
 * matches this tag_id exactly.
 *
 * IMPORTANT: fatherName and motherName share tag 13 (leaf index 12).
 * The Merkle tree treats the entire parentsInfo field as a single leaf.
 * Selective disclosure of fatherName or motherName reveals the full
 * parentsInfo value — subfield isolation is not possible at the circuit level.
 */

import type { MerkleWitnessData } from '../types/merkle.js';

const FIELD_TAG_MAP: Record<string, number> = {
  documentNumber: 1,
  idNumber: 1,
  fullName: 2,
  dateOfBirth: 3,
  age: 3,
  gender: 4,
  nationality: 5,
  ethnicity: 6,
  religion: 7,
  hometown: 8,
  permanentAddress: 9,
  address: 9,
  identifyingMarks: 10,
  issueDate: 11,
  expiryDate: 12,
  parentsInfo: 13,
  fatherName: 13,
  motherName: 13,
  spouse: 14,
  oldIdNumber: 15,
  personalIdCode: 16,
};

const MERKLE_DEPTH = 5;

export function fieldIdToTagId(fieldId: string): number {
  const tagId = FIELD_TAG_MAP[fieldId];

  if (tagId === undefined) {
    throw new Error(`Unknown DG13 field "${fieldId}" for Merkle disclosure`);
  }

  return tagId;
}

export function fieldIdToLeafIndex(fieldId: string): number {
  return fieldIdToTagId(fieldId) - 1;
}

export function extractSiblingsForLeaf(
  leafIndex: number,
  witness: MerkleWitnessData,
): string[] {
  if (leafIndex < 0 || leafIndex >= witness.leaves.length) {
    throw new Error(`Leaf index ${leafIndex} out of range [0, ${witness.leaves.length})`);
  }

  const allLevels = [witness.leaves, ...witness.levels];

  const siblings: string[] = [];

  let idx = leafIndex;

  for (let level = 0; level < MERKLE_DEPTH; level++) {
    const siblingIdx = idx ^ 1;

    const levelData = allLevels[level];

    if (!levelData || siblingIdx >= levelData.length) {
      throw new Error(
        `Merkle tree structure invalid at level ${level}, sibling index ${siblingIdx}`,
      );
    }

    siblings.push(levelData[siblingIdx]!);

    idx >>= 1;
  }

  return siblings;
}

export function isDg13Field(fieldId: string): boolean {
  return fieldId in FIELD_TAG_MAP;
}
