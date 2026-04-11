/**
 * Poseidon2 Merkle tree builder.
 *
 * Must produce identical results to the dg13-merklelize Noir circuit:
 *   Leaf = Poseidon2([tagId, length, data[0..3], salt, packedHash], 8)
 *   Node = Poseidon2([left, right], 2)
 *   Commitment = Poseidon2([root, salt], 2)
 *
 * Tree: 32 leaves, depth 5.
 */

import type { Poseidon2Hasher } from './poseidon2.js';

export const TREE_DEPTH = 5;
export const TREE_LEAVES = 32;

export interface LeafInput {
  tagId: number;
  length: number;
  packedFields: bigint[];
  packedHash: bigint;
}

export interface MerkleTree {
  root: bigint;
  commitment: bigint;
  leaves: bigint[];
  getSiblings(leafIndex: number): bigint[];
}

export function buildMerkleTree(
  fields: LeafInput[],
  salt: bigint,
  hasher: Poseidon2Hasher,
): MerkleTree {
  // Build leaves
  const leaves: bigint[] = [];
  for (const f of fields) {
    if (f.packedFields.length !== 4) {
      throw new Error(`LeafInput must have exactly 4 packedFields, got ${f.packedFields.length}`);
    }
    leaves.push(hasher.hash([
      BigInt(f.tagId),
      BigInt(f.length),
      f.packedFields[0]!,
      f.packedFields[1]!,
      f.packedFields[2]!,
      f.packedFields[3]!,
      salt,
      f.packedHash,
    ], 8));
  }

  // Pad to 32 leaves
  while (leaves.length < TREE_LEAVES) {
    leaves.push(0n);
  }

  // Build tree levels bottom-up
  const levels: bigint[][] = [leaves.slice()];
  let current = leaves;
  while (current.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(hasher.hash([current[i]!, current[i + 1]!], 2));
    }
    levels.push(next);
    current = next;
  }

  const root = current[0]!;
  const commitment = hasher.hash([root, salt], 2);

  return {
    root,
    commitment,
    leaves: levels[0]!,
    getSiblings(leafIndex: number): bigint[] {
      if (leafIndex < 0 || leafIndex >= TREE_LEAVES) {
        throw new Error(`leafIndex ${leafIndex} out of range [0, ${TREE_LEAVES})`);
      }
      const siblings: bigint[] = [];
      let idx = leafIndex;
      for (let level = 0; level < TREE_DEPTH; level++) {
        const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
        siblings.push(levels[level]![siblingIdx]!);
        idx = Math.floor(idx / 2);
      }
      return siblings;
    },
  };
}
