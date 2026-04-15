/**
 * Poseidon2 Merkle tree builder (16 leaves, depth 4).
 *
 * Matches the dg13-merklelize circuit's leaf and tree construction exactly:
 *   entropy  = Poseidon2([tagId, length, data[0..3], domain, dgHashHi, dgHashLo], 9)
 *   leaf     = Poseidon2([tagId, length, data[0..3], entropy], 7)
 *   node     = Poseidon2([left, right], 2)
 *   commitment = Poseidon2([root, domain], 2)
 *
 * Pure JS — no WASM or native dependencies.
 */

import { poseidon2BigInt } from './poseidon2.js';
import type { CachedMerkleTree, LeafData, MerkleLeafInput } from './types.js';

export const TREE_DEPTH = 4;
export const TREE_LEAVES = 16;

/**
 * Build a Poseidon2 Merkle tree from DG13 field inputs.
 *
 * @param fields - 16 leaf inputs (tagId, length, packed field data)
 * @param domain - Domain hash (hex field element)
 * @param dgHashHi - Upper 16 bytes of DG13 SHA-256 hash (hex)
 * @param dgHashLo - Lower 16 bytes of DG13 SHA-256 hash (hex)
 */
export function buildMerkleTree(
  fields: MerkleLeafInput[],
  domain: string,
  dgHashHi: string,
  dgHashLo: string,
): CachedMerkleTree {
  const domainBig = BigInt(domain);
  const dgHi = BigInt(dgHashHi);
  const dgLo = BigInt(dgHashLo);

  const leaves: bigint[] = [];
  const leafDataArr: LeafData[] = [];
  const entropies: string[] = [];

  for (let i = 0; i < TREE_LEAVES; i++) {
    const f = fields[i];
    if (!f) {
      leaves.push(0n);
      leafDataArr.push({ length: '0', data: ['0x0', '0x0', '0x0', '0x0'] });
      entropies.push('0x0');
      continue;
    }

    const tagId = BigInt(f.tagId);
    const length = BigInt(f.length);
    const data = f.packedFields.map(BigInt);

    const entropy = poseidon2BigInt(
      [tagId, length, data[0]!, data[1]!, data[2]!, data[3]!, domainBig, dgHi, dgLo],
      9,
    );

    const leaf = poseidon2BigInt(
      [tagId, length, data[0]!, data[1]!, data[2]!, data[3]!, entropy],
      7,
    );

    leaves.push(leaf);
    entropies.push('0x' + entropy.toString(16));
    leafDataArr.push({
      length: f.length.toString(),
      data: f.packedFields,
    });
  }

  // Pad to TREE_LEAVES
  while (leaves.length < TREE_LEAVES) {
    leaves.push(0n);
    leafDataArr.push({ length: '0', data: ['0x0', '0x0', '0x0', '0x0'] });
    entropies.push('0x0');
  }

  // Build tree levels bottom-up
  const levels: bigint[][] = [leaves.slice()];
  let current = leaves;
  while (current.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(poseidon2BigInt([current[i]!, current[i + 1]!], 2));
    }
    levels.push(next);
    current = next;
  }

  const root = current[0]!;
  const commitment = poseidon2BigInt([root, domainBig], 2);

  // Build siblings for each leaf
  const siblings: string[][] = [];
  for (let leafIndex = 0; leafIndex < TREE_LEAVES; leafIndex++) {
    const path: string[] = [];
    let idx = leafIndex;
    for (let level = 0; level < TREE_DEPTH; level++) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      path.push('0x' + levels[level]![siblingIdx]!.toString(16));
      idx = Math.floor(idx / 2);
    }
    siblings.push(path);
  }

  return {
    root: '0x' + root.toString(16),
    commitment: '0x' + commitment.toString(16),
    leaves: entropies,
    siblings,
    leafData: leafDataArr,
  };
}
