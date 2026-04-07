/**
 * Merkle-tree selective disclosure types.
 *
 * Used for field-level privacy within DG13: each field can be independently
 * proven via its Merkle path without revealing other fields.
 *
 * Tree parameters (matching dg13-merklelize-circuit):
 *   Leaves: 32, Depth: 5, Hash: Poseidon2 (BN254)
 *   Leaf = Poseidon2([tagId, length, data[0..3], salt, packedHash], 8)
 *   Node = Poseidon2([left, right], 2)
 *   Commitment = Poseidon2([root, salt], 2)
 */

export interface MerkleFieldData {
  tagId: number;
  length: number;
  packedFields: string[];
  rawBytes: number[];
}

export interface MerkleWitnessData {
  salt: string;
  packedHash: string;
  leaves: string[];
  levels: string[][];
  merkleRoot: string;
  commitment: string;
  fieldData: MerkleFieldData[];
}

export interface MerkleDisclosureProof {
  type: 'MerkleDisclosureProof';
  conditionID: string;
  fieldIndex: number;
  fieldValue: string;
  leafPreimage: {
    tagId: number;
    length: number;
    data: string[];
    salt: string;
    packedHash: string;
  };
  siblings: string[];
  commitment: string;
  dependsOn?: Record<string, string>;
}
