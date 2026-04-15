/**
 * Pure JS Poseidon2 hasher over BN254 — no WASM or native deps.
 *
 * Uses @zkpassport/poseidon2 which implements the same Poseidon2 sponge
 * construction as Noir circuits (noir-lang/poseidon v0.2.6).
 */

import { poseidon2Hash } from '@zkpassport/poseidon2';

/**
 * Poseidon2 hash: takes an array of BN254 field elements (as hex strings)
 * and returns a single field element (hex string).
 *
 * Compatible with Noir's `Poseidon2::hash(inputs, len)`.
 */
export function poseidon2(inputs: string[], len: number): string {
  const fields: bigint[] = [];
  for (let i = 0; i < len && i < inputs.length; i++) {
    fields.push(BigInt(inputs[i]!));
  }
  const result = poseidon2Hash(fields);
  return '0x' + result.toString(16);
}

/**
 * Synchronous bigint-based Poseidon2 hash.
 * Used internally by the Merkle tree builder.
 */
export function poseidon2BigInt(inputs: bigint[], len: number): bigint {
  return poseidon2Hash(inputs.slice(0, len));
}
