/**
 * Production Poseidon2 hasher using @aztec/bb.js BarretenbergSync.
 *
 * Matches the Poseidon2 inside Noir circuits (BN254 curve).
 * Used by presentation-exchange verifier for MerkleDisclosureProof verification.
 *
 * Requires @aztec/bb.js as a peer dependency.
 */

const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface Poseidon2Hasher {
  hash(inputs: bigint[], len: number): bigint;
}

export async function createPoseidon2Hasher(): Promise<Poseidon2Hasher> {
  // @ts-expect-error -- peer dependency, resolved at runtime
  const bbjs = await import('@aztec/bb.js');

  const BarretenbergSync = bbjs.BarretenbergSync;

  const Fr = bbjs.Fr;

  await BarretenbergSync.initSingleton();

  const bb = BarretenbergSync.getSingleton();

  return {
    hash(inputs: bigint[], len: number): bigint {
      const fields: unknown[] = [];

      for (let i = 0; i < len && i < inputs.length; i++) {
        const val = inputs[i]!;

        if (val < 0n || val >= BN254_PRIME) {
          throw new Error(`Poseidon2 input[${i}] out of BN254 field range`);
        }

        fields.push(new Fr(val));
      }

      const result = bb.poseidon2Hash(fields);

      return result.toBigInt();
    },
  };
}
