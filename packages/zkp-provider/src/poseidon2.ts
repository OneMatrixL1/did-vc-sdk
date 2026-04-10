/**
 * Production Poseidon2 hasher using @aztec/bb.js BarretenbergSync.
 *
 * Matches the Poseidon2 inside Noir circuits (BN254 curve).
 * Used by the ICAO proof system for Merkle tree construction.
 */

const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface Poseidon2Hasher {
  hash(inputs: bigint[], len: number): bigint;
}

/** Convert a bigint to a 32-byte big-endian Uint8Array (BN254 field element). */
function bigintToBytes32(val: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let v = val;
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

/** Convert a 32-byte big-endian Uint8Array to bigint. */
function bytes32ToBigint(buf: Uint8Array): bigint {
  let val = 0n;
  for (const b of buf) val = val * 256n + BigInt(b);
  return val;
}

export async function createPoseidon2Hasher(): Promise<Poseidon2Hasher> {
  const { BarretenbergSync } = await import('@aztec/bb.js');

  await BarretenbergSync.initSingleton();
  const bb = BarretenbergSync.getSingleton();

  return {
    hash(inputs: bigint[], len: number): bigint {
      const fields: Uint8Array[] = [];
      for (let i = 0; i < len && i < inputs.length; i++) {
        const val = inputs[i]!;
        if (val < 0n || val >= BN254_PRIME) {
          throw new Error(`Poseidon2 input[${i}] out of BN254 field range`);
        }
        fields.push(bigintToBytes32(val));
      }
      const result = bb.poseidon2Hash({ inputs: fields });
      return bytes32ToBigint(result.hash);
    },
  };
}
