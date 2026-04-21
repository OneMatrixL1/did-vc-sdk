/**
 * Bignum → limbs conversion for the did-delegate circuit.
 *
 * The circuit declares `chipPubKeyLimbs: u128[18]` / `signatureLimbs: u128[18]`,
 * matching the `BigNum<18, BN2048>` convention used by noir-bignum: 18 limbs
 * of 120 bits each, stored little-endian (limb[0] = least significant).
 *
 * The circuit ABI encodes u128 as a JSON field — we ship each limb as a
 * decimal string so bb.js/noir_js passes them through unchanged.
 *
 * Barrett reduction helper:
 *   redc = ⌊2^(2·limbs·bitsPerLimb) / modulus⌋
 * which is how `noir-bignum` precomputes the Barrett parameter. If this
 * circuit ends up using 128-bit limbs instead, change `BITS_PER_LIMB` to 128.
 */

export const LIMB_COUNT = 18;
export const BITS_PER_LIMB = 120; // flip to 128 if the circuit disagrees

/**
 * Declared modulus width for the circuit's `BigNumParams<18, 2048>` instance.
 * The did-delegate circuit is specifically RSA-2048, so MOD_BITS is constant.
 */
export const MOD_BITS = 2048;

/**
 * Extra overflow bits used by noir-bignum v0.9.2's `__barrett_reduction`
 * (see `BARRETT_REDUCTION_OVERFLOW_BITS` in unconstrained_helpers.nr). The
 * redc_param must be computed with exactly this margin or the constrained
 * RSA multiplications fail their quadratic-remainder assertion.
 */
export const BARRETT_OVERFLOW_BITS = 6;

/** Convert big-endian bytes → 18-limb little-endian bignum (decimal strings). */
export function bytesToLimbs(beBytes: Uint8Array): string[] {
  let n = 0n;
  for (let i = 0; i < beBytes.length; i++) {
    n = (n << 8n) | BigInt(beBytes[i] ?? 0);
  }
  return bigintToLimbs(n);
}

export function bigintToLimbs(n: bigint): string[] {
  const mask = (1n << BigInt(BITS_PER_LIMB)) - 1n;
  const limbs: string[] = [];
  let x = n;
  for (let i = 0; i < LIMB_COUNT; i++) {
    limbs.push((x & mask).toString());
    x >>= BigInt(BITS_PER_LIMB);
  }
  if (x !== 0n) {
    throw new Error(
      `bigint exceeds ${LIMB_COUNT}·${BITS_PER_LIMB} bits — cannot fit into fixed-width bignum`,
    );
  }
  return limbs;
}

/**
 * Compute Barrett reduction parameter matching noir-bignum v0.9.2:
 *   redc_param = ⌊2^(MOD_BITS·2 + BARRETT_OVERFLOW_BITS) / modulus⌋
 *
 * `MOD_BITS` is the circuit's declared modulus width (2048 here), **not**
 * the bit-length of the specific modulus value. The 6-bit overflow margin
 * is required so that the constrained Barrett multiplication in
 * `evaluate_quadratic_expression` doesn't exceed its error bound.
 */
export function computeBarrettRedc(modulusBE: Uint8Array): string[] {
  let modulus = 0n;
  for (let i = 0; i < modulusBE.length; i++) {
    modulus = (modulus << 8n) | BigInt(modulusBE[i] ?? 0);
  }
  if (modulus === 0n) throw new Error('Barrett redc: modulus is zero');
  const shift = BigInt(MOD_BITS * 2 + BARRETT_OVERFLOW_BITS);
  const redc = (1n << shift) / modulus;
  return bigintToLimbs(redc);
}
