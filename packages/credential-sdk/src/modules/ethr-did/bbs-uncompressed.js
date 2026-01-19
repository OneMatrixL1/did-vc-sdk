import { bls12_381 as bls } from '@noble/curves/bls12-381';

/**
 * Ensure BLS G2 public key is in uncompressed format (192 bytes)
 * @param {Uint8Array} publicKey - 96 (compressed) or 192 (uncompressed) bytes
 * @returns {Uint8Array} 192-byte uncompressed G2 public key
 * @throws {Error} If key length is invalid
 */
export function getUncompressedG2PublicKey(publicKey) {
  const keyBytes = publicKey instanceof Uint8Array
    ? publicKey
    : new Uint8Array(publicKey);

  if (keyBytes.length === 192) {
    return keyBytes; // Already uncompressed
  }

  if (keyBytes.length === 96) {
    // Decompress: 96 → 192 bytes
    const point = bls.G2.Point.fromHex(keyBytes);
    return point.toBytes(false);
  }

  throw new Error(`Invalid BLS G2 public key length: ${keyBytes.length} bytes. Expected 96 or 192`);
}

/**
 * Convert 192-byte uncompressed G2 key to 96-byte compressed format
 *
 * @param {Uint8Array} uncompressedKey - 192-byte uncompressed G2 public key
 * @returns {Uint8Array} 96-byte compressed G2 public key
 * @throws {Error} If compression fails or input is invalid
 */
export function compressG2PublicKey(uncompressedKey) {
  if (!uncompressedKey || uncompressedKey.length !== 192) {
    throw new Error(`Expected 192-byte uncompressed G2 key, got ${uncompressedKey?.length || 0} bytes`);
  }

  try {
    // Parse the uncompressed point
    const point = bls.G2.Point.fromHex(uncompressedKey);

    // Convert to compressed format (96 bytes)
    const compressedKey = point.toBytes(true); // true = compressed format

    if (compressedKey.length !== 96) {
      throw new Error(`Compression produced ${compressedKey.length} bytes, expected 96`);
    }

    return new Uint8Array(compressedKey);
  } catch (error) {
    throw new Error(
      `Failed to compress G2 public key: ${error.message}`
    );
  }
}

export default {
  getUncompressedG2PublicKey,
  compressG2PublicKey,
};
