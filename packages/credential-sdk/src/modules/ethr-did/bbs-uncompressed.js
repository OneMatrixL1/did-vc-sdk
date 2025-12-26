import { bls12_381 as bls } from '@noble/curves/bls12-381';

/**
 * Convert BBSPublicKey or compressed G2 buffer to 192-byte uncompressed G2 format
 *
 * @param {Object|Uint8Array} bbsPublicKeyOrBuffer - BBSPublicKey instance from @docknetwork/crypto-wasm-ts or 96-byte compressed buffer
 * @returns {Uint8Array} 192-byte uncompressed G2 public key
 * @throws {Error} If decompression fails
 */
export function getUncompressedG2PublicKey(bbsPublicKeyOrBuffer) {
  if (bbsPublicKeyOrBuffer.length === 96) {
    const keyBytes = bbsPublicKeyOrBuffer instanceof Uint8Array
      ? bbsPublicKeyOrBuffer
      : new Uint8Array(bbsPublicKeyOrBuffer);

    // Parse the compressed point and convert to uncompressed format
    const point = bls.G2.ProjectivePoint.fromHex(keyBytes);
    return point.toRawBytes(false); // false = uncompressed format
  } else if (bbsPublicKeyOrBuffer.length === 192) {
    return bbsPublicKeyOrBuffer;
  } else {
    throw new Error('Invalid BBS+ G2 public key');
  }
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
    const point = bls.G2.ProjectivePoint.fromHex(uncompressedKey);

    // Convert to compressed format (96 bytes)
    const compressedKey = point.toRawBytes(true); // true = compressed format

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
