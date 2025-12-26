/**
 * BBS Uncompressed G2 Key Handling
 *
 * This module provides utilities for working with 192-byte uncompressed G2 public keys
 * required for Ethereum smart contract compatibility with BLS verification precompiles.
 *
 * The @docknetwork/crypto-wasm-ts library provides compressed G2 keys (96 bytes),
 * but the EthereumDIDRegistry contract requires uncompressed format (192 bytes).
 * This module uses @noble/curves to perform the decompression.
 *
 * @module ethr-did/bbs-uncompressed
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381';

/**
 * Convert BBSPublicKey or compressed G2 buffer to 192-byte uncompressed G2 format
 *
 * The crypto-wasm-ts library's BBSPublicKey class provides `.value` property
 * that returns 96-byte compressed G2 points. This function uses @noble/curves
 * to decompress the point to the 192-byte uncompressed format required by
 * Ethereum smart contracts.
 *
 * @param {Object|Uint8Array} bbsPublicKeyOrBuffer - BBSPublicKey instance from @docknetwork/crypto-wasm-ts or 96-byte compressed buffer
 * @returns {Uint8Array} 192-byte uncompressed G2 public key
 * @throws {Error} If decompression fails
 *
 * @example
 * const keypair = BBSKeypair.generate(params);
 * const uncompressedKey = getUncompressedG2PublicKey(keypair.pk);
 * console.log(uncompressedKey.length); // 192
 *
 * @example
 * // Also works with raw 96-byte buffers
 * const compressedBuffer = new Uint8Array(96);
 * const uncompressedKey = getUncompressedG2PublicKey(compressedBuffer);
 * console.log(uncompressedKey.length); // 192
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
 * This is the inverse of getUncompressedG2PublicKey(). It's needed for BBS
 * signature verification with crypto-wasm-ts which expects compressed keys.
 *
 * @param {Uint8Array} uncompressedKey - 192-byte uncompressed G2 public key
 * @returns {Uint8Array} 96-byte compressed G2 public key
 * @throws {Error} If compression fails or input is invalid
 *
 * @example
 * const uncompressed = bbsKeypair.getPublicKeyBufferUncompressed();
 * const compressed = compressG2PublicKey(uncompressed);
 * const bbsPubKey = new BBSPublicKey(compressed);
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
