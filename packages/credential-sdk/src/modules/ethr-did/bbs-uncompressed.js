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

/**
 * Create public key buffer suitable for contract interaction
 *
 * This function ensures the public key is in the 192-byte uncompressed format
 * required by EthereumDIDRegistry contract's BLS verification precompiles.
 *
 * @param {Object} keypair - BBS keypair instance
 * @returns {Uint8Array} 192-byte uncompressed G2 public key for contract use
 * @throws {Error} If uncompressed serialization is not available
 */
export function createContractPublicKeyBuffer(keypair) {
  if (!keypair || !keypair.pk) {
    throw new Error('Keypair must have pk (public key) property');
  }

  return getUncompressedG2PublicKey(keypair.pk);
}

/**
 * Migration helper: Understand the key format transition
 *
 * This helper documents the breaking change and provides guidance for migration.
 *
 * **Old Format (Compressed G2)**:
 * - Size: 96 bytes
 * - Format: x-coordinate only, y-coordinate computed from curve equation
 * - Used: Previously by SDK for BBS signatures
 * - NOT compatible with: Ethereum smart contract precompiles
 *
 * **New Format (Uncompressed G2)**:
 * - Size: 192 bytes
 * - Format: Both x and y coordinates explicitly stored
 * - Structure: [x0_hi(48), x0_lo(48), x1_hi(48), x1_lo(48), y0_hi(48), y0_lo(48), y1_hi(48), y1_lo(48)]
 * - Used: Required for smart contract BLS verification
 * - Compatible with: EIP-2537 BLS12-381 precompiles
 *
 * **Migration Path**:
 * 1. Update @docknetwork/crypto-wasm-ts to support uncompressed serialization
 * 2. Use `getUncompressedG2PublicKey()` to get contract-compatible keys
 * 3. Regenerate all BBS keypairs and Ethereum addresses
 * 4. Update test data with new 192-byte keys
 * 5. Redeploy smart contract with updated expectations
 *
 * @returns {Object} Migration information object
 */
export function getMigrationInfo() {
  return {
    status: 'AWAITING_LIBRARY_SUPPORT',
    description: 'Uncompressed G2 serialization support needed in @docknetwork/crypto-wasm-ts',
    oldFormat: {
      name: 'Compressed G2',
      size: 96,
      compatible: false,
    },
    newFormat: {
      name: 'Uncompressed G2',
      size: 192,
      compatible: true,
    },
    breakingChange: true,
    requiredActions: [
      'Update @docknetwork/crypto-wasm-ts library',
      'Regenerate all BBS keypairs',
      'Recalculate all Ethereum addresses',
      'Update all test data',
      'Redeploy smart contract',
    ],
  };
}

export default {
  getUncompressedG2PublicKey,
  compressG2PublicKey,
  createContractPublicKeyBuffer,
  getMigrationInfo,
};
