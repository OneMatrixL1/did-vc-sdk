import {
  BBSKeypair,
  BBSSignature,
  BBSPublicKey,
  BBSSecretKey,
  BBSSignatureParams,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
} from '@docknetwork/crypto-wasm-ts';

import { Bls12381BBS23DockVerKeyName } from './constants';
import DockCryptoKeyPair from './common/DockCryptoKeyPair';
import { bls12_381 } from '@noble/curves/bls12-381';

export default class Bls12381BBSKeyPairDock2023 extends DockCryptoKeyPair {
  constructor(options) {
    super(options, Bls12381BBS23DockVerKeyName);
  }

  /**
   * Returns the public key as a hex string (0x-prefixed).
   * Used for Ethereum contract calls that expect hex-encoded public keys.
   * BLS12-381 G2 public keys are 96 bytes (compressed).
   * @returns {string} 0x-prefixed hex string (192 characters for 96 bytes)
   */
  get publicKeyHex() {
    if (!this.publicKeyBuffer) {
      throw new Error('No public key available');
    }

    const hexString = Array.from(this.publicKeyBuffer)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');

    return `0x${hexString}`;
  }

  /**
   * Returns the public key as uncompressed hex string (0x-prefixed).
   * Smart contracts typically expect uncompressed G2 points (192 bytes).
   * This method decompresses the 96-byte compressed G2 to 192-byte uncompressed format.
   * @returns {string} 0x-prefixed hex string (384 characters for 192 bytes)
   */
  getPublicKeyUncompressedHex() {
    if (!this.publicKeyBuffer) {
      throw new Error('No public key available');
    }

    // Ensure publicKeyBuffer is Uint8Array
    const pubKeyBytes = this.publicKeyBuffer instanceof Uint8Array
      ? this.publicKeyBuffer
      : new Uint8Array(this.publicKeyBuffer);

    // Load the compressed G2 point
    const g2Point = bls12_381.G2.ProjectivePoint.fromHex(pubKeyBytes);

    // Get uncompressed bytes (192 bytes)
    const uncompressed = g2Point.toRawBytes(false);

    const hexString = Array.from(uncompressed)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');

    return `0x${hexString}`;
  }

  /**
   * Sign a message hash using BLS12-381 with Domain Separation Tag (DST).
   * This method is designed for compatibility with Ethereum smart contracts
   * that verify BLS signatures using hashToPoint + pairing verification.
   *
   * The signing process:
   * 1. Hash the message to a G1 point using hashToG1(DST, messageHash)
   * 2. Sign the G1 point with the BLS12-381 secret key
   * 3. Return the signature bytes (96 bytes uncompressed G1)
   *
   * @param {Uint8Array} messageBytes - 32-byte Keccak256 hash of the message
   * @param {Uint8Array|string} dstBytes - Domain Separation Tag (e.g., "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")
   * @returns {Uint8Array} 96-byte signature (uncompressed G1 point)
   * @throws {Error} If no private key is available
   */
  signBLS(messageBytes, dstBytes) {
    if (!this.privateKeyBuffer) {
      throw new Error('No private key to sign with. Cannot perform BLS signature.');
    }

    // Convert DST to Uint8Array if it's a string
    const dst = typeof dstBytes === 'string'
      ? new TextEncoder().encode(dstBytes)
      : new Uint8Array(dstBytes);

    // Ensure messageBytes is Uint8Array
    const messageHash = messageBytes instanceof Uint8Array
      ? messageBytes
      : new Uint8Array(messageBytes);

    // Validate message hash length
    if (messageHash.length !== 32) {
      throw new Error(`Message hash must be exactly 32 bytes, got ${messageHash.length}`);
    }

    // The secret key is stored as raw bytes (32 bytes for BLS12-381 scalar)
    // Convert to Uint8Array since privateKeyBuffer may be a regular Array or Buffer
    const secretKeyBytes = this.privateKeyBuffer instanceof Uint8Array
      ? this.privateKeyBuffer
      : new Uint8Array(this.privateKeyBuffer);

    // Hash the message to a G1 point using the DST
    // This is equivalent to hashToPoint(DST, messageHash) in the Solidity contract
    const messagePoint = bls12_381.G1.hashToCurve(messageHash, { DST: dst });

    // Sign the message point with the secret key
    // In BLS, signing is: signature = messagePoint * secretKey (scalar multiplication)
    const secretKeyScalar = bls12_381.fields.Fr.fromBytes(secretKeyBytes);
    const signaturePoint = messagePoint.multiply(secretKeyScalar);

    // Return the uncompressed signature (96 bytes for uncompressed G1)
    // Smart contracts typically expect uncompressed G1 points
    return signaturePoint.toRawBytes(false);
  }

  /**
   * Returns the signature as a hex string (0x-prefixed).
   * Convenience method for Ethereum contract calls.
   * @param {Uint8Array} signatureBytes - The signature bytes
   * @returns {string} 0x-prefixed hex string
   */
  static signatureToHex(signatureBytes) {
    const hexString = Array.from(signatureBytes)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');

    return `0x${hexString}`;
  }
}

Bls12381BBSKeyPairDock2023.SecretKey = BBSSecretKey;
Bls12381BBSKeyPairDock2023.PublicKey = BBSPublicKey;
Bls12381BBSKeyPairDock2023.SignatureParams = BBSSignatureParams;
Bls12381BBSKeyPairDock2023.Signature = BBSSignature;
Bls12381BBSKeyPairDock2023.KeyPair = BBSKeypair;
Bls12381BBSKeyPairDock2023.defaultLabelBytes = BBS_SIGNATURE_PARAMS_LABEL_BYTES;
