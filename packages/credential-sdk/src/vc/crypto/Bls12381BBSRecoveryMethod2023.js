/**
 * Bls12381BBSRecoveryMethod2023 verification key class
 *
 * This class implements signature verification for BBS 2023 keys where:
 * - The public key is embedded in the proof (not stored on-chain)
 * - The Ethereum address is derived from the BBS public key via keccak256
 * - Verification compares derived address with the DID's address
 *
 * Similar to EcdsaSecp256k1RecoveryMethod2020, but instead of recovering
 * the public key from the signature, it receives the public key explicitly
 * in the proof object.
 *
 * Used by ethr DIDs with BBS signatures which store:
 * - type: "Bls12381BBSRecoveryMethod2023"
 * - publicKeyBase58: Base58-encoded BBS public key (accepts both formats):
 *   - 96 bytes: compressed G2 point (automatically decompressed internally)
 *   - 192 bytes: uncompressed G2 point (used directly)
 *
 * This maintains backward compatibility with existing credentials that may have
 * either compressed or uncompressed keys embedded in their proofs.
 */
import b58 from 'bs58';
import {
  BBSPublicKey,
  BBSSignature,
  BBSSignatureParams,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
} from '@docknetwork/crypto-wasm-ts';
import { bbsPublicKeyToAddress, parseDID } from '../../modules/ethr-did/utils';
import { compressG2PublicKey, getUncompressedG2PublicKey } from '../../modules/ethr-did/bbs-uncompressed';
import { u8aToU8a } from '../../utils/types/bytes';

export default class Bls12381BBSRecoveryMethod2023 {
  /**
   * Create a BBS recovery method instance
   * @param {string} publicKeyBase58 - Base58-encoded BBS public key (96 or 192 bytes)
   * @param {string} controller - The DID that controls this key
   * @param {string} expectedAddress - The expected Ethereum address from the DID
   * @throws {Error} If public key is not 96 or 192 bytes
   */
  constructor(publicKeyBase58, controller, expectedAddress) {
    this.publicKeyBase58 = publicKeyBase58;
    this.controller = controller;
    this.publicKeyBuffer = b58.decode(publicKeyBase58);

    // Accept both compressed (96 bytes) and uncompressed (192 bytes) G2 formats
    // This maintains backward compatibility with existing credentials that have
    // 96-byte compressed keys embedded in their proofs
    if (this.publicKeyBuffer.length === 96) {
      // Decompress to 192 bytes for internal use
      this.publicKeyBuffer = getUncompressedG2PublicKey(this.publicKeyBuffer);
    } else if (this.publicKeyBuffer.length !== 192) {
      throw new Error(
        `Invalid BBS public key length: expected 96 bytes (compressed G2) or 192 bytes (uncompressed G2), got ${this.publicKeyBuffer.length}`
      );
    }

    // Expected address from the DID (to compare against derived address)
    this.expectedAddress = expectedAddress;

    // Derive address from public key for validation
    this.derivedAddress = bbsPublicKeyToAddress(this.publicKeyBuffer);
  }

  /**
   * Construct the recovery method object from a verification method
   * @param {object} verificationMethod - Verification method object
   * @returns {Bls12381BBSRecoveryMethod2023}
   */
  static from(verificationMethod) {
    const { publicKeyBase58, controller } = verificationMethod;
    if (!publicKeyBase58) {
      throw new Error('publicKeyBase58 required for BBS recovery method');
    }

    // Derive expected address from public key
    let publicKeyBuffer = b58.decode(publicKeyBase58);

    // Ensure we have uncompressed format for address derivation
    if (publicKeyBuffer.length === 96) {
      publicKeyBuffer = getUncompressedG2PublicKey(publicKeyBuffer);
    } else if (publicKeyBuffer.length !== 192) {
      throw new Error(
        `Invalid BBS public key length: expected 96 bytes (compressed G2) or 192 bytes (uncompressed G2), got ${publicKeyBuffer.length}`
      );
    }

    const expectedAddress = bbsPublicKeyToAddress(publicKeyBuffer);

    return new this(publicKeyBase58, controller, expectedAddress);
  }

  /**
   * Construct the recovery method from a proof object and issuer DID
   * This is used during verification when the public key is embedded in the proof
   *
   * For dual-address DIDs (did:ethr:[network:]0xSecp:0xBBS), uses the BBS address
   * for strict validation. For single-address DIDs, uses the main address.
   *
   * @param {object} proof - Proof object containing publicKeyBase58 and verificationMethod
   * @param {string} issuerDID - The issuer's DID (to extract expected address)
   * @returns {Bls12381BBSRecoveryMethod2023}
   */
  static fromProof(proof, issuerDID) {
    if (!proof.publicKeyBase58) {
      throw new Error('proof.publicKeyBase58 required for BBS address verification');
    }

    // Extract expected BBS address from DID
    const parsed = parseDID(issuerDID);

    // For dual-address DIDs, use bbsAddress; for single-address, use address
    const expectedBBSAddress = parsed.isDualAddress
      ? parsed.bbsAddress
      : parsed.address;

    const instance = new this(proof.publicKeyBase58, issuerDID, expectedBBSAddress);

    // Set the ID from the proof's verificationMethod for purpose validation
    const verificationMethodId = typeof proof.verificationMethod === 'object'
      ? proof.verificationMethod.id
      : proof.verificationMethod;
    instance.id = verificationMethodId;

    return instance;
  }

  /**
   * Returns a verifier object for use with jsonld-signatures
   * @returns {{verify: Function}} Used to verify jsonld-signatures
   */
  verifier() {
    return Bls12381BBSRecoveryMethod2023.verifierFactory(
      this.publicKeyBuffer,
      this.expectedAddress,
    );
  }

  /**
   * Verifier factory that verifies BBS signature and validates address derivation
   * @param {Uint8Array} publicKeyBuffer - BBS public key (192 bytes, uncompressed G2 point)
   * @param {string} expectedAddress - Expected Ethereum address from DID
   * @returns {object} Verifier object with verify method
   */
  static verifierFactory(publicKeyBuffer, expectedAddress) {
    // Normalize expected address to lowercase for case-insensitive comparison
    const normalizedExpectedAddress = expectedAddress.toLowerCase();

    return {
      async verify({ data, signature: rawSignature }) {
        try {
          // 1. First verify the address derivation matches the DID
          const derivedAddress = bbsPublicKeyToAddress(publicKeyBuffer);
          if (derivedAddress.toLowerCase() !== normalizedExpectedAddress) {
            // Public key doesn't match the DID's address
            return false;
          }

          // 2. Verify the BBS signature
          const msgCount = data.length;
          const sigParams = BBSSignatureParams.getSigParamsOfRequiredSize(
            msgCount,
            BBS_SIGNATURE_PARAMS_LABEL_BYTES,
          );
          const signature = new BBSSignature(u8aToU8a(rawSignature));

          // Convert uncompressed (192 bytes) to compressed if needed
          const keyBytes = publicKeyBuffer.length === 192
            ? compressG2PublicKey(publicKeyBuffer)
            : publicKeyBuffer;

          const pk = new BBSPublicKey(u8aToU8a(keyBytes));

          const result = signature.verify(data, pk, sigParams, false);
          return result.verified;
        } catch (e) {
          // Verification failed
          console.error('BBS recovery verification error:', e);
          return false;
        }
      },
    };
  }
}
