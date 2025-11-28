/**
 * Bls12381BBSRecoveryMethod2023 verification key class
 *
 * This class implements signature verification for BBS+ keys where:
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
 * - publicKeyBase58: Base58-encoded 96-byte BBS public key
 */
import b58 from 'bs58';
import {
  BBSPublicKey,
  BBSSignature,
  BBSSignatureParams,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
} from '@docknetwork/crypto-wasm-ts';
import { bbsPublicKeyToAddress } from '../../modules/ethr-did/utils';
import { u8aToU8a } from '../../utils/types/bytes';

export default class Bls12381BBSRecoveryMethod2023 {
  /**
   * Create a BBS recovery method instance
   * @param {string} publicKeyBase58 - Base58-encoded BBS public key (96 bytes)
   * @param {string} controller - The DID that controls this key
   * @param {string} expectedAddress - The expected Ethereum address from the DID
   */
  constructor(publicKeyBase58, controller, expectedAddress) {
    this.publicKeyBase58 = publicKeyBase58;
    this.controller = controller;
    this.publicKeyBuffer = b58.decode(publicKeyBase58);

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
    const publicKeyBuffer = b58.decode(publicKeyBase58);
    const expectedAddress = bbsPublicKeyToAddress(publicKeyBuffer);

    return new this(publicKeyBase58, controller, expectedAddress);
  }

  /**
   * Construct the recovery method from a proof object and issuer DID
   * This is used during verification when the public key is embedded in the proof
   * @param {object} proof - Proof object containing publicKeyBase58 and verificationMethod
   * @param {string} issuerDID - The issuer's DID (to extract expected address)
   * @returns {Bls12381BBSRecoveryMethod2023}
   */
  static fromProof(proof, issuerDID) {
    if (!proof.publicKeyBase58) {
      throw new Error('proof.publicKeyBase58 required for BBS address verification');
    }

    // Extract address from DID: did:ethr:[network:]0xAddress
    const didParts = issuerDID.split(':');
    const expectedAddress = didParts[didParts.length - 1];

    const instance = new this(proof.publicKeyBase58, issuerDID, expectedAddress);

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
   * @param {Uint8Array} publicKeyBuffer - BBS public key (96 bytes)
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
          const pk = new BBSPublicKey(u8aToU8a(publicKeyBuffer));

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
