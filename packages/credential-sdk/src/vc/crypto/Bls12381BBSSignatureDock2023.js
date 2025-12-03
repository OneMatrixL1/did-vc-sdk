import {
  BBSCredential,
  BBSCredentialBuilder,
} from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';

import { Bls12381BBS23SigDockSigName } from './constants';

import Bls12381BBSKeyPairDock2023 from './Bls12381BBSKeyPairDock2023';
import DockCryptoSignature from './common/DockCryptoSignature';
import Bls12381BBSRecoveryMethod2023 from './Bls12381BBSRecoveryMethod2023';
import { isEthrDID, bbsPublicKeyToAddress, parseDID } from '../../modules/ethr-did/utils';
import { u8aToU8a } from '../../utils/types/bytes';
import CustomLinkedDataSignature from './common/CustomLinkedDataSignature';

/**
 * A BBS signature suite for use with BLS12-381 Dock key pairs
 */
export default class Bls12381BBSSignatureDock2023 extends DockCryptoSignature {
  /**
   * Default constructor
   * @param options {SignatureSuiteOptions} options for constructing the signature suite
   */
  constructor(options = {}) {
    super(
      {
        ...options,
        signer:
          options.signer
          || Bls12381BBSSignatureDock2023.signerFactory(
            options.keypair,
            options.verificationMethod,
          ),
      },
      Bls12381BBS23SigDockSigName,
      Bls12381BBSKeyPairDock2023,
      'https://ld.truvera.io/security/bbs23/v1',
    );
  }

  /**
   * Override signerFactory to include publicKeyBase58 for ethr DID address verification.
   * Also validates that BBS keypair matches the DID's BBS address for ethr DIDs.
   * @param keypair - BBS keypair
   * @param verificationMethod - Verification method ID
   * @returns {object} Signer object with id, publicKeyBase58, and sign method
   */
  static signerFactory(keypair, verificationMethod) {
    const { KeyPair } = this;
    const paramGetter = this.paramGenerator;

    // Extract DID from verification method if available
    const verificationMethodId = typeof verificationMethod === 'object'
      ? verificationMethod.id || verificationMethod
      : verificationMethod;
    const didPart = verificationMethodId?.split('#')[0];

    // Validate BBS keypair matches DID's BBS address (for ethr DIDs)
    if (didPart && isEthrDID(didPart) && keypair?.publicKeyBuffer) {
      const parsed = parseDID(didPart);
      const derivedBBSAddress = bbsPublicKeyToAddress(keypair.publicKeyBuffer);

      // Determine expected BBS address based on DID type
      const expectedBBSAddress = parsed.isDualAddress
        ? parsed.bbsAddress
        : parsed.address;

      if (derivedBBSAddress.toLowerCase() !== expectedBBSAddress.toLowerCase()) {
        throw new Error(
          `BBS keypair does not match DID's BBS address. `
          + `Derived: ${derivedBBSAddress}, Expected: ${expectedBBSAddress}`,
        );
      }
    }

    // Get base signer from parent
    const baseSigner = {
      id: verificationMethod,
      async sign({ data }) {
        if (!keypair || !keypair.privateKeyBuffer) {
          throw new Error('No private key to sign with.');
        }

        const msgCount = data.length;
        const sigParams = paramGetter(msgCount, KeyPair.defaultLabelBytes);
        const sk = KeyPair.adaptKey(
          new KeyPair.SecretKey(u8aToU8a(keypair.privateKeyBuffer)),
          data.length,
        );
        const signature = KeyPair.Signature.generate(data, sk, sigParams);
        return signature.value;
      },
    };

    // Add publicKeyBase58 if keypair is available (for ethr DID address verification)
    if (keypair && keypair.publicKeyBuffer) {
      baseSigner.publicKeyBase58 = b58.encode(new Uint8Array(keypair.publicKeyBuffer));
    }

    return baseSigner;
  }

  /**
   * Override sign to include publicKeyBase58 in proof for ethr DID address verification.
   * This enables self-contained credential verification without on-chain BBS key storage.
   * @param {object} options - Options containing verifyData and proof
   * @returns {Promise<object>} Proof object with signature and publicKeyBase58
   */
  async sign({ verifyData, proof }) {
    const finalProof = await super.sign({ verifyData, proof });

    // Add publicKeyBase58 for ethr DID address-based verification
    if (this.signer?.publicKeyBase58) {
      finalProof.publicKeyBase58 = this.signer.publicKeyBase58;
    }

    return finalProof;
  }

  /**
   * Override getVerificationMethod to use embedded public key for ethr DIDs.
   *
   * For ethr DIDs with embedded publicKeyBase58 in proof:
   * - If key derives to DID's address: use recovery method (no on-chain lookup needed)
   * - Otherwise: fall back to standard DID document resolution (for delegate keys)
   *
   * @param {object} options - Options containing proof and documentLoader
   * @returns {Promise<object>} Verification method object
   */
  async getVerificationMethod({ proof, documentLoader }) {
    const verificationMethodId = typeof proof.verificationMethod === 'object'
      ? proof.verificationMethod.id
      : proof.verificationMethod;

    if (verificationMethodId && proof.publicKeyBase58) {
      const didPart = verificationMethodId.split('#')[0];

      if (isEthrDID(didPart)) {
        const publicKeyBuffer = b58.decode(proof.publicKeyBase58);
        const derivedAddress = bbsPublicKeyToAddress(publicKeyBuffer);
        const didParts = parseDID(didPart);

        if (derivedAddress.toLowerCase() === didParts.address.toLowerCase()) {
          // Address-based: BBS key derives to DID's address - use recovery method
          return Bls12381BBSRecoveryMethod2023.fromProof(proof, didPart);
        }
      }
    }

    // Fall back to standard DID document resolution
    return super.getVerificationMethod({ proof, documentLoader });
  }

  /**
   * Override verifySignature to handle BBS recovery method
   * @param {object} options - Options containing verifyData, verificationMethod, and proof
   * @returns {Promise<boolean>} Verification result
   */
  async verifySignature({ verifyData, verificationMethod, proof }) {
    if (verificationMethod instanceof Bls12381BBSRecoveryMethod2023) {
      const signatureBytes = this.constructor.extractSignatureBytes(proof);
      const verifier = verificationMethod.verifier();
      return verifier.verify({ data: verifyData, signature: signatureBytes });
    }

    return super.verifySignature({ verifyData, verificationMethod, proof });
  }

  /**
   * Override getTrimmedProofAndValue to strip publicKeyBase58 from proof
   * This is necessary because publicKeyBase58 is added after signing for ethr DID
   * address verification, and BBS signatures verify against specific message fields.
   * Including publicKeyBase58 in the trimmed proof would break verification.
   * @param {object} document - The document being verified
   * @param {object} explicitProof - Optional explicit proof object
   * @returns {Array} [trimmedProof, proofValue]
   */
  static getTrimmedProofAndValue(document, explicitProof) {
    const [trimmedProof, proofVal] = super.getTrimmedProofAndValue(document, explicitProof);

    // Remove publicKeyBase58 from trimmed proof as it was added after signing
    // for ethr DID address verification and is not part of the signed message
    delete trimmedProof.publicKeyBase58;

    return [trimmedProof, proofVal];
  }

  /**
   * Extract signature bytes from proof
   * @param {object} proof - Proof object containing proofValue
   * @returns {Uint8Array} Signature bytes
   */
  static extractSignatureBytes(proof) {
    const { proofValue } = proof;
    if (proofValue && typeof proofValue === 'string') {
      return b58.decode(
        CustomLinkedDataSignature.fromJsigProofValue(proofValue),
      );
    }
    throw new Error('No proofValue found in proof');
  }
}

Bls12381BBSSignatureDock2023.KeyPair = Bls12381BBSKeyPairDock2023;
Bls12381BBSSignatureDock2023.CredentialBuilder = BBSCredentialBuilder;
Bls12381BBSSignatureDock2023.Credential = BBSCredential;
Bls12381BBSSignatureDock2023.proofType = [
  Bls12381BBS23SigDockSigName,
  `sec:${Bls12381BBS23SigDockSigName}`,
  `https://w3id.org/security#${Bls12381BBS23SigDockSigName}`,
];
