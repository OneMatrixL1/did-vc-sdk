import { EcdsaSecp256k1Signature2020Name, EcdsaSecp256k1RecoveryMethod2020Name } from './constants';
import EcdsaSecp256k1RecoveryMethod2020 from './EcdsaSecp256k1RecoveryMethod2020';
import CustomLinkedDataSignature from './common/CustomLinkedDataSignature';

const SUITE_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1';

/**
 * EcdsaSecp256k1Signature2020 - Signature suite for Ethereum-style recovery verification
 *
 * This suite works with EcdsaSecp256k1RecoveryMethod2020 verification methods that:
 * - Store only the blockchain account ID (Ethereum address)
 * - Recover the public key from the signature during verification
 *
 * Used primarily by ethr DIDs which use the EIP-155 blockchain account format.
 */
export default class EcdsaSecp256k1Signature2020 extends CustomLinkedDataSignature {
  /**
   * Creates a new EcdsaSecp256k1Signature2020 instance
   * @constructor
   * @param {object} config - Configuration options
   */
  constructor({
    keypair,
    verificationMethod,
    verifier,
    signer,
    useProofValue,
  } = {}) {
    super({
      type: EcdsaSecp256k1Signature2020Name,
      LDKeyClass: EcdsaSecp256k1RecoveryMethod2020,
      contextUrl: SUITE_CONTEXT_URL,
      alg: 'ES256K',
      signer:
        signer
        || EcdsaSecp256k1Signature2020.signerFactory(keypair, verificationMethod),
      verifier,
      useProofValue,
    });
    this.requiredKeyType = EcdsaSecp256k1RecoveryMethod2020Name;
  }

  /**
   * Generate object with `sign` method
   * Creates Ethereum-style signatures with recovery ID for use with EcdsaSecp256k1RecoveryMethod2020
   * @param keypair
   * @param verificationMethod
   * @returns {object}
   */
  static signerFactory(keypair, verificationMethod) {
    return {
      id: verificationMethod,
      async sign({ data }) {
        // Import ethers for Ethereum-style signing with recovery ID
        const { SigningKey } = await import('@ethersproject/signing-key');
        const { hashMessage } = await import('@ethersproject/hash');

        // Get private key from keypair (handle both function and property)
        const privateKeyBytes = typeof keypair.privateKey === 'function'
          ? keypair.privateKey()
          : keypair.privateKey;
        const privateKeyHex = '0x' + Buffer.from(privateKeyBytes).toString('hex');
        const signingKey = new SigningKey(privateKeyHex);

        // Hash the data and sign
        const messageHash = hashMessage(data);
        const signature = signingKey.signDigest(messageHash);

        // The signature object has r, s, v properties
        // We need to serialize it properly for recovery
        // ethers serialized format: r (32 bytes) + s (32 bytes) + v (1 byte)
        const r = signature.r.substring(2); // Remove 0x prefix
        const s = signature.s.substring(2); // Remove 0x prefix
        const v = signature.v.toString(16).padStart(2, '0'); // Convert to hex

        const serialized = r + s + v;
        return Buffer.from(serialized, 'hex');
      },
    };
  }
}
