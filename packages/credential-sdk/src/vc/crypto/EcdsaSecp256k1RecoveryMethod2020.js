/**
 * EcdsaSecp256k1RecoveryMethod2020 verification key class
 *
 * This class implements signature verification for Ethereum-style keys where:
 * - Only the blockchain account ID (Ethereum address) is stored
 * - The public key is recovered from the signature during verification
 *
 * Used by ethr DIDs which store verification methods with:
 * - type: "EcdsaSecp256k1RecoveryMethod2020"
 * - blockchainAccountId: "eip155:chainId:0xAddress"
 */
export default class EcdsaSecp256k1RecoveryMethod2020 {
  constructor(blockchainAccountId) {
    this.blockchainAccountId = blockchainAccountId;
    // Extract Ethereum address from blockchainAccountId (format: eip155:chainId:address)
    this.ethereumAddress = blockchainAccountId.split(':').pop().toLowerCase();
  }

  /**
   * Construct the recovery method object from the verification method
   * @param verificationMethod
   * @returns {EcdsaSecp256k1RecoveryMethod2020}
   */
  static from(verificationMethod) {
    if (
      !verificationMethod.type
      || verificationMethod.type.indexOf('EcdsaSecp256k1RecoveryMethod2020') === -1
    ) {
      throw new Error(
        `verification method should have type EcdsaSecp256k1RecoveryMethod2020 - got: ${verificationMethod.type}`,
      );
    }

    // Handle both compact and expanded forms
    const blockchainAccountId = verificationMethod.blockchainAccountId
      || verificationMethod['sec:blockchainAccountId'];

    if (!blockchainAccountId) {
      throw new Error(
        'EcdsaSecp256k1RecoveryMethod2020 requires blockchainAccountId',
      );
    }

    return new this(blockchainAccountId);
  }

  /**
   * Construct the verifier factory that uses signature recovery
   * @returns {object}
   */
  verifier() {
    return EcdsaSecp256k1RecoveryMethod2020.verifierFactory(this.ethereumAddress);
  }

  /**
   * Verifier factory that recovers public key from signature and verifies against blockchain account
   * @param expectedAddress - Ethereum address (0x-prefixed hex string)
   * @returns {object}
   */
  static verifierFactory(expectedAddress) {
    // Normalize expected address to lowercase for case-insensitive comparison
    const normalizedExpectedAddress = expectedAddress.toLowerCase();

    return {
      async verify({ data, signature }) {
        // Import ethers for public key recovery
        const { recoverPublicKey } = await import('@ethersproject/signing-key');
        const { computeAddress } = await import('@ethersproject/transactions');
        const { hashMessage } = await import('@ethersproject/hash');

        try {
          // Recover public key from signature
          const messageHash = hashMessage(data);

          // Convert signature to hex string format that ethers expects
          const signatureHex = '0x' + Buffer.from(signature).toString('hex');

          const recoveredPubKey = recoverPublicKey(messageHash, signatureHex);

          // Derive address from recovered public key
          const recoveredAddress = computeAddress(recoveredPubKey).toLowerCase();

          // Verify the recovered address matches the expected address
          return recoveredAddress === normalizedExpectedAddress;
        } catch (error) {
          // Recovery failed or signature invalid
          return false;
        }
      },
    };
  }
}
