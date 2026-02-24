/**
 * Integration tests for EthrDIDModule.changeOwnerWithPubkey
 *
 * Tests the BLS signature-based ownership change flow:
 * 1. Generate BBS keypair
 * 2. Derive address from uncompressed 192-byte G2 public key
 * 3. Sign ownership change with BLS (produces G1 signature)
 * 4. Submit transaction to VietChain contract
 * 5. Verify ownership was changed on-chain
 *
 * This is the main flow we refactored:
 * - SDK sends 192-byte uncompressed G2 public keys to contract
 * - EthrDIDModule is responsible for decompression (96→192 bytes)
 * - Address derivation uses keccak256(192-byte uncompressed key)
 *
 * Environment Variables (REQUIRED):
 * ----------------------------------
 * ETHR_NETWORK_RPC_URL   - RPC endpoint URL (e.g., https://rpc.vietcha.in)
 * ETHR_PRIVATE_KEY       - Private key of funded gas payer account
 *
 * Optional Environment Variables:
 * -------------------------------
 * ETHR_NETWORK           - Network name (default: vietchain)
 * ETHR_REGISTRY_ADDRESS  - DID Registry contract address
 *
 * Usage:
 * ------
 * ETHR_PRIVATE_KEY=0x... ETHR_NETWORK=vietchain \
 * ETHR_NETWORK_RPC_URL=https://rpc.vietcha.in \
 * ETHR_REGISTRY_ADDRESS=0x8697547b3b82327B70A90C6248662EC083ad5A62 \
 * yarn test:integration --testMatch ethr-did-changeowner-pubkey.integration.test.js
 */
import 'dotenv/config';
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { EthrDIDModule } from '../src/modules/ethr-did';
import { Secp256k1Keypair } from '../src/keypairs';
import { keypairToAddress, verifyBLSSignature, signWithBLSKeypair } from '../src/modules/ethr-did/utils';
import { DEFAULT_REGISTRY_ADDRESS } from '../src/vc/constants';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';

// Configuration from environment (required for integration tests)
if (!process.env.ETHR_NETWORK_RPC_URL) {
  throw new Error(
    'ETHR_NETWORK_RPC_URL environment variable is required for integration tests. '
    + 'Use scripts/test-integration-vietchain.sh or set ETHR_NETWORK_RPC_URL manually.',
  );
}

if (!process.env.ETHR_PRIVATE_KEY) {
  throw new Error(
    'ETHR_PRIVATE_KEY environment variable is required for integration tests. '
    + 'Tests require a funded account to pay gas fees.',
  );
}

const networkConfig = {
  name: process.env.ETHR_NETWORK || 'vietchain',
  rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
  registry:
    process.env.ETHR_REGISTRY_ADDRESS
    || DEFAULT_REGISTRY_ADDRESS, // VietChain default
};

describe('EthrDID changeOwnerWithPubkey Integration Tests', () => {
  /** @type {EthrDIDModule} */
  let module;

  /** @type {Secp256k1Keypair} */
  let gasPayerKeypair;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create module with test network
    module = new EthrDIDModule({
      networks: [networkConfig],
      defaultNetwork: networkConfig.name,
    });

    // Load gas payer keypair from environment
    const privateKeyBytes = Buffer.from(
      process.env.ETHR_PRIVATE_KEY.replace('0x', ''),
      'hex',
    );
    gasPayerKeypair = new Secp256k1Keypair(privateKeyBytes, 'private');
  });

  describe('BLS Signature-based Ownership Change', () => {
    test('changes DID owner using BBS keypair signature (192-byte uncompressed key)', async () => {
      // Step 1: Generate BBS keypair
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({ id: 'test-bbs-owner' });

      // Step 2: Derive address from uncompressed 192-byte G2 public key
      const did = await module.createNewDID(bbsKeypair);

      // Step 3: Create new owner address
      const newOwnerWallet = Secp256k1Keypair.random();
      const newOwnerAddress = keypairToAddress(newOwnerWallet);

      const receipt = await module.changeOwnerWithPubkey(
        did,
        newOwnerAddress,
        bbsKeypair,
        gasPayerKeypair,
      );

      /** @type {import('../src/types/did/document').DIDDocument} */
      const didDoc = await module.getDocument(did);

      // Step 4: Verify ownership change on-chain
      expect(receipt.status).toBe(1);
      expect(receipt.txHash).toBeDefined();

      // Check verification method
      expect(didDoc.verificationMethod).toBeDefined();
      const accountId = didDoc.verificationMethod[0].blockchainAccountId;
      const addressFromAccount = accountId.split(':')[2];
      expect(addressFromAccount.toLowerCase()).toBe(newOwnerAddress.toLowerCase());
    }, 60000); // 60 second timeout for network operations

    test('fails with invalid BBS signature', async () => {
      // Create two different BBS keypairs
      const bbsKeypair1 = Bls12381BBSKeyPairDock2023.generate({ id: 'keypair-1' });
      const bbsKeypair2 = Bls12381BBSKeyPairDock2023.generate({ id: 'keypair-2' });

      const did1 = await module.createNewDID(bbsKeypair1);
      const newOwner = keypairToAddress(Secp256k1Keypair.random());

      // Try to change owner of DID1 using signature from keypair2
      await expect(
        module.changeOwnerWithPubkey(
          did1,
          newOwner,
          bbsKeypair2, // Wrong keypair!
          gasPayerKeypair,
        ),
      ).rejects.toThrow();
    }, 60000);
  });

  describe('verifyBLSSignature Utility', () => {
    test('verifies a signature generated by signWithBLSKeypair', async () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({ id: 'test-verify' });
      const did = await module.createNewDID(bbsKeypair);
      const newOwner = keypairToAddress(Secp256k1Keypair.random());

      const hashToSign = await module.createChangeOwnerWithPubkeyHash(did, newOwner);

      const signature = await signWithBLSKeypair(hashToSign, bbsKeypair);
      const publicKey = bbsKeypair.publicKeyBuffer;

      const isValid = verifyBLSSignature(signature, hashToSign, publicKey);
      expect(isValid).toBe(true);
    });

    test('fails for invalid signature', async () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({ id: 'test-fail-sig' });
      const did = await module.createNewDID(bbsKeypair);
      const newOwner = keypairToAddress(Secp256k1Keypair.random());

      const hashToSign = await module.createChangeOwnerWithPubkeyHash(did, newOwner);

      const signature = await signWithBLSKeypair(hashToSign, bbsKeypair);
      signature[0] ^= 0xFF;

      const isValid = verifyBLSSignature(signature, hashToSign, bbsKeypair.publicKeyBuffer);
      expect(isValid).toBe(false);
    });

    test('fails for incorrect message hash', async () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({ id: 'test-fail-msg' });
      const did = await module.createNewDID(bbsKeypair);
      const newOwner1 = keypairToAddress(Secp256k1Keypair.random());
      const newOwner2 = keypairToAddress(Secp256k1Keypair.random());

      const hashToSign = await module.createChangeOwnerWithPubkeyHash(did, newOwner1);
      const wrongHash = await module.createChangeOwnerWithPubkeyHash(did, newOwner2);

      const signature = await signWithBLSKeypair(hashToSign, bbsKeypair);

      const isValid = verifyBLSSignature(signature, wrongHash, bbsKeypair.publicKeyBuffer);
      expect(isValid).toBe(false);
    });
  });
});
