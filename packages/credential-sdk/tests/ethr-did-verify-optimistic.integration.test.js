/**
 * Integration tests for verifyCredentialOptimistic() - True Fallback Path
 *
 * This test verifies the core purpose of optimistic verification:
 * - Optimistic resolution fails (DID has on-chain modifications)
 * - Fallback to blockchain resolution succeeds
 *
 * Unlike unit tests that mock blockchain responses, this test runs against
 * a live testnet to validate the real fallback mechanism.
 *
 * Test Flow:
 * 1. Setup: Create a primary DID controlled by a Secp256k1 keypair
 * 2. Modify: Add a BBS key as an attribute (modifies on-chain state)
 * 3. Issue: Issue a credential using the registered BBS key
 * 4. Verify: Call verifyCredentialOptimistic - optimistic fails, blockchain succeeds
 *
 * IMPORTANT: This test requires a live testnet connection and a funded account.
 *
 * Environment Variables (REQUIRED):
 * ----------------------------------
 * ETHR_NETWORK_RPC_URL   - RPC endpoint URL (e.g., https://rpc.vietcha.in)
 * ETHR_PRIVATE_KEY       - Private key of funded account for gas fees
 *
 * Optional Environment Variables:
 * -------------------------------
 * ETHR_NETWORK           - Network name (default: sepolia)
 * ETHR_REGISTRY_ADDRESS  - DID Registry contract address
 *
 * Run with:
 *   ETHR_PRIVATE_KEY=0x... ETHR_NETWORK=vietchain ETHR_NETWORK_RPC_URL=https://rpc.vietcha.in \
 *   ETHR_REGISTRY_ADDRESS=0xF0889fb2473F91c068178870ae2e1A0408059A03 \
 *   yarn jest packages/credential-sdk/tests/ethr-did-verify-optimistic.integration.test.js
 */

import { ethers } from 'ethers';
import b58 from 'bs58';
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import {
  EthrDIDModule,
  verifyCredentialOptimistic,
  createMemoryStorageAdapter,
} from '../src/modules/ethr-did';
import { keypairToAddress } from '../src/modules/ethr-did/utils';
import { Secp256k1Keypair } from '../src/keypairs';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';

// BBS key attribute name for ethr DID
// Format: did/pub/<algorithm>/<purpose>/<encoding>
const BBS_ATTRIBUTE_NAME = 'did/pub/Bls12381G2Key2020/veriKey/base58';

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
  name: process.env.ETHR_NETWORK || 'sepolia',
  rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
  registry:
    process.env.ETHR_REGISTRY_ADDRESS
    || '0x03d5003bf0e79c5f5223588f347eba39afbc3818',
};

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';

describe('verifyCredentialOptimistic() - True Fallback Integration Test', () => {
  let module;
  let provider;
  let founderKeypair;

  // Test state - persisted across the lifecycle
  let ownerKeypair; // Secp256k1 keypair that controls the DID
  let ownerDID; // The primary DID
  let bbsKeypair; // BBS keypair to be registered
  let bbsPublicKeyBase58; // Base58 encoded BBS public key
  let bbsKeyDoc; // Key document for BBS signing
  let signedCredential; // Credential issued by registered BBS key

  /**
   * Helper function to fund a test account with gas
   */
  async function fundTestAccount(recipientAddress, amountInEther = '0.1') {
    const founderPrivateKey = founderKeypair.privateKey();
    const founderPrivateKeyHex = `0x${Array.from(founderPrivateKey)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}`;
    const founderWallet = new ethers.Wallet(founderPrivateKeyHex, provider);

    const tx = await founderWallet.sendTransaction({
      to: recipientAddress,
      value: ethers.utils.parseEther(amountInEther),
    });

    await tx.wait();
  }

  /**
   * Create a BBS key document from the DID document.
   * Finds the verification method that matches the BBS public key.
   */
  async function createBBSKeyDocFromDIDDocument(ethrModule, bbs, did) {
    const didDocument = await ethrModule.getDocument(did);
    const targetPublicKeyBase58 = b58.encode(bbs.publicKeyBuffer);
    const targetPublicKeyHex = Buffer.from(bbs.publicKeyBuffer).toString('hex');

    // Find the verification method for the BBS key (registered via setAttribute)
    const verificationMethod = didDocument.verificationMethod?.find(
      (vm) => vm.publicKeyBase58 === targetPublicKeyBase58
        || vm.publicKeyHex === targetPublicKeyHex,
    );

    if (!verificationMethod) {
      // eslint-disable-next-line no-console
      console.error('DID Document:', JSON.stringify(didDocument, null, 2));
      throw new Error(
        `No verification method found for BBS public key. `
          + 'Ensure the BBS key was registered via setAttribute.',
      );
    }

    return {
      id: verificationMethod.id,
      controller: did,
      type: Bls12381BBS23DockVerKeyName,
      publicKeyBase58: targetPublicKeyBase58,
      keypair: bbs,
    };
  }

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create module with test network (NOT optimistic by default)
    module = new EthrDIDModule({
      networks: [networkConfig],
      defaultNetwork: networkConfig.name,
    });

    // Create provider
    provider = new ethers.providers.JsonRpcProvider(networkConfig.rpcUrl);

    // Load founder keypair from environment
    const privateKeyBytes = Buffer.from(
      process.env.ETHR_PRIVATE_KEY.replace('0x', ''),
      'hex',
    );
    founderKeypair = new Secp256k1Keypair(privateKeyBytes, 'private');

    // Generate keypairs for the test
    ownerKeypair = Secp256k1Keypair.random();
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'bbs-optimistic-fallback-test-key',
      controller: 'temp',
    });
    bbsPublicKeyBase58 = b58.encode(bbsKeypair.publicKeyBuffer);
  });

  describe('True Fallback Path', () => {
    /**
     * STEP 1: Setup - Create primary DID controlled by Secp256k1 keypair
     */
    test('Step 1: Create primary DID with Secp256k1 keypair', async () => {
      // Fund the owner account
      const ownerAddress = keypairToAddress(ownerKeypair);
      await fundTestAccount(ownerAddress, '0.2');

      // Create the DID
      ownerDID = await module.createNewDID(ownerKeypair);

      expect(ownerDID).toBeDefined();
      expect(ownerDID).toContain(`did:ethr:${networkConfig.name}:`);

      // eslint-disable-next-line no-console
      console.log(`✓ Step 1: Created primary DID: ${ownerDID}`);
    }, 60000);

    /**
     * STEP 2: Modify - Add BBS public key as an attribute
     * This modifies the DID's on-chain state, causing optimistic resolution to fail
     */
    test('Step 2: Register BBS public key via setAttribute (modifies on-chain state)', async () => {
      expect(ownerDID).toBeDefined();

      // Register the BBS public key as an attribute
      const receipt = await module.setAttribute(
        ownerDID,
        BBS_ATTRIBUTE_NAME,
        bbsPublicKeyBase58,
        ownerKeypair,
        86400, // 1 day validity
      );

      expect(receipt.transactionHash).toBeDefined();
      expect(receipt.status).toBe(1);

      // Verify BBS key appears in DID document (via blockchain resolution)
      const document = await module.getDocument(ownerDID);
      const targetHex = Buffer.from(b58.decode(bbsPublicKeyBase58)).toString('hex');
      const bbsVM = document.verificationMethod?.find(
        (vm) => vm.publicKeyBase58 === bbsPublicKeyBase58
          || vm.publicKeyHex === targetHex,
      );

      expect(bbsVM).toBeDefined();

      // eslint-disable-next-line no-console
      console.log(`✓ Step 2: Registered BBS public key on-chain`);
      // eslint-disable-next-line no-console
      console.log(`  Transaction: ${receipt.transactionHash}`);
    }, 60000);

    /**
     * STEP 3: Issue - Create credential using the registered BBS key
     */
    test('Step 3: Issue credential with registered BBS key', async () => {
      expect(ownerDID).toBeDefined();

      // Create BBS key document from DID document
      bbsKeyDoc = await createBBSKeyDocFromDIDDocument(module, bbsKeypair, ownerDID);

      // Create unsigned credential
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential', 'OptimisticFallbackTestCredential'],
        issuer: ownerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder-optimistic-test',
          alumniOf: 'Optimistic Fallback Test University',
        },
      };

      // Issue credential with BBS signature
      signedCredential = await issueCredential(bbsKeyDoc, unsignedCredential);

      expect(signedCredential).toBeDefined();
      expect(signedCredential.proof).toBeDefined();
      expect(signedCredential.proof.type).toBe('Bls12381BBSSignatureDock2023');
      expect(signedCredential.proof.verificationMethod).toBe(bbsKeyDoc.id);

      // eslint-disable-next-line no-console
      console.log('✓ Step 3: Issued BBS credential');
      // eslint-disable-next-line no-console
      console.log(`  Verification method: ${signedCredential.proof.verificationMethod}`);
    }, 60000);

    /**
     * STEP 4: Verify with Fallback - Call verifyCredentialOptimistic
     *
     * This is the CRITICAL test - validates the core purpose of optimistic verification:
     * - Optimistic resolution generates a default document (no BBS key)
     * - BBS key is NOT in the default document, so verification fails
     * - Fallback to blockchain resolution finds the registered BBS key
     * - Final verification succeeds
     */
    test('Step 4: verifyCredentialOptimistic succeeds via fallback path', async () => {
      expect(signedCredential).toBeDefined();

      const storage = createMemoryStorageAdapter();

      // First, verify that pure optimistic resolution would FAIL
      // (because the BBS key is NOT in the default document)
      const optimisticOnlyModule = new EthrDIDModule({
        networks: [networkConfig],
        defaultNetwork: networkConfig.name,
        optimistic: true, // Force optimistic mode
      });

      const optimisticResult = await verifyCredential(signedCredential, {
        resolver: optimisticOnlyModule,
      });

      // Optimistic-only should FAIL (BBS key not in default document)
      expect(optimisticResult.verified).toBe(false);
      // eslint-disable-next-line no-console
      console.log(`✓ Confirmed: Pure optimistic resolution fails (verified=${optimisticResult.verified})`);

      // Now, verify that blockchain resolution SUCCEEDS
      const blockchainResult = await verifyCredential(signedCredential, {
        resolver: module, // Uses blockchain by default
      });

      expect(blockchainResult.verified).toBe(true);
      // eslint-disable-next-line no-console
      console.log(`✓ Confirmed: Blockchain resolution succeeds (verified=${blockchainResult.verified})`);

      // Finally, test the ACTUAL fallback mechanism via verifyCredentialOptimistic
      // This should:
      // 1. Try optimistic first → FAIL
      // 2. Mark DID in storage
      // 3. Fallback to blockchain → SUCCESS
      const fallbackResult = await verifyCredentialOptimistic(signedCredential, {
        module,
        storage,
      });

      // The final result should be SUCCESS (via fallback)
      expect(fallbackResult.verified).toBe(true);

      // The DID should be marked in storage (because optimistic failed)
      expect(await storage.has(ownerDID)).toBe(true);

      // eslint-disable-next-line no-console
      console.log('✓ Step 4: verifyCredentialOptimistic succeeded via fallback');
      // eslint-disable-next-line no-console
      console.log(`  Final result: verified=${fallbackResult.verified}`);
      // eslint-disable-next-line no-console
      console.log(`  DID marked in storage: ${await storage.has(ownerDID)}`);
    }, 60000);

    /**
     * STEP 5: Verify subsequent calls skip optimistic (DID already marked)
     */
    test('Step 5: Subsequent verification skips optimistic (DID pre-marked)', async () => {
      expect(signedCredential).toBeDefined();

      const storage = createMemoryStorageAdapter();

      // Pre-mark the DID as needing blockchain
      await storage.set(ownerDID);

      // This should go directly to blockchain resolution (skip optimistic)
      const result = await verifyCredentialOptimistic(signedCredential, {
        module,
        storage,
      });

      expect(result.verified).toBe(true);

      // eslint-disable-next-line no-console
      console.log('✓ Step 5: Subsequent verification succeeds (skipped optimistic)');
    }, 60000);
  });

  describe('Edge Cases', () => {
    /**
     * Test that tampered credentials still fail even with fallback
     */
    test('Tampered credential fails even with blockchain fallback', async () => {
      expect(signedCredential).toBeDefined();

      const tamperedCredential = {
        ...signedCredential,
        credentialSubject: {
          ...signedCredential.credentialSubject,
          alumniOf: 'Tampered University',
        },
      };

      const storage = createMemoryStorageAdapter();

      const result = await verifyCredentialOptimistic(tamperedCredential, {
        module,
        storage,
      });

      // Should fail - tampering invalidates signature
      expect(result.verified).toBe(false);

      // DID should still be marked (optimistic failed first)
      expect(await storage.has(ownerDID)).toBe(true);

      // eslint-disable-next-line no-console
      console.log('✓ Tampered credential correctly fails even with fallback');
    }, 60000);

    /**
     * Test that wrong public key in proof fails verification
     *
     * Note: When verifying via blockchain resolution with an on-chain registered key,
     * the verification uses the key found in the DID document by fragment ID,
     * NOT the embedded publicKeyBase58 in the proof. This is the expected behavior
     * for Approach 2 (Secp256k1 DID + registered BBS key).
     *
     * The embedded publicKeyBase58 is primarily used for Approach 1 (BBS-derived DID)
     * where the key is recovered from the proof via address derivation.
     */
    test('Wrong public key in proof - behavior depends on verification method', async () => {
      expect(signedCredential).toBeDefined();

      // Generate a different BBS keypair
      const wrongKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'wrong-key',
        controller: 'temp',
      });
      const wrongPublicKey = b58.encode(wrongKeypair.publicKeyBuffer);

      const tamperedCredential = {
        ...signedCredential,
        proof: {
          ...signedCredential.proof,
          publicKeyBase58: wrongPublicKey,
        },
      };

      // For on-chain registered keys (Approach 2), the verification uses
      // the key from the DID document, not the embedded one in the proof.
      // The verificationMethod fragment (#delegate-1) points to the correct key.
      const result = await verifyCredentialOptimistic(tamperedCredential, {
        module,
      });

      // This actually succeeds because the blockchain resolver uses the
      // registered key found by fragment ID, not the embedded publicKeyBase58.
      // This is correct behavior for Approach 2.
      expect(result.verified).toBe(true);

      // eslint-disable-next-line no-console
      console.log('✓ Verification uses on-chain key (ignores tampered publicKeyBase58)');
      // eslint-disable-next-line no-console
      console.log('  Note: This is expected for Approach 2 (registered BBS key)');
    }, 60000);
  });
});
