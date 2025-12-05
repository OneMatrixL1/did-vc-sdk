/**
 * BBS Delegation Lifecycle Integration Test
 *
 * This test verifies the complete lifecycle of BBS key registration on ethr DIDs:
 * 1. Setup: Create a primary DID controlled by a Secp256k1 keypair
 * 2. Register: Add a BBS public key as an attribute (did/pub/Bls12381G2Key2020/veriKey/base58)
 * 3. Issue & Verify: Issue a VC using the registered BBS key
 * 4. Revoke: Revoke the BBS key attribute
 * 5. Verify Failure: Verify that credentials from the revoked key no longer verify
 *
 * NOTE: ethr DID uses setAttribute (not addDelegate) for BBS keys because:
 * - addDelegate only stores an address, which resolves as EcdsaSecp256k1RecoveryMethod2020
 * - setAttribute with did/pub/Bls12381G2Key2020/... stores the actual BBS public key
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
 *   yarn jest packages/credential-sdk/tests/ethr-did-bbs-delegation.integration.test.js
 */

import { ethers } from 'ethers';
import b58 from 'bs58';
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { EthrDIDModule } from '../src/modules/ethr-did';
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

describe('BBS Delegation Lifecycle Integration Test', () => {
  let module;
  let provider;
  let founderKeypair;

  // Test state - persisted across the lifecycle
  let ownerKeypair; // Secp256k1 keypair that controls the DID
  let ownerDID; // The primary DID
  let bbsKeypair; // BBS keypair to be registered
  let bbsPublicKeyBase58; // Base58 encoded BBS public key
  let bbsKeyDoc; // Key document for BBS signing
  let credentialIssuedByBBS; // Credential issued by registered BBS key

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
    // The resolver may store the key as publicKeyHex or publicKeyBase58
    const verificationMethod = didDocument.verificationMethod?.find(
      (vm) => vm.publicKeyBase58 === targetPublicKeyBase58
        || vm.publicKeyHex === targetPublicKeyHex,
    );

    if (!verificationMethod) {
      // eslint-disable-next-line no-console
      console.error('DID Document:', JSON.stringify(didDocument, null, 2));
      // eslint-disable-next-line no-console
      console.error('Looking for BBS key (hex):', targetPublicKeyHex);
      // eslint-disable-next-line no-console
      console.error('Looking for BBS key (base58):', targetPublicKeyBase58);
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

    // Create module with test network
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
      id: 'bbs-registered-key',
      controller: 'temp',
    });
    bbsPublicKeyBase58 = b58.encode(bbsKeypair.publicKeyBuffer);
  });

  describe('Lifecycle Steps', () => {
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
      expect(ownerDID.toLowerCase()).toContain(ownerAddress.toLowerCase());

      // Verify DID document exists
      const document = await module.getDocument(ownerDID);
      expect(document).toBeDefined();
      expect(document.id).toBe(ownerDID);
      expect(document.verificationMethod).toBeDefined();
      expect(document.verificationMethod.length).toBeGreaterThanOrEqual(1);

      // eslint-disable-next-line no-console
      console.log(`✓ Created primary DID: ${ownerDID}`);
    }, 60000);

    /**
     * STEP 2: Register - Add BBS public key as an attribute
     *
     * Uses setAttribute with did/pub/Bls12381G2Key2020/veriKey/base58 format.
     * This registers the BBS public key on-chain so it appears in the DID document
     * as a proper BLS verification method.
     */
    test('Step 2: Register BBS public key via setAttribute', async () => {
      expect(ownerDID).toBeDefined(); // Ensure Step 1 completed

      // Register the BBS public key as an attribute
      const receipt = await module.setAttribute(
        ownerDID,
        BBS_ATTRIBUTE_NAME,
        bbsPublicKeyBase58,
        ownerKeypair,
        86400, // 1 day validity
      );

      expect(receipt.transactionHash).toBeDefined();
      expect(receipt.status).toBe(1); // Transaction success

      // Verify BBS key appears in DID document
      const document = await module.getDocument(ownerDID);

      // Find the BBS verification method by public key (check both hex and base58)
      const targetHex = Buffer.from(b58.decode(bbsPublicKeyBase58)).toString('hex');
      const bbsVM = document.verificationMethod?.find(
        (vm) => vm.publicKeyBase58 === bbsPublicKeyBase58
          || vm.publicKeyHex === targetHex,
      );

      expect(bbsVM).toBeDefined();
      expect(bbsVM.type).toBe('Bls12381G2Key2020');

      // eslint-disable-next-line no-console
      console.log(`✓ Registered BBS public key on-chain`);
      // eslint-disable-next-line no-console
      console.log(`  Verification method ID: ${bbsVM.id}`);
      // eslint-disable-next-line no-console
      console.log(`  Type: ${bbsVM.type}`);
    }, 60000);

    /**
     * STEP 3: Issue & Verify - Issue VC using registered BBS key and verify it
     */
    test('Step 3: Issue and verify credential with registered BBS key', async () => {
      expect(ownerDID).toBeDefined(); // Ensure Step 1 completed

      // Create BBS key document from DID document
      bbsKeyDoc = await createBBSKeyDocFromDIDDocument(module, bbsKeypair, ownerDID);

      expect(bbsKeyDoc).toBeDefined();
      expect(bbsKeyDoc.id).toContain(ownerDID);
      expect(bbsKeyDoc.type).toBe(Bls12381BBS23DockVerKeyName);

      // Create unsigned credential
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: ownerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:student123',
          alumniOf: 'BBS Registration Test University',
        },
      };

      // Issue credential with BBS signature
      credentialIssuedByBBS = await issueCredential(bbsKeyDoc, unsignedCredential);

      expect(credentialIssuedByBBS).toBeDefined();
      expect(credentialIssuedByBBS.issuer).toBe(ownerDID);
      expect(credentialIssuedByBBS.proof).toBeDefined();
      expect(credentialIssuedByBBS.proof.type).toBe('Bls12381BBSSignatureDock2023');
      expect(credentialIssuedByBBS.proof.verificationMethod).toBe(bbsKeyDoc.id);

      // Verify the credential
      const verifyResult = await verifyCredential(credentialIssuedByBBS, {
        resolver: module,
      });

      expect(verifyResult.verified).toBe(true);
      expect(verifyResult.results).toBeDefined();
      expect(verifyResult.results[0].verified).toBe(true);

      // eslint-disable-next-line no-console
      console.log('✓ Issued and verified BBS credential');
      // eslint-disable-next-line no-console
      console.log(`  Proof type: ${credentialIssuedByBBS.proof.type}`);
      // eslint-disable-next-line no-console
      console.log(`  Verification method: ${credentialIssuedByBBS.proof.verificationMethod}`);
    }, 60000);

    /**
     * STEP 4: Revoke - Remove BBS key attribute
     */
    test('Step 4: Revoke BBS key attribute', async () => {
      expect(ownerDID).toBeDefined(); // Ensure Step 1 completed

      // Revoke the BBS key attribute
      const receipt = await module.revokeAttribute(
        ownerDID,
        BBS_ATTRIBUTE_NAME,
        bbsPublicKeyBase58,
        ownerKeypair,
      );

      expect(receipt.transactionHash).toBeDefined();
      expect(receipt.status).toBe(1); // Transaction success

      // Verify BBS key no longer appears in DID document
      const document = await module.getDocument(ownerDID);

      const bbsVM = document.verificationMethod?.find(
        (vm) => vm.publicKeyBase58 === bbsPublicKeyBase58,
      );

      // After revocation, the BBS key should not be in the document
      expect(bbsVM).toBeUndefined();

      // eslint-disable-next-line no-console
      console.log(`✓ Revoked BBS key attribute`);
    }, 60000);

    /**
     * STEP 5: Verify Failure - Credential from revoked BBS key should fail verification
     *
     * This is the CRITICAL step - ensures that revoking a BBS key invalidates
     * credentials signed by that key.
     */
    test('Step 5: Verification fails after BBS key revocation', async () => {
      expect(credentialIssuedByBBS).toBeDefined(); // Ensure Step 3 completed

      // Attempt to verify the same credential again
      // This should FAIL because the BBS key is no longer registered
      const verifyResult = await verifyCredential(credentialIssuedByBBS, {
        resolver: module,
      });

      expect(verifyResult.verified).toBe(false);

      // eslint-disable-next-line no-console
      console.log('✓ Verification correctly failed after BBS key revocation');
      // eslint-disable-next-line no-console
      console.log(`  Result: verified=${verifyResult.verified}`);
      if (verifyResult.error) {
        // eslint-disable-next-line no-console
        console.log(`  Error: ${verifyResult.error.message || verifyResult.error}`);
      }
    }, 60000);
  });

  describe('Additional Verification', () => {
    /**
     * Test that a newly issued credential from the revoked BBS key also fails
     */
    test('New credentials from revoked BBS key should fail verification', async () => {
      expect(bbsKeyDoc).toBeDefined();

      // Issue a NEW credential with the revoked BBS key
      const newCredential = await issueCredential(bbsKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: ownerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder456',
          alumniOf: 'Post-Revocation University',
        },
      });

      expect(newCredential.proof).toBeDefined();

      // Verification should fail
      const verifyResult = await verifyCredential(newCredential, {
        resolver: module,
      });

      expect(verifyResult.verified).toBe(false);

      // eslint-disable-next-line no-console
      console.log('✓ New credentials from revoked BBS key correctly fail verification');
    }, 60000);

    /**
     * Test that the owner can still issue credentials after BBS key revocation
     */
    test('Owner can still issue credentials after BBS key revocation', async () => {
      expect(ownerDID).toBeDefined();

      // Get owner's key document from DID document
      const didDocument = await module.getDocument(ownerDID);
      const ownerAddress = keypairToAddress(ownerKeypair).toLowerCase();

      const ownerVM = didDocument.verificationMethod?.find((vm) => {
        if (!vm.blockchainAccountId) return false;
        const vmAddress = vm.blockchainAccountId.split(':').pop().toLowerCase();
        return vmAddress === ownerAddress;
      });

      expect(ownerVM).toBeDefined();

      // eslint-disable-next-line no-underscore-dangle
      const publicKeyBytes = ownerKeypair._publicKey();
      const ownerKeyDoc = {
        id: ownerVM.id,
        controller: ownerDID,
        type: ownerVM.type,
        publicKeyBase58: b58.encode(publicKeyBytes),
        keypair: ownerKeypair,
      };

      // Issue credential with owner's secp256k1 key
      const ownerCredential = await issueCredential(ownerKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: ownerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder789',
          alumniOf: 'Owner Credential University',
        },
      });

      expect(ownerCredential.proof).toBeDefined();
      expect(ownerCredential.proof.type).toBe('EcdsaSecp256k1Signature2020');

      // Verification should succeed
      const verifyResult = await verifyCredential(ownerCredential, {
        resolver: module,
      });

      expect(verifyResult.verified).toBe(true);

      // eslint-disable-next-line no-console
      console.log('✓ Owner can still issue valid credentials after BBS key revocation');
    }, 60000);
  });
});
