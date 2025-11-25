/**
 * Integration tests for EthrDIDModule
 *
 * These tests require network connectivity to an Ethereum-compatible chain.
 *
 * Quick Start:
 * -----------
 * Use provided shell scripts for common networks:
 *   ../../scripts/test-integration-vietchain.sh
 *   ../../scripts/test-integration-sepolia.sh
 *
 * Or set environment variables manually:
 *   export ETHR_NETWORK=vietchain
 *   export ETHR_NETWORK_RPC_URL=https://rpc.vietcha.in
 *   export ETHR_REGISTRY_ADDRESS=0xF0889fb2473F91c068178870ae2e1A0408059A03
 *   export ETHR_PRIVATE_KEY=0x...  # REQUIRED: funded account for gas fees
 *   yarn test:integration
 *
 * Environment Variables (REQUIRED):
 * ----------------------------------
 * ETHR_NETWORK_RPC_URL   - RPC endpoint URL (e.g., https://rpc.vietcha.in)
 * ETHR_PRIVATE_KEY       - Private key of funded account
 *
 * Optional Environment Variables:
 * -------------------------------
 * ETHR_NETWORK           - Network name (default: sepolia)
 * ETHR_REGISTRY_ADDRESS  - DID Registry contract address (default: Sepolia registry)
 *
 * Note: Tests will create on-chain transactions and consume gas fees.
 */

import { ethers } from 'ethers';
import b58 from 'bs58';
import { EthrDIDModule, createVietChainConfig } from '../src/modules/ethr-did';
import { Secp256k1Keypair } from '../src/keypairs';
import { keypairToAddress } from '../src/modules/ethr-did/utils';
import { issueCredential, verifyCredential } from '../src/vc';

// Configuration from environment (required for integration tests)
if (!process.env.ETHR_NETWORK_RPC_URL) {
  throw new Error(
    'ETHR_NETWORK_RPC_URL environment variable is required for integration tests. '
      + 'Use scripts/test-integration-vietchain.sh or scripts/test-integration-sepolia.sh',
  );
}

const networkConfig = {
  name: process.env.ETHR_NETWORK || 'sepolia',
  rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
  registry:
    process.env.ETHR_REGISTRY_ADDRESS
    || '0x03d5003bf0e79c5f5223588f347eba39afbc3818',
};

const MESSAGING_SERVICE_URL = 'https://example.com/messages';

describe('EthrDID Integration Tests', () => {
  let module;
  let founderKeypair; // Main funded wallet
  let provider;

  // Helper function to fund a test account with minimal gas
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

  beforeAll(() => {
    // Create module with test network
    module = new EthrDIDModule({
      networks: [networkConfig],
      defaultNetwork: networkConfig.name,
    });

    // Create provider
    provider = new ethers.providers.JsonRpcProvider(networkConfig.rpcUrl);

    // Require funded private key for integration tests
    if (!process.env.ETHR_PRIVATE_KEY) {
      throw new Error(
        'ETHR_PRIVATE_KEY environment variable is required for integration tests. '
          + 'Tests require a funded account to pay gas fees. '
          + 'Use scripts/test-integration-vietchain.sh or scripts/test-integration-sepolia.sh',
      );
    }

    const privateKeyBytes = Buffer.from(
      process.env.ETHR_PRIVATE_KEY.replace('0x', ''),
      'hex',
    );
    founderKeypair = new Secp256k1Keypair(privateKeyBytes, 'private');
  });

  describe('DID Resolution', () => {
    test('getDocument resolves DID document', async () => {
      const keypair = Secp256k1Keypair.random();
      const did = await module.createNewDID(keypair);
      const document = await module.getDocument(did);

      expect(document).toBeDefined();
      expect(document.id).toBe(did);
      expect(document.verificationMethod).toBeDefined();
    }, 30000); // 30s timeout for network operations
  });

  describe('DID Attribute Management', () => {
    test('setAttribute adds attribute to DID document', async () => {
      // Create and fund a test account
      const testKeypair = Secp256k1Keypair.random();
      const testAddress = keypairToAddress(testKeypair);
      await fundTestAccount(testAddress, '0.05');

      const did = await module.createNewDID(testKeypair);

      const receipt = await module.setAttribute(
        did,
        'did/svc/TestService',
        'https://example.com/test',
        testKeypair,
      );

      expect(receipt.transactionHash).toBeDefined();
      expect(receipt.blockNumber).toBeGreaterThan(0);
      expect(receipt.status).toBe(1); // Transaction success

      // Verify attribute was added
      const document = await module.getDocument(did);
      expect(document.service).toBeDefined();
    }, 60000); // 60s timeout
  });

  describe('Delegate Management', () => {
    test('addDelegate adds delegate to DID', async () => {
      // Create and fund a test account
      const testKeypair = Secp256k1Keypair.random();
      const testAddress = keypairToAddress(testKeypair);
      await fundTestAccount(testAddress, '0.05');

      const delegateKeypair = Secp256k1Keypair.random();
      const did = await module.createNewDID(testKeypair);
      const delegateAddress = keypairToAddress(delegateKeypair);

      const receipt = await module.addDelegate(
        did,
        delegateAddress,
        testKeypair,
        { delegateType: 'veriKey', expiresIn: 86400 },
      );

      expect(receipt.transactionHash).toBeDefined();
      expect(receipt.status).toBe(1);

      // Verify delegate was added
      const document = await module.getDocument(did);
      expect(document.verificationMethod.length).toBeGreaterThan(1);
    }, 60000);

    test('revokeDelegate removes delegate from DID', async () => {
      // Create and fund a test account
      const testKeypair = Secp256k1Keypair.random();
      const testAddress = keypairToAddress(testKeypair);
      await fundTestAccount(testAddress, '0.05');

      const delegateKeypair = Secp256k1Keypair.random();
      const did = await module.createNewDID(testKeypair);
      const delegateAddress = keypairToAddress(delegateKeypair);

      // Add delegate first
      await module.addDelegate(did, delegateAddress, testKeypair, {
        delegateType: 'veriKey',
        expiresIn: 86400,
      });

      // Then revoke
      const receipt = await module.revokeDelegate(
        did,
        delegateAddress,
        testKeypair,
        'veriKey',
      );

      expect(receipt.transactionHash).toBeDefined();
      expect(receipt.status).toBe(1);
    }, 120000); // 2 minutes for 2 transactions
  });

  describe('Ownership Transfer', () => {
    test('changeOwner transfers DID ownership', async () => {
      // Create and fund two test accounts
      const testKeypair = Secp256k1Keypair.random();
      const testAddress = keypairToAddress(testKeypair);
      await fundTestAccount(testAddress, '0.05');

      const newOwnerKeypair = Secp256k1Keypair.random();
      const newOwnerAddress = keypairToAddress(newOwnerKeypair);
      await fundTestAccount(newOwnerAddress, '0.05');

      const did = await module.createNewDID(testKeypair);

      // Transfer ownership to new owner
      const receipt = await module.changeOwner(
        did,
        newOwnerAddress,
        testKeypair,
      );

      expect(receipt.transactionHash).toBeDefined();
      expect(receipt.status).toBe(1);

      // After transfer, old owner can no longer modify
      await expect(
        module.setAttribute(did, 'test', 'value', testKeypair),
      ).rejects.toThrow();

      // But new owner can modify
      const receipt2 = await module.setAttribute(
        did,
        'did/svc/NewService',
        'https://example.com/new',
        newOwnerKeypair,
      );

      expect(receipt2.status).toBe(1);
    }, 90000); // 90s for multiple transactions
  });

  // Helper function to create credential
  const createCredential = (issuerDID, subject) => ({
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1',
    ],
    type: ['VerifiableCredential', 'AlumniCredential'],
    issuer: issuerDID,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'did:example:student123',
      alumniOf: subject,
    },
  });

  // Helper to create key doc using verification method from DID document
  const createKeyDocFromDIDDocument = async (ethrModule, keypair, didId) => {
    const didDocument = await ethrModule.getDocument(didId);
    const address = keypairToAddress(keypair).toLowerCase();

    // Find verification method that matches this keypair's address (case-insensitive)
    const verificationMethod = didDocument.verificationMethod?.find((vm) => {
      if (!vm.blockchainAccountId) return false;
      const vmAddress = vm.blockchainAccountId.split(':').pop().toLowerCase();
      return vmAddress === address;
    });

    if (!verificationMethod) {
      console.error(
        'Available verification methods:',
        didDocument.verificationMethod,
      );
      console.error('Looking for address:', address);
      throw new Error(`No verification method found for address ${address}`);
    }

    // eslint-disable-next-line no-underscore-dangle
    const publicKeyBytes = keypair._publicKey();
    const publicKeyBase58 = b58.encode(publicKeyBytes);
    return {
      id: verificationMethod.id,
      controller: didId,
      type: verificationMethod.type, // Use actual type from DID document
      publicKeyBase58,
      keypair,
    };
  };

  describe('DID Document Updates & Signing', () => {
    test('signs and verifies credentials after each DID manipulation', async () => {
      // Create and fund a test account
      const ownerKeypair = Secp256k1Keypair.random();
      const ownerAddress = keypairToAddress(ownerKeypair);
      await fundTestAccount(ownerAddress, '0.2');

      const did = await module.createNewDID(ownerKeypair);

      // === STEP 1: Sign with initial DID ===
      const ownerKeyDoc = await createKeyDocFromDIDDocument(
        module,
        ownerKeypair,
        did,
      );
      const cred1 = await issueCredential(
        ownerKeyDoc,
        createCredential(did, 'Initial University'),
      );

      expect(cred1.proof).toBeDefined();
      expect(cred1.proof.type).toBe('EcdsaSecp256k1Signature2020');
      expect(cred1.issuer).toBe(did);

      const verify1 = await verifyCredential(cred1, { resolver: module });
      expect(verify1.verified).toBe(true);

      // === STEP 2: Add service attribute, then sign ===
      await module.setAttribute(
        did,
        'did/svc/MessagingService',
        MESSAGING_SERVICE_URL,
        ownerKeypair,
        86400,
      );

      const cred2 = await issueCredential(
        ownerKeyDoc,
        createCredential(did, 'Service University'),
      );
      expect(cred2.proof).toBeDefined();
      expect(cred2.proof.type).toBe('EcdsaSecp256k1Signature2020');

      const verify2 = await verifyCredential(cred2, { resolver: module });
      expect(verify2.verified).toBe(true);

      // === STEP 3: Add delegate, sign with both owner AND delegate ===
      const delegateKeypair = Secp256k1Keypair.random();
      const delegateAddress = keypairToAddress(delegateKeypair);

      await module.addDelegate(did, delegateAddress, ownerKeypair, {
        delegateType: 'veriKey',
        expiresIn: 86400,
      });

      // Sign with owner key (should still work)
      const cred3a = await issueCredential(
        ownerKeyDoc,
        createCredential(did, 'Owner After Delegate'),
      );
      expect(cred3a.proof).toBeDefined();
      expect(cred3a.proof.type).toBe('EcdsaSecp256k1Signature2020');

      const verify3a = await verifyCredential(cred3a, { resolver: module });
      expect(verify3a.verified).toBe(true);

      // Sign with delegate key
      const delegateKeyDoc = await createKeyDocFromDIDDocument(
        module,
        delegateKeypair,
        did,
      );
      const cred3b = await issueCredential(
        delegateKeyDoc,
        createCredential(did, 'Delegate University'),
      );
      expect(cred3b.proof).toBeDefined();
      expect(cred3b.proof.type).toBe('EcdsaSecp256k1Signature2020');

      const verify3b = await verifyCredential(cred3b, { resolver: module });
      expect(verify3b.verified).toBe(true);

      // === STEP 4: Revoke delegate, owner can still sign ===
      await module.revokeDelegate(
        did,
        delegateAddress,
        ownerKeypair,
        'veriKey',
      );

      // Sign with owner key (should still work)
      const cred4a = await issueCredential(
        ownerKeyDoc,
        createCredential(did, 'Owner After Revoke'),
      );
      expect(cred4a.proof).toBeDefined();
      expect(cred4a.proof.type).toBe('EcdsaSecp256k1Signature2020');

      const verify4a = await verifyCredential(cred4a, { resolver: module });
      expect(verify4a.verified).toBe(true);

      // Verify revoked delegate's credential no longer verifies
      const cred4b = await issueCredential(
        delegateKeyDoc,
        createCredential(did, 'Revoked Delegate University'),
      );
      const verify4b = await verifyCredential(cred4b, { resolver: module });
      expect(verify4b.verified).toBe(false);

      // === STEP 5: Transfer ownership, new owner can sign ===
      const newOwnerKeypair = Secp256k1Keypair.random();
      const newOwnerAddress = keypairToAddress(newOwnerKeypair);
      await fundTestAccount(newOwnerAddress, '0.05');

      await module.changeOwner(did, newOwnerAddress, ownerKeypair);

      // Sign with new owner key
      const newOwnerKeyDoc = await createKeyDocFromDIDDocument(
        module,
        newOwnerKeypair,
        did,
      );
      const cred5a = await issueCredential(
        newOwnerKeyDoc,
        createCredential(did, 'New Owner University'),
      );
      expect(cred5a.proof).toBeDefined();
      expect(cred5a.proof.type).toBe('EcdsaSecp256k1Signature2020');

      const verify5a = await verifyCredential(cred5a, { resolver: module });
      expect(verify5a.verified).toBe(true);

      // Verify old owner's credential no longer verifies
      const cred5b = await issueCredential(
        ownerKeyDoc,
        createCredential(did, 'Old Owner University'),
      );
      const verify5b = await verifyCredential(cred5b, { resolver: module });
      expect(verify5b.verified).toBe(false);
    }, 180000); // 3 minutes for multiple transactions

    test('verifies document changes before/after updates and can sign credentials', async () => {
      // Create and fund a test account
      const testKeypair = Secp256k1Keypair.random();
      const testAddress = keypairToAddress(testKeypair);
      await fundTestAccount(testAddress, '0.1');

      const did = await module.createNewDID(testKeypair);

      // Get BEFORE document
      const docBefore = await module.getDocument(did);

      expect(docBefore.id).toBe(did);
      expect(docBefore.verificationMethod).toBeDefined();
      expect(docBefore.verificationMethod.length).toBeGreaterThanOrEqual(1); // At least owner key

      const vmCountBefore = docBefore.verificationMethod.length;
      const serviceCountBefore = docBefore.service?.length || 0;

      // Add a service attribute
      await module.setAttribute(
        did,
        'did/svc/MessagingService',
        MESSAGING_SERVICE_URL,
        testKeypair,
        86400, // 1 day
      );

      // Add a delegate
      const delegateKeypair = Secp256k1Keypair.random();
      const delegateAddress = keypairToAddress(delegateKeypair);
      await module.addDelegate(did, delegateAddress, testKeypair, {
        delegateType: 'veriKey',
        expiresIn: 86400,
      });

      // Get AFTER document
      const docAfter = await module.getDocument(did);

      // Verify changes
      expect(docAfter.id).toBe(did);
      expect(docAfter.verificationMethod.length).toBeGreaterThan(vmCountBefore);
      expect(docAfter.service?.length || 0).toBeGreaterThan(serviceCountBefore);

      // Verify the specific service was added
      const messagingService = docAfter.service?.find(
        (s) => s.type === 'MessagingService'
          || s.serviceEndpoint === MESSAGING_SERVICE_URL,
      );
      expect(messagingService).toBeDefined();

      // We expect at least 2 VMs: the owner + the delegate
      expect(docAfter.verificationMethod.length).toBeGreaterThanOrEqual(2);

      // Verify the delegate is in the verification methods
      const delegateInVM = docAfter.verificationMethod.some((vm) => vm.blockchainAccountId
        ?.toLowerCase()
        .includes(delegateAddress.toLowerCase()));
      expect(delegateInVM).toBe(true);

      // Now test issuing a credential with the ethr DID
      // Use the same approach as the other test for consistency
      const keyDoc = await createKeyDocFromDIDDocument(
        module,
        testKeypair,
        did,
      );

      const unsignedCredential = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://www.w3.org/2018/credentials/examples/v1',
        ],
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: did,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:student123',
          degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Science and Arts',
          },
        },
      };

      const signedVC = await issueCredential(keyDoc, unsignedCredential);

      expect(signedVC).toBeDefined();
      expect(signedVC.proof).toBeDefined();
      expect(signedVC.proof.type).toBe('EcdsaSecp256k1Signature2020');
      expect(signedVC.proof.verificationMethod).toBeDefined();
      expect(signedVC.issuer).toBe(did);
    }, 120000); // 2 minutes for multiple transactions
  });

  describe('Multi-Network Operations', () => {
    test('can operate on different networks', async () => {
      const multiNetModule = new EthrDIDModule({
        networks: ['sepolia', createVietChainConfig()],
        defaultNetwork: 'sepolia',
      });

      const keypair = Secp256k1Keypair.random();
      const sepoliaDID = await multiNetModule.createNewDID(keypair, 'sepolia');
      const vietChainDID = await multiNetModule.createNewDID(
        keypair,
        'vietchain',
      );

      // DIDs should be different due to network prefix
      expect(sepoliaDID).not.toBe(vietChainDID);
      expect(sepoliaDID).toContain('sepolia');
      expect(vietChainDID).toContain('vietchain');
    }, 30000);
  });

  describe('Error Handling', () => {
    test('handles insufficient funds gracefully', async () => {
      // Create an unfunded account
      const unfundedKeypair = Secp256k1Keypair.random();
      const did = await module.createNewDID(unfundedKeypair);

      await expect(
        module.setAttribute(did, 'test', 'value', unfundedKeypair),
      ).rejects.toThrow(/insufficient funds|gas/i);
    }, 30000);

    test('handles network errors gracefully', async () => {
      const badModule = new EthrDIDModule({
        networks: [
          {
            name: 'invalid',
            rpcUrl: 'https://invalid-network.example.com',
            registry: '0x0000000000000000000000000000000000000000',
          },
        ],
      });

      const keypair = Secp256k1Keypair.random();
      const did = await badModule.createNewDID(keypair);

      await expect(badModule.getDocument(did)).rejects.toThrow();
    }, 30000);
  });
});
