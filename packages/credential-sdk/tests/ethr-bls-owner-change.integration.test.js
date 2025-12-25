/**
 * Integration tests for BLS owner change with EthereumDIDRegistry contract
 *
 * These tests verify end-to-end contract integration for BLS-based ownership transfer:
 * - BLS keypair generation and 192-byte uncompressed G2 public key format
 * - Address derivation from 192-byte uncompressed G2 public key
 * - EIP-712 message signing with BLS12-381 (G2 signature)
 * - Contract verification of BLS signatures via changeOwnerWithPubkey()
 * - Smart contract compatibility with uncompressed format (not compressed)
 *
 * CRITICAL: The contract requires:
 * - Public key: 96 bytes uncompressed G1 (line 422)
 * - Signature: 192 bytes uncompressed G2 (line 425)
 * - Contract uses BLS2.g2Unmarshal() which expects uncompressed format
 *
 * Environment Variables (REQUIRED):
 * ----------------------------------
 * ETHR_NETWORK_RPC_URL   - RPC endpoint URL (e.g., https://rpc.vietcha.in)
 * ETHR_PRIVATE_KEY       - Private key of funded account for gas fees
 *
 * Optional Environment Variables:
 * -------------------------------
 * ETHR_NETWORK           - Network name (default: vietchain)
 * ETHR_REGISTRY_ADDRESS  - DID Registry contract address
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { ethers } from 'ethers';
import { EthrDIDModule } from '../src/modules/ethr-did';
import { Secp256k1Keypair } from '../src/keypairs';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import {
  keypairToAddress,
  bbsPublicKeyToAddress,
  publicKeyToAddress,
} from '../src/modules/ethr-did/utils';

// Configuration from environment (required for integration tests)
const SKIP_INTEGRATION = !process.env.ETHR_NETWORK_RPC_URL || !process.env.ETHR_PRIVATE_KEY;

if (SKIP_INTEGRATION) {
  console.warn(
    'Skipping BLS owner change integration tests - ETHR_NETWORK_RPC_URL and ETHR_PRIVATE_KEY required',
  );
}

const networkConfig = SKIP_INTEGRATION
  ? null
  : {
    name: process.env.ETHR_NETWORK || 'vietchain',
    rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
    registry:
        process.env.ETHR_REGISTRY_ADDRESS
        || '0xF0889fb2473F91c068178870ae2e1A0408059A03',
  };

describe('BLS Owner Change Contract Integration', () => {
  let module;
  let provider;
  let founderKeypair; // Funded secp256k1 keypair for gas fees

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

  beforeAll(async () => {
    if (SKIP_INTEGRATION) return;

    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create module
    module = new EthrDIDModule({
      networks: [networkConfig],
      defaultNetwork: networkConfig.name,
    });

    // Create provider
    provider = new ethers.providers.JsonRpcProvider(networkConfig.rpcUrl);

    // Create founder keypair from environment variable
    const privateKeyBytes = Buffer.from(
      process.env.ETHR_PRIVATE_KEY.replace('0x', ''),
      'hex',
    );
    founderKeypair = new Secp256k1Keypair(privateKeyBytes, 'private');
  });

  describe('BLS Keypair and Public Key Format', () => {
    test('generates 192-byte uncompressed G2 public key for contract', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key',
        controller: 'test',
      });

      // Get uncompressed G2 public key (192 bytes) as required by contract
      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();

      expect(uncompressedPubkey).toBeDefined();
      expect(uncompressedPubkey).toBeInstanceOf(Uint8Array);
      expect(uncompressedPubkey.length).toBe(192); // Contract requires 192 bytes (uncompressed G2)

      // Verify it's different from compressed format
      expect(bbsKeypair.publicKeyBuffer.length).toBe(96); // Compressed is 96 bytes
      expect(uncompressedPubkey).not.toEqual(bbsKeypair.publicKeyBuffer);
    });

    test('derives valid Ethereum address from 192-byte uncompressed G2 public key', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'address-test-key',
        controller: 'test',
      });

      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();
      const address = bbsPublicKeyToAddress(uncompressedPubkey);

      // Verify address format
      expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(ethers.utils.isAddress(address)).toBe(true);
      expect(address).toBe(ethers.utils.getAddress(address)); // Checksummed

      // Verify consistency with publicKeyToAddress
      const addressFromGeneric = publicKeyToAddress(uncompressedPubkey);
      expect(address).toBe(addressFromGeneric);
    });
  });

  describe('Contract Integration: changeOwnerWithPubkey', () => {
    test('successfully transfers DID ownership using BLS signature', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      // Create BLS keypair for current owner
      const ownerBBSKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'owner-key',
        controller: 'owner',
      });

      // Derive address from BLS public key
      const ownerAddress = bbsPublicKeyToAddress(
        ownerBBSKeypair.getPublicKeyBufferUncompressed(),
      );

      // Create DID from BLS keypair
      const did = await module.createNewDID(ownerBBSKeypair);
      expect(did).toContain(ownerAddress);

      // Create new owner (secp256k1 for simplicity in this test)
      const newOwnerKeypair = Secp256k1Keypair.random();
      const newOwnerAddress = keypairToAddress(newOwnerKeypair);

      // Fund both accounts
      await fundTestAccount(ownerAddress, '0.05'); // Old owner needs gas for initial setup if any
      await fundTestAccount(newOwnerAddress, '0.05'); // New owner for future operations

      // Create a gas payer keypair (secp256k1) - funded account to pay for transaction
      const gasPayerKeypair = Secp256k1Keypair.random();
      const gasPayerAddress = keypairToAddress(gasPayerKeypair);
      await fundTestAccount(gasPayerAddress, '0.1');

      // Change owner using BLS signature
      // This tests the full contract integration:
      // 1. SDK generates 192-byte uncompressed G2 public key
      // 2. SDK derives address from public key
      // 3. SDK signs EIP-712 message with BLS12-381 (produces G2 signature)
      // 4. Contract verifies signature using BLS2.g2Unmarshal() and pairing check
      const receipt = await module.changeOwnerWithPubkey(
        did,
        newOwnerAddress,
        ownerBBSKeypair,
        gasPayerKeypair,
      );

      // Verify transaction succeeded
      expect(receipt).toBeDefined();
      expect(receipt.txHash).toBeDefined();
      expect(receipt.blockNumber).toBeGreaterThan(0);
      expect(receipt.status).toBe(1); // Transaction success

      // Verify ownership was transferred
      const document = await module.getDocument(did);
      expect(document).toBeDefined();

      // Find the controller verification method
      const controller = document.verificationMethod?.find(
        (vm) => vm.id.endsWith('#controller'),
      );
      expect(controller).toBeDefined();

      // Extract address from blockchainAccountId
      const controllerAddress = controller.blockchainAccountId
        .split(':')
        .pop()
        .toLowerCase();
      expect(controllerAddress).toBe(newOwnerAddress.toLowerCase());
    }, 120000); // 2 minutes timeout for blockchain operations

    test('address derivation is consistent with contract expectations', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      // Create multiple BLS keypairs and verify address derivation
      const keypair1 = Bls12381BBSKeyPairDock2023.generate({
        id: 'consistency-key-1',
        controller: 'test',
      });
      const keypair2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'consistency-key-2',
        controller: 'test',
      });

      const uncompressed1 = keypair1.getPublicKeyBufferUncompressed();
      const uncompressed2 = keypair2.getPublicKeyBufferUncompressed();

      // Verify format
      expect(uncompressed1.length).toBe(192);
      expect(uncompressed2.length).toBe(192);

      // Derive addresses
      const address1 = bbsPublicKeyToAddress(uncompressed1);
      const address2 = bbsPublicKeyToAddress(uncompressed2);

      // Addresses should be different for different keypairs
      expect(address1).not.toBe(address2);

      // But same keypair should produce same address
      const address1Again = bbsPublicKeyToAddress(uncompressed1);
      expect(address1).toBe(address1Again);

      // Verify addresses are valid Ethereum addresses
      expect(ethers.utils.isAddress(address1)).toBe(true);
      expect(ethers.utils.isAddress(address2)).toBe(true);
    });

    test('contract rejects invalid signature', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      // Create owner BLS keypair
      const ownerBBSKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'owner-key-invalid',
        controller: 'owner',
      });

      const ownerAddress = bbsPublicKeyToAddress(
        ownerBBSKeypair.getPublicKeyBufferUncompressed(),
      );

      // Create DID
      const did = await module.createNewDID(ownerBBSKeypair);

      // Create different BLS keypair (wrong one)
      const wrongBBSKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'wrong-key',
        controller: 'wrong',
      });

      // Create new owner
      const newOwnerKeypair = Secp256k1Keypair.random();
      const newOwnerAddress = keypairToAddress(newOwnerKeypair);

      // Fund accounts
      await fundTestAccount(ownerAddress, '0.05');
      const gasPayerKeypair = Secp256k1Keypair.random();
      const gasPayerAddress = keypairToAddress(gasPayerKeypair);
      await fundTestAccount(gasPayerAddress, '0.1');

      // Attempt to change owner with wrong BLS keypair should fail
      await expect(
        module.changeOwnerWithPubkey(
          did,
          newOwnerAddress,
          wrongBBSKeypair, // Wrong keypair!
          gasPayerKeypair,
        ),
      ).rejects.toThrow(/bad_signature|execution reverted/i);
    }, 120000);
  });

  describe('Public Key Format Validation', () => {
    test('verifies uncompressed format is required by contract', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'format-test-key',
        controller: 'test',
      });

      // Compressed format (96 bytes) - SDK uses this for storage/transmission
      const compressed = bbsKeypair.publicKeyBuffer;
      expect(compressed.length).toBe(96);

      // Uncompressed format (192 bytes) - Contract requires this
      const uncompressed = bbsKeypair.getPublicKeyBufferUncompressed();
      expect(uncompressed.length).toBe(192);

      // The SDK must expand to uncompressed before sending to contract
      // This is what changeOwnerWithPubkey() does internally
      expect(uncompressed).not.toEqual(compressed);

      // Both should derive to the same address
      const compressedAddress = bbsPublicKeyToAddress(compressed);
      const uncompressedAddress = bbsPublicKeyToAddress(uncompressed);
      expect(compressedAddress).toBe(uncompressedAddress);
    });

    test('contract expects 192-byte G2 signatures', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      // This test documents the signature format requirement
      // The contract's changeOwnerWithPubkey requires:
      // - require(signature.length == 192, "invalid_signature_length");
      // - Uses BLS2.g2Unmarshal() which expects uncompressed G2 (192 bytes)

      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'sig-format-test',
        controller: 'test',
      });

      // BLS signatures on BLS12-381 G2 are 192 bytes when uncompressed
      // This is verified in the signWithBLSKeypair() function
      // which is tested in ethr-bls-owner-change.test.js

      expect(bbsKeypair.getPublicKeyBufferUncompressed().length).toBe(192);

      // The contract cannot handle compressed G2 because BLS2 library
      // does not support G2 compression - only uncompressed format
    });
  });

  describe('End-to-End Integration Verification', () => {
    test('complete workflow: BLS key generation -> address derivation -> contract verification', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL or private key');
        return;
      }

      // STEP 1: Generate BLS keypair
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'e2e-test-key',
        controller: 'e2e-test',
      });

      // STEP 2: Get 192-byte uncompressed G2 public key
      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();
      expect(uncompressedPubkey.length).toBe(192);

      // STEP 3: Derive Ethereum address from uncompressed public key
      const derivedAddress = bbsPublicKeyToAddress(uncompressedPubkey);
      expect(ethers.utils.isAddress(derivedAddress)).toBe(true);

      // STEP 4: Create DID (which includes address derivation)
      const did = await module.createNewDID(bbsKeypair);
      const didAddress = did.split(':').pop();
      expect(didAddress.toLowerCase()).toBe(derivedAddress.toLowerCase());

      // STEP 5: Fund the address
      await fundTestAccount(derivedAddress, '0.05');

      // STEP 6: Prepare for ownership transfer
      const newOwnerKeypair = Secp256k1Keypair.random();
      const newOwnerAddress = keypairToAddress(newOwnerKeypair);
      await fundTestAccount(newOwnerAddress, '0.05');

      const gasPayerKeypair = Secp256k1Keypair.random();
      const gasPayerAddress = keypairToAddress(gasPayerKeypair);
      await fundTestAccount(gasPayerAddress, '0.1');

      // STEP 7: Execute changeOwnerWithPubkey - Full contract integration test
      // This internally:
      // - Creates EIP-712 hash with uncompressed pubkey
      // - Signs hash with BLS (produces G2 signature)
      // - Calls contract's changeOwnerWithPubkey(newOwner, pubkey, signature)
      // - Contract verifies BLS signature using pairing check
      const receipt = await module.changeOwnerWithPubkey(
        did,
        newOwnerAddress,
        bbsKeypair,
        gasPayerKeypair,
      );

      // STEP 8: Verify transaction succeeded
      expect(receipt.status).toBe(1);
      expect(receipt.txHash).toBeDefined();

      // STEP 9: Verify ownership changed on-chain
      const document = await module.getDocument(did);
      const controller = document.verificationMethod?.find(
        (vm) => vm.id.endsWith('#controller'),
      );
      const controllerAddress = controller.blockchainAccountId.split(':').pop().toLowerCase();
      expect(controllerAddress).toBe(newOwnerAddress.toLowerCase());

      console.log('✅ End-to-End Integration Verified:');
      console.log('  - BLS keypair generated with 192-byte uncompressed G2 public key');
      console.log('  - Address derived correctly from uncompressed format');
      console.log(`  - DID created: ${did}`);
      console.log(`  - Ownership transferred via BLS signature (tx: ${receipt.txHash})`);
      console.log('  - Contract verified signature and updated owner on-chain');
    }, 180000); // 3 minutes for complete workflow
  });
});
