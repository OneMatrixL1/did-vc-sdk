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
 * ETHR_REGISTRY_ADDRESS=0xF0889fb2473F91c068178870ae2e1A0408059A03 \
 * yarn test:integration --testMatch ethr-did-changeowner-pubkey.integration.test.js
 */

import { ethers } from 'ethers';
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { EthrDIDModule } from '../src/modules/ethr-did';
import { Secp256k1Keypair } from '../src/keypairs';
import { keypairToAddress, parseDID } from '../src/modules/ethr-did/utils';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { getUncompressedG2PublicKey } from '../src/modules/ethr-did/bbs-uncompressed';

// Configuration from environment (required for integration tests)
if (!process.env.ETHR_NETWORK_RPC_URL) {
  throw new Error(
    'ETHR_NETWORK_RPC_URL environment variable is required for integration tests. '
      + 'Use scripts/test-integration-vietchain.sh or set ETHR_NETWORK_RPC_URL manually.',
  );
}

const networkConfig = {
  name: process.env.ETHR_NETWORK || 'vietchain',
  rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
  registry:
    process.env.ETHR_REGISTRY_ADDRESS
    || '0xF0889fb2473F91c068178870ae2e1A0408059A03', // VietChain default
};

describe('EthrDID changeOwnerWithPubkey Integration Tests', () => {
  let module;
  let gasPayerKeypair;
  let provider;

  // Helper to fund test accounts
  async function fundTestAccount(recipientAddress, amountInEther = '0.1') {
    const gasPayerPrivateKey = gasPayerKeypair.privateKey();
    const gasPayerPrivateKeyHex = `0x${Array.from(gasPayerPrivateKey)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')}`;
    const gasPayerWallet = new ethers.Wallet(gasPayerPrivateKeyHex, provider);

    const tx = await gasPayerWallet.sendTransaction({
      to: recipientAddress,
      value: ethers.parseEther(amountInEther),
    });

    await tx.wait();
    console.log(`Funded ${recipientAddress} with ${amountInEther} ETH`);
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
    provider = new ethers.JsonRpcProvider(networkConfig.rpcUrl);

    // Require funded private key for gas
    if (!process.env.ETHR_PRIVATE_KEY) {
      throw new Error(
        'ETHR_PRIVATE_KEY environment variable is required for integration tests. '
          + 'Tests require a funded account to pay gas fees.',
      );
    }

    const privateKeyBytes = Buffer.from(
      process.env.ETHR_PRIVATE_KEY.replace('0x', ''),
      'hex',
    );
    gasPayerKeypair = new Secp256k1Keypair(privateKeyBytes, 'private');

    console.log('\n========================================');
    console.log('VietChain Integration Test Configuration');
    console.log('========================================');
    console.log(`Network: ${networkConfig.name}`);
    console.log(`RPC URL: ${networkConfig.rpcUrl}`);
    console.log(`Registry: ${networkConfig.registry}`);
    console.log(`Gas Payer: ${keypairToAddress(gasPayerKeypair)}`);
    console.log('========================================\n');
  });

  describe('BLS Signature-based Ownership Change', () => {
    test('changes DID owner using BBS keypair signature (192-byte uncompressed key)', async () => {
      console.log('\n--- Test: changeOwnerWithPubkey with 192-byte uncompressed G2 public key ---');

      // Step 1: Generate BBS keypair
      console.log('\n1. Generating BBS keypair...');
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-bbs-owner',
        controller: 'temp',
      });

      // Verify we have the compressed 96-byte public key
      expect(bbsKeypair.publicKeyBuffer.length).toBe(96);
      console.log(`   ✓ Generated BBS keypair (compressed public key: 96 bytes)`);

      // Step 2: Derive address from uncompressed 192-byte G2 public key
      console.log('\n2. Deriving address from uncompressed G2 public key...');
      const bbsAddress = keypairToAddress(bbsKeypair);
      console.log(`   ✓ BBS-derived address: ${bbsAddress}`);

      // Create DID for this BBS address
      const did = await module.createNewDID(bbsKeypair);
      console.log(`   ✓ Created DID: ${did}`);

      // Verify DID contains the correct address
      const { address: didAddress } = parseDID(did);
      expect(didAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());

      // Step 3: Verify initial owner (should be the BBS address)
      console.log('\n3. Verifying initial owner on-chain...');
      const registryContract = new ethers.Contract(
        networkConfig.registry,
        [
          'function identityOwner(address identity) view returns (address)',
        ],
        provider,
      );

      const initialOwner = await registryContract.identityOwner(bbsAddress);
      console.log(`   ✓ Initial owner: ${initialOwner}`);
      expect(initialOwner.toLowerCase()).toBe(bbsAddress.toLowerCase());

      // Step 4: Create new owner address
      console.log('\n4. Creating new owner address...');
      const newOwnerWallet = ethers.Wallet.createRandom();
      const newOwnerAddress = newOwnerWallet.address;
      console.log(`   ✓ New owner address: ${newOwnerAddress}`);

      // Step 5: Sign and submit ownership change using BLS signature
      console.log('\n5. Signing ownership change with BLS keypair...');
      console.log('   - Using 192-byte uncompressed G2 public key');
      console.log('   - Generating G1 signature (96 bytes uncompressed)');

      // Verify the module's internal decompression logic
      const { publicKeyBuffer } = bbsKeypair;
      const uncompressedKey = getUncompressedG2PublicKey(publicKeyBuffer);
      expect(uncompressedKey.length).toBe(192);
      console.log(`   ✓ Decompressed G2 public key: ${uncompressedKey.length} bytes`);

      // Submit the changeOwnerWithPubkey transaction
      console.log('\n6. Submitting changeOwnerWithPubkey transaction...');
      const startTime = Date.now();

      const receipt = await module.changeOwnerWithPubkey(
        did,
        newOwnerAddress,
        bbsKeypair,
        gasPayerKeypair,
      );

      const duration = Date.now() - startTime;

      console.log(`   ✓ Transaction completed in ${duration}ms`);
      console.log(`   - Transaction hash: ${receipt.txHash}`);
      console.log(`   - Block number: ${receipt.blockNumber}`);
      console.log(`   - Gas used: ${receipt.gasUsed?.toString() || 'N/A'}`);
      console.log(`   - Status: ${receipt.status === 1 ? 'SUCCESS' : 'FAILED'}`);

      // Step 7: Verify ownership change on-chain
      console.log('\n7. Verifying ownership change on-chain...');
      const finalOwner = await registryContract.identityOwner(bbsAddress);
      console.log(`   ✓ Final owner: ${finalOwner}`);

      expect(receipt.status).toBe(1);
      expect(finalOwner.toLowerCase()).toBe(newOwnerAddress.toLowerCase());
      expect(receipt.txHash).toBeDefined();

      console.log('\n✅ changeOwnerWithPubkey flow completed successfully!');
      console.log('   - BBS keypair generated ✓');
      console.log('   - 192-byte uncompressed G2 key used ✓');
      console.log('   - Address derived correctly ✓');
      console.log('   - BLS signature generated ✓');
      console.log('   - Contract accepted transaction ✓');
      console.log('   - Ownership changed on-chain ✓');
    }, 60000); // 60 second timeout for network operations

    test('verifies 192-byte uncompressed key format is sent to contract', async () => {
      console.log('\n--- Test: Verify 192-byte uncompressed key format ---');

      // Generate BBS keypair
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key-format',
        controller: 'temp',
      });

      console.log('\n1. Public key format verification:');
      console.log(`   - Compressed key size: ${bbsKeypair.publicKeyBuffer.length} bytes`);
      expect(bbsKeypair.publicKeyBuffer.length).toBe(96);

      // Test the decompression utility directly
      const uncompressed = getUncompressedG2PublicKey(bbsKeypair.publicKeyBuffer);
      console.log(`   - Uncompressed key size: ${uncompressed.length} bytes`);
      expect(uncompressed.length).toBe(192);

      // Verify address derivation uses uncompressed key
      const derivedAddress = keypairToAddress(bbsKeypair);
      console.log(`   - Derived address: ${derivedAddress}`);

      // Manually compute address from uncompressed key to verify
      const manualHash = ethers.keccak256(uncompressed);
      const manualAddress = ethers.getAddress(
        '0x' + manualHash.slice(-40),
      );
      console.log(`   - Manual address (from uncompressed): ${manualAddress}`);

      expect(derivedAddress.toLowerCase()).toBe(manualAddress.toLowerCase());

      console.log('\n✅ Key format verification passed!');
      console.log('   - 96-byte compressed → 192-byte uncompressed ✓');
      console.log('   - Address derived from uncompressed key ✓');
    }, 30000);

    test('handles gas estimation for changeOwnerWithPubkey', async () => {
      console.log('\n--- Test: Gas estimation ---');

      // Create BBS identity
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'gas-test',
        controller: 'temp',
      });
      const did = await module.createNewDID(bbsKeypair);
      const newOwnerAddress = keypairToAddress(Secp256k1Keypair.random());

      console.log('\n1. Executing changeOwnerWithPubkey...');
      const receipt = await module.changeOwnerWithPubkey(
        did,
        newOwnerAddress,
        bbsKeypair,
        gasPayerKeypair,
      );

      console.log('\n2. Gas usage:');
      console.log(`   - Gas used: ${receipt.gasUsed?.toString() || 'N/A'}`);

      expect(receipt.gasUsed).toBeDefined();
      expect(receipt.gasUsed > 0n).toBe(true);

      console.log('\n✅ Gas estimation completed!');
    }, 60000);

    test('fails with invalid BBS signature', async () => {
      console.log('\n--- Test: Invalid signature rejection ---');

      // Create two different BBS keypairs
      const bbsKeypair1 = Bls12381BBSKeyPairDock2023.generate({
        id: 'keypair-1',
        controller: 'temp',
      });
      const bbsKeypair2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'keypair-2',
        controller: 'temp',
      });

      const did1 = await module.createNewDID(bbsKeypair1);
      const did2Address = keypairToAddress(bbsKeypair2);
      const newOwner = keypairToAddress(Secp256k1Keypair.random());

      console.log('\n1. Attempting ownership change with wrong keypair signature...');
      console.log('   DID1:', did1);
      console.log('   bbsKeypair2 address:', did2Address);
      console.log('   newOwner:', newOwner);

      // Try to change owner of DID1 using signature from keypair2
      // This should fail because the signature won't match the public key
      await expect(
        module.changeOwnerWithPubkey(
          did1,
          newOwner,
          bbsKeypair2, // Wrong keypair!
          gasPayerKeypair,
        ),
      ).rejects.toThrow();

      console.log('   ✓ Transaction rejected (as expected)');
      console.log('\n✅ Invalid signature protection working!');
    }, 60000);
  });

});
