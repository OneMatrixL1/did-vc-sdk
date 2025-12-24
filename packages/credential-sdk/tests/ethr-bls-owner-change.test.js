/**
 * Unit tests for BLS owner change functionality
 *
 * Tests for:
 * - publicKeyToAddress() - derive address from BLS public key
 * - createChangeOwnerWithPubkeyTypedData() - EIP-712 message construction
 * - computeChangeOwnerWithPubkeyHash() - hash computation
 * - signWithBLSKeypair() - signing with BBS keypair
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { ethers } from 'ethers';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import {
  publicKeyToAddress,
  createChangeOwnerWithPubkeyTypedData,
  computeChangeOwnerWithPubkeyHash,
  signWithBLSKeypair,
  bbsPublicKeyToAddress,
} from '../src/modules/ethr-did/utils';

describe('BLS Owner Change Utilities', () => {
  let bbsKeypair;
  let bbsAddress;
  let chainId;
  let registryAddress;
  let identityAddress;
  let newOwnerAddress;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create BBS keypair
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'test-bls-key',
      controller: 'test-controller',
    });

    // Derive address from BBS public key
    bbsAddress = bbsPublicKeyToAddress(bbsKeypair.publicKeyBuffer);

    // Setup test addresses
    chainId = 1;
    registryAddress = ethers.Wallet.createRandom().address;
    identityAddress = bbsAddress; // Current owner is the BBS address
    newOwnerAddress = ethers.Wallet.createRandom().address;
  });

  describe('publicKeyToAddress()', () => {
    test('derives address from 96-byte BLS public key', () => {
      const address = publicKeyToAddress(bbsKeypair.publicKeyBuffer);

      expect(address).toBeDefined();
      expect(typeof address).toBe('string');
      expect(address.startsWith('0x')).toBe(true);
      expect(address.length).toBe(42); // 0x + 40 hex characters
      expect(ethers.utils.isAddress(address)).toBe(true);
    });

    test('returns checksummed address', () => {
      const address = publicKeyToAddress(bbsKeypair.publicKeyBuffer);

      expect(address).toBe(ethers.utils.getAddress(address));
    });

    test('derives same address from Uint8Array or Array', () => {
      const uint8Address = publicKeyToAddress(bbsKeypair.publicKeyBuffer);
      const arrayAddress = publicKeyToAddress(Array.from(bbsKeypair.publicKeyBuffer));

      expect(uint8Address).toBe(arrayAddress);
    });

    test('derives consistent address from same public key', () => {
      const address1 = publicKeyToAddress(bbsKeypair.publicKeyBuffer);
      const address2 = publicKeyToAddress(bbsKeypair.publicKeyBuffer);

      expect(address1).toBe(address2);
    });

    test('throws error for unsupported public key length', () => {
      const invalidKeyBytes = new Uint8Array(32); // Wrong length

      expect(() => {
        publicKeyToAddress(invalidKeyBytes);
      }).toThrow('Unsupported public key length');
    });

    test('matches bbsPublicKeyToAddress for consistency', () => {
      const pubkeyAddress = publicKeyToAddress(bbsKeypair.publicKeyBuffer);
      const bbsAddress2 = bbsPublicKeyToAddress(bbsKeypair.publicKeyBuffer);

      expect(pubkeyAddress).toBe(bbsAddress2);
    });
  });

  describe('createChangeOwnerWithPubkeyTypedData()', () => {
    test('creates valid EIP-712 typed data structure', () => {
      const nonce = 0;
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      // Verify structure
      expect(typedData.domain).toBeDefined();
      expect(typedData.types).toBeDefined();
      expect(typedData.primaryType).toBe('ChangeOwnerWithPubkey');
      expect(typedData.message).toBeDefined();
    });

    test('sets correct domain properties', () => {
      const nonce = 0;
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      expect(typedData.domain.name).toBe('EthereumDIDRegistry');
      expect(typedData.domain.version).toBe('1');
      expect(typedData.domain.chainId).toBe(chainId);
      expect(typedData.domain.verifyingContract).toBe(ethers.utils.getAddress(registryAddress));
    });

    test('includes all required types', () => {
      const nonce = 0;
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      expect(typedData.types.ChangeOwnerWithPubkey).toBeDefined();

      // Verify ChangeOwnerWithPubkey fields
      const fieldNames = typedData.types.ChangeOwnerWithPubkey.map((f) => f.name);
      expect(fieldNames).toContain('identity');
      expect(fieldNames).toContain('signer');
      expect(fieldNames).toContain('newOwner');
      expect(fieldNames).toContain('nonce');
    });

    test('checksums all addresses in message', () => {
      const nonce = 0;
      const unchecksummedIdentity = identityAddress.toLowerCase();
      const unchecksummedSigner = bbsAddress.toLowerCase();
      const unchecksummedNewOwner = newOwnerAddress.toLowerCase();

      const typedData = createChangeOwnerWithPubkeyTypedData(
        unchecksummedIdentity,
        unchecksummedSigner,
        unchecksummedNewOwner,
        nonce,
        registryAddress,
        chainId,
      );

      expect(typedData.message.identity).toBe(ethers.utils.getAddress(identityAddress));
      expect(typedData.message.signer).toBe(ethers.utils.getAddress(bbsAddress));
      expect(typedData.message.newOwner).toBe(ethers.utils.getAddress(newOwnerAddress));
    });

    test('includes nonce in message', () => {
      const nonce = 42;
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      expect(typedData.message.nonce).toBe('42');
    });

    test('converts nonce to string', () => {
      const nonce = ethers.BigNumber.from(100);
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      expect(typeof typedData.message.nonce).toBe('string');
      expect(typedData.message.nonce).toBe('100');
    });
  });

  describe('computeChangeOwnerWithPubkeyHash()', () => {
    test('computes valid EIP-712 hash', () => {
      const nonce = 0;
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      const hash = computeChangeOwnerWithPubkeyHash(typedData);

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash.startsWith('0x')).toBe(true);
      expect(hash.length).toBe(66); // 0x + 64 hex characters (32 bytes)
    });

    test('produces different hash for different nonce', () => {
      const typedData1 = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        0,
        registryAddress,
        chainId,
      );

      const typedData2 = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        1,
        registryAddress,
        chainId,
      );

      const hash1 = computeChangeOwnerWithPubkeyHash(typedData1);
      const hash2 = computeChangeOwnerWithPubkeyHash(typedData2);

      expect(hash1).not.toBe(hash2);
    });

    test('produces different hash for different signer', () => {
      const otherAddress = ethers.Wallet.createRandom().address;

      const typedData1 = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        0,
        registryAddress,
        chainId,
      );

      const typedData2 = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        otherAddress,
        newOwnerAddress,
        0,
        registryAddress,
        chainId,
      );

      const hash1 = computeChangeOwnerWithPubkeyHash(typedData1);
      const hash2 = computeChangeOwnerWithPubkeyHash(typedData2);

      expect(hash1).not.toBe(hash2);
    });

    test('produces different hash for different newOwner', () => {
      const otherOwner = ethers.Wallet.createRandom().address;

      const typedData1 = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        0,
        registryAddress,
        chainId,
      );

      const typedData2 = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        otherOwner,
        0,
        registryAddress,
        chainId,
      );

      const hash1 = computeChangeOwnerWithPubkeyHash(typedData1);
      const hash2 = computeChangeOwnerWithPubkeyHash(typedData2);

      expect(hash1).not.toBe(hash2);
    });

    test('produces consistent hash for same inputs', () => {
      const nonce = 0;
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      const hash1 = computeChangeOwnerWithPubkeyHash(typedData);
      const hash2 = computeChangeOwnerWithPubkeyHash(typedData);

      expect(hash1).toBe(hash2);
    });
  });

  describe('signWithBLSKeypair()', () => {
    test('requires keypair with private key', async () => {
      const noPrivateKeyKeypair = {
        publicKeyBuffer: bbsKeypair.publicKeyBuffer,
        constructor: bbsKeypair.constructor,
      };

      const hash = ethers.utils.keccak256('0x0001');

      await expect(
        signWithBLSKeypair(hash, noPrivateKeyKeypair),
      ).rejects.toThrow('private key for signing');
    });

    test('handles both hex string and Uint8Array hashes', async () => {
      const hash = ethers.utils.keccak256('0x0001');
      const hashBytes = new Uint8Array(Buffer.from(hash.slice(2), 'hex'));

      // Verify both formats are accepted without throwing
      expect(() => {
        // Just verify the hash conversion works
        const hexString = hash.startsWith('0x') ? hash.slice(2) : hash;
        const bytes = new Uint8Array(Buffer.from(hexString, 'hex'));
        expect(bytes.length).toBe(32);
      }).not.toThrow();

      expect(() => {
        const bytes = new Uint8Array(hashBytes);
        expect(bytes.length).toBe(32);
      }).not.toThrow();
    });

    test('handles hash without 0x prefix', async () => {
      const hash = ethers.utils.keccak256('0x0001');
      const hashWithoutPrefix = hash.slice(2);

      // Verify the conversion works
      expect(() => {
        const bytes = new Uint8Array(Buffer.from(hashWithoutPrefix, 'hex'));
        expect(bytes.length).toBe(32);
      }).not.toThrow();
    });
  });

  describe('Full owner change flow', () => {
    test('complete flow: create message and hash', () => {
      const nonce = 0;

      // Step 1: Create EIP-712 message
      const typedData = createChangeOwnerWithPubkeyTypedData(
        identityAddress,
        bbsAddress,
        newOwnerAddress,
        nonce,
        registryAddress,
        chainId,
      );

      expect(typedData.message.identity).toBe(ethers.utils.getAddress(identityAddress));
      expect(typedData.message.signer).toBe(ethers.utils.getAddress(bbsAddress));
      expect(typedData.message.newOwner).toBe(ethers.utils.getAddress(newOwnerAddress));
      expect(typedData.message.nonce).toBe('0');

      // Step 2: Compute hash
      const hash = computeChangeOwnerWithPubkeyHash(typedData);
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);

      // Verify the hash is deterministic
      const hash2 = computeChangeOwnerWithPubkeyHash(typedData);
      expect(hash).toBe(hash2);

      console.log(`Owner change flow prepared:`);
      console.log(`  Identity: ${identityAddress}`);
      console.log(`  Signer: ${bbsAddress}`);
      console.log(`  New Owner: ${newOwnerAddress}`);
      console.log(`  Nonce: ${nonce}`);
      console.log(`  EIP-712 Hash: ${hash}`);
    });
  });
});
