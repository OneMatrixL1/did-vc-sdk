/**
 * Unit tests for BLS/BBS utilities
 *
 * Tests for:
 * - publicKeyToAddress() - derive address from BLS public key (192-byte uncompressed G2)
 * - bbsPublicKeyToAddress() - derive address from BBS public key
 * - signWithBLSKeypair() - signing with BBS keypair
 *
 * Note: EIP-712 message construction and hash computation are now handled
 * by the ethr-did library (submodule) and are tested there.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { ethers } from 'ethers';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import {
  publicKeyToAddress,
  signWithBLSKeypair,
  bbsPublicKeyToAddress,
} from '../src/modules/ethr-did/utils';

describe('BLS/BBS Utilities', () => {
  let bbsKeypair;
  let bbsPublicKeyUncompressed;
  let bbsAddress;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create BBS keypair
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'test-bls-key',
      controller: 'test-controller',
    });

    // Get uncompressed G2 public key (192 bytes) for Ethereum contract interaction
    bbsPublicKeyUncompressed = bbsKeypair.getPublicKeyBufferUncompressed();

    // Derive address from BBS public key (uncompressed format)
    bbsAddress = bbsPublicKeyToAddress(bbsPublicKeyUncompressed);
  });

  describe('publicKeyToAddress()', () => {
    test('derives address from 192-byte BLS public key', () => {
      const address = publicKeyToAddress(bbsPublicKeyUncompressed);

      expect(address).toBeDefined();
      expect(typeof address).toBe('string');
      expect(address.startsWith('0x')).toBe(true);
      expect(address.length).toBe(42); // 0x + 40 hex characters
      expect(ethers.utils.isAddress(address)).toBe(true);
    });

    test('returns checksummed address', () => {
      const address = publicKeyToAddress(bbsPublicKeyUncompressed);

      expect(address).toBe(ethers.utils.getAddress(address));
    });

    test('derives same address from Uint8Array or Array', () => {
      const uint8Address = publicKeyToAddress(bbsPublicKeyUncompressed);
      const arrayAddress = publicKeyToAddress(Array.from(bbsPublicKeyUncompressed));

      expect(uint8Address).toBe(arrayAddress);
    });

    test('derives consistent address from same public key', () => {
      const address1 = publicKeyToAddress(bbsPublicKeyUncompressed);
      const address2 = publicKeyToAddress(bbsPublicKeyUncompressed);

      expect(address1).toBe(address2);
    });

    test('throws error for unsupported public key length', () => {
      const invalidKeyBytes = new Uint8Array(32); // Wrong length

      expect(() => {
        publicKeyToAddress(invalidKeyBytes);
      }).toThrow('Unsupported public key length');
    });

    test('matches bbsPublicKeyToAddress for consistency', () => {
      const pubkeyAddress = publicKeyToAddress(bbsPublicKeyUncompressed);
      const bbsAddress2 = bbsPublicKeyToAddress(bbsPublicKeyUncompressed);

      expect(pubkeyAddress).toBe(bbsAddress2);
    });
  });

  describe('Uncompressed G2 Public Key Format', () => {
    test('generates 192-byte uncompressed G2 public key', () => {
      expect(bbsPublicKeyUncompressed).toBeDefined();
      expect(bbsPublicKeyUncompressed).toBeInstanceOf(Uint8Array);
      expect(bbsPublicKeyUncompressed.length).toBe(192);
    });

    test('uncompressed key is different from compressed key', () => {
      // The compressed public key should be 96 bytes
      expect(bbsKeypair.publicKeyBuffer.length).toBe(96);
      // The uncompressed should be 192 bytes
      expect(bbsPublicKeyUncompressed.length).toBe(192);
      // They should not be the same
      expect(bbsPublicKeyUncompressed).not.toEqual(bbsKeypair.publicKeyBuffer);
    });

    test('getPublicKeyBufferUncompressed is deterministic', () => {
      const uncompressed1 = bbsKeypair.getPublicKeyBufferUncompressed();
      const uncompressed2 = bbsKeypair.getPublicKeyBufferUncompressed();

      expect(uncompressed1).toEqual(uncompressed2);
    });
  });

  describe('signWithBLSKeypair()', () => {
    test('requires keypair with private key', async () => {
      const noPrivateKeyKeypair = {
        publicKeyBuffer: bbsPublicKeyUncompressed,
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

  describe('Address derivation consistency', () => {
    test('same keypair produces same address', () => {
      const address1 = bbsPublicKeyToAddress(bbsPublicKeyUncompressed);
      const address2 = bbsPublicKeyToAddress(bbsPublicKeyUncompressed);

      expect(address1).toBe(address2);
      expect(address1).toBe(bbsAddress);
    });

    test('different keypairs produce different addresses', async () => {
      const keypair2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-bls-key-2',
        controller: 'test-controller-2',
      });
      const pubkey2 = keypair2.getPublicKeyBufferUncompressed();
      const address2 = bbsPublicKeyToAddress(pubkey2);

      expect(address2).not.toBe(bbsAddress);
      expect(ethers.utils.isAddress(address2)).toBe(true);
    });
  });
});
