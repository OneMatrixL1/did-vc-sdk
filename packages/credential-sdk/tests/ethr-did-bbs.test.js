/**
 * Unit tests for BBS keypair support in EthrDIDModule
 *
 * Tests address derivation from BBS public keys using keccak256.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import {
  EthrDIDModule, createVietChainConfig,
} from '../src/modules/ethr-did';
import {
  bbsPublicKeyToAddress,
  detectKeypairType,
  keypairToAddress,
  addressToDID,
  parseDID,
  isEthrDID,
  createSigner,
} from '../src/modules/ethr-did/utils';
import { Secp256k1Keypair } from '../src/keypairs';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';

describe('BBS Address Derivation', () => {
  let bbsKeypair;

  beforeAll(async () => {
    // Initialize WASM module before using BBS
    await initializeWasm();

    // Generate a BBS keypair for testing
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'test-key-1',
      controller: 'did:example:test',
    });
  });

  describe('bbsPublicKeyToAddress', () => {
    test('derives valid Ethereum address from BBS public key', () => {
      // Use uncompressed G2 public key (192 bytes)
      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();
      const address = bbsPublicKeyToAddress(uncompressedPubkey);

      // Should be a valid checksummed Ethereum address
      expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    test('generates consistent address for same public key', () => {
      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();
      const address1 = bbsPublicKeyToAddress(uncompressedPubkey);
      const address2 = bbsPublicKeyToAddress(uncompressedPubkey);

      expect(address1).toBe(address2);
    });

    test('generates different addresses for different public keys', () => {
      const bbsKeypair2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key-2',
        controller: 'did:example:test',
      });

      const uncompressed1 = bbsKeypair.getPublicKeyBufferUncompressed();
      const uncompressed2 = bbsKeypair2.getPublicKeyBufferUncompressed();
      const address1 = bbsPublicKeyToAddress(uncompressed1);
      const address2 = bbsPublicKeyToAddress(uncompressed2);

      expect(address1).not.toBe(address2);
    });

    test('throws for invalid input types', () => {
      expect(() => bbsPublicKeyToAddress('invalid')).toThrow();
      expect(() => bbsPublicKeyToAddress(null)).toThrow();
      expect(() => bbsPublicKeyToAddress(undefined)).toThrow();
    });

    test('throws for wrong length public key', () => {
      const wrongLength = new Uint8Array(32); // Wrong size
      expect(() => bbsPublicKeyToAddress(wrongLength)).toThrow(/must be 192 bytes/);
    });

    test('accepts plain Array with 192 bytes', () => {
      // Create a plain array with 192 bytes (uncompressed G2)
      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();
      const plainArray = Array.from(uncompressedPubkey);
      const address = bbsPublicKeyToAddress(plainArray);
      expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    test('BBS keypair uses 96-byte compressed format internally', () => {
      // The keypair stores compressed format (96 bytes)
      expect(bbsKeypair.publicKeyBuffer.length).toBe(96);
    });

    test('BBS uncompressed public key is 192 bytes', () => {
      // But we use uncompressed format (192 bytes) for Ethereum contracts
      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();
      expect(uncompressedPubkey.length).toBe(192);
    });
  });

  describe('detectKeypairType', () => {
    test('detects BBS keypair', () => {
      expect(detectKeypairType(bbsKeypair)).toBe('bbs');
    });

    test('detects Secp256k1 keypair', () => {
      const secp256k1Keypair = Secp256k1Keypair.random();
      expect(detectKeypairType(secp256k1Keypair)).toBe('secp256k1');
    });

    test('throws for unknown keypair type', () => {
      expect(() => detectKeypairType({})).toThrow(/Unknown keypair type/);
      expect(() => detectKeypairType({ publicKeyBuffer: new Uint8Array(32) })).toThrow(/Unknown keypair type/);
    });
  });

  describe('keypairToAddress with auto-detection', () => {
    test('handles BBS keypair', () => {
      const address = keypairToAddress(bbsKeypair);

      expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    test('handles Secp256k1 keypair', () => {
      const secp256k1Keypair = Secp256k1Keypair.random();
      const address = keypairToAddress(secp256k1Keypair);

      expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    test('BBS and Secp256k1 produce different addresses', () => {
      const secp256k1Keypair = Secp256k1Keypair.random();

      const bbsAddress = keypairToAddress(bbsKeypair);
      const secp256k1Address = keypairToAddress(secp256k1Keypair);

      // Both should be valid but different
      expect(bbsAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(secp256k1Address).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(bbsAddress).not.toBe(secp256k1Address);
    });
  });

  describe('createSigner with BBS', () => {
    test('throws error for BBS keypair', () => {
      expect(() => createSigner(bbsKeypair, null)).toThrow(/BBS transaction signing not yet supported/);
    });

    test('works for Secp256k1 keypair', () => {
      const secp256k1Keypair = Secp256k1Keypair.random();
      // Note: This will fail without a real provider, but shouldn't throw the BBS error
      expect(() => createSigner(secp256k1Keypair, null)).not.toThrow(/BBS transaction signing/);
    });
  });
});

describe('EthrDIDModule with BBS Keypair', () => {
  let module;
  let bbsKeypair;

  beforeAll(() => {
    module = new EthrDIDModule({
      networks: [createVietChainConfig()],
      defaultNetwork: 'vietchain',
    });

    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'test-key-1',
      controller: 'did:example:test',
    });
  });

  describe('createNewDID with BBS', () => {
    test('generates valid DID from BBS keypair', async () => {
      const did = await module.createNewDID(bbsKeypair);

      expect(isEthrDID(did)).toBe(true);
      expect(did).toContain('did:ethr:vietchain:');
    });

    test('generates consistent DID for same BBS keypair', async () => {
      const did1 = await module.createNewDID(bbsKeypair);
      const did2 = await module.createNewDID(bbsKeypair);

      expect(did1).toBe(did2);
    });

    test('generates different DIDs for different BBS keypairs', async () => {
      const bbsKeypair2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key-2',
        controller: 'did:example:test',
      });

      const did1 = await module.createNewDID(bbsKeypair);
      const did2 = await module.createNewDID(bbsKeypair2);

      expect(did1).not.toBe(did2);
    });

    test('DID contains correct address derived from BBS public key', async () => {
      // Use uncompressed G2 public key (192 bytes)
      const uncompressedPubkey = bbsKeypair.getPublicKeyBufferUncompressed();
      const expectedAddress = bbsPublicKeyToAddress(uncompressedPubkey);
      const did = await module.createNewDID(bbsKeypair);
      const parsed = parseDID(did);

      expect(parsed.address.toLowerCase()).toBe(expectedAddress.toLowerCase());
    });

    test('can create DID on specific network', async () => {
      const multiNetworkModule = new EthrDIDModule({
        networks: ['sepolia', createVietChainConfig()],
        defaultNetwork: 'vietchain',
      });

      const sepoliaDID = await multiNetworkModule.createNewDID(bbsKeypair, 'sepolia');
      const vietChainDID = await multiNetworkModule.createNewDID(bbsKeypair, 'vietchain');

      expect(parseDID(sepoliaDID).network).toBe('sepolia');
      expect(parseDID(vietChainDID).network).toBe('vietchain');

      // Same keypair should produce same address on different networks
      expect(parseDID(sepoliaDID).address).toBe(parseDID(vietChainDID).address);
    });
  });

  describe('Transaction methods with BBS (should fail)', () => {
    test('createDocumentTx throws for BBS keypair', async () => {
      const did = await module.createNewDID(bbsKeypair);
      const didDocument = {
        id: did,
        verificationMethod: [{
          type: 'Bls12381G2Key2020',
          publicKeyHex: Buffer.from(bbsKeypair.publicKeyBuffer).toString('hex'),
        }],
      };

      await expect(module.createDocumentTx(didDocument, bbsKeypair))
        .rejects.toThrow(/BBS transaction signing not yet supported/);
    });
  });
});

describe('BBS and Secp256k1 Address Compatibility', () => {
  test('both keypair types produce valid Ethereum addresses', async () => {
    const module = new EthrDIDModule({
      networks: [createVietChainConfig()],
    });

    const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'bbs-key',
      controller: 'did:example:test',
    });
    const secp256k1Keypair = Secp256k1Keypair.random();

    const bbsDID = await module.createNewDID(bbsKeypair);
    const secp256k1DID = await module.createNewDID(secp256k1Keypair);

    // Both should be valid ethr DIDs
    expect(isEthrDID(bbsDID)).toBe(true);
    expect(isEthrDID(secp256k1DID)).toBe(true);

    // Both addresses should be valid
    const bbsAddress = parseDID(bbsDID).address;
    const secp256k1Address = parseDID(secp256k1DID).address;

    expect(bbsAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(secp256k1Address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
});
