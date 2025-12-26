import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { Secp256k1Keypair } from '../src/keypairs';
import { Bls12381BBSKeyPairDock2023 } from '../src/vc/crypto';
import { detectKeypairType } from '../src/modules/ethr-did/utils';

describe('detectKeypairType', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  describe('Secp256k1Keypair detection', () => {
    test('detects Secp256k1Keypair by constructor name', () => {
      const keypair = new Secp256k1Keypair(
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      );
      expect(detectKeypairType(keypair)).toBe('secp256k1');
    });

    test('detects random Secp256k1Keypair', () => {
      const keypair = Secp256k1Keypair.random();
      expect(detectKeypairType(keypair)).toBe('secp256k1');
    });
  });

  describe('BBS keypair detection', () => {
    test('detects Bls12381BBSKeyPairDock2023 by constructor name', () => {
      const keypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key',
        controller: 'did:example:123',
      });
      expect(detectKeypairType(keypair)).toBe('bbs');
    });

    test('detects random BBS keypair', () => {
      const keypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key-2',
        controller: 'did:example:456',
      });
      expect(detectKeypairType(keypair)).toBe('bbs');
    });
  });

  describe('Error cases', () => {
    test('throws error for null keypair', () => {
      expect(() => detectKeypairType(null)).toThrow('Invalid keypair: must be an object');
    });

    test('throws error for undefined keypair', () => {
      expect(() => detectKeypairType(undefined)).toThrow('Invalid keypair: must be an object');
    });

    test('throws error for non-object keypair', () => {
      expect(() => detectKeypairType('not-a-keypair')).toThrow('Invalid keypair: must be an object');
    });

    test('throws error for unknown object type', () => {
      const unknownObject = { someProperty: 'value' };
      expect(() => detectKeypairType(unknownObject)).toThrow('Unknown keypair type');
    });
  });

  describe('Property-based fallback detection', () => {
    test('detects BBS keypair by properties when constructor name is unavailable', () => {
      const keypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key',
        controller: 'did:example:123',
      });

      // Simulate constructor name being unavailable
      Object.defineProperty(keypair, 'constructor', {
        value: { name: 'UnknownConstructor' },
        writable: true,
      });

      // Should still detect as BBS via property checks
      expect(detectKeypairType(keypair)).toBe('bbs');
    });

    test('detects Secp256k1 keypair by properties when constructor name is unavailable', () => {
      const keypair = Secp256k1Keypair.random();

      // Simulate constructor name being unavailable
      Object.defineProperty(keypair, 'constructor', {
        value: { name: 'UnknownConstructor' },
        writable: true,
      });

      // Should still detect as secp256k1 via property checks
      expect(detectKeypairType(keypair)).toBe('secp256k1');
    });

    test('detects BBS keypair for plain object with only publicKeyBuffer (optimistic verification)', () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'test-key',
        controller: 'did:example:123',
      });

      // Create a plain object with only publicKeyBuffer (as used in optimistic verification)
      const plainObject = {
        publicKeyBuffer: bbsKeypair.publicKeyBuffer,
      };

      // Should detect as BBS via duck-typing
      expect(detectKeypairType(plainObject)).toBe('bbs');
    });
  });
});
